"""Run real owner-service workflows against temporary SQLite/files and local S3.

Requires boto3 and, unless --s3-endpoint is supplied, moto[server]. Does not use
AWS credentials or external endpoints. Checks observed effects, not verdicts alone.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import http.client
import http.server
import json
import os
import random
import select
import signal
import socket
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit

import boto3

from agent_circuit_breaker import __version__
from agent_circuit_breaker.owner import request, verify_bundle
from agent_circuit_breaker.owner_setup import initialize
from agent_circuit_breaker.workflow import digest
from agent_circuit_breaker.s3 import S3Publisher
from agent_circuit_breaker.runtime import ExecutionUncertain


def free_port():
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        return server.getsockname()[1]


class Rehearsal:
    def __init__(self, root, endpoint, *, seed=172):
        self.root, self.endpoint = root, endpoint
        self.records, self.latencies = [], []
        self.random = random.Random(seed)
        self.access = "acb-rehearsal-access"
        self.secret = "acb-rehearsal-secret-only-not-a-real-credential"
        self.s3 = boto3.client("s3", endpoint_url=endpoint, region_name="us-east-1", aws_access_key_id=os.environ.get("ACB_REHEARSAL_S3_ACCESS", self.access), aws_secret_access_key=os.environ.get("ACB_REHEARSAL_S3_SECRET", self.secret))
        self.access = os.environ.get("ACB_REHEARSAL_S3_ACCESS", self.access)
        self.secret = os.environ.get("ACB_REHEARSAL_S3_SECRET", self.secret)
        self.bucket = "acb172-" + uuid.uuid4().hex[:20]
        self.s3.create_bucket(Bucket=self.bucket)
        self.processes = []

    def check(self, name, condition, category="invariant"):
        self.records.append({"name": name, "category": category, "passed": bool(condition)})
        if not condition:
            raise AssertionError(name)

    def fixture(self, name, *, export_limit=1048576, endpoint=None):
        info = initialize(self.root / name)
        # Short socket paths keep this executable on macOS's sockaddr_un limit.
        info["agent_socket"] = str(self.root / (name + ".sock"))
        config = json.loads(Path(info["config"]).read_text())
        config['workflow']['repository_status'] = True
        config["workflow"]["destinations"] = {"archive": ["internal", "public"]}
        config["effect_limits"]["export_bytes"] = export_limit
        config["effect_limits"]["files_written"] = 20
        config["s3_destinations"] = {"archive": {"endpoint": endpoint or self.endpoint, "bucket": self.bucket, "region": "us-east-1", "prefix": name,
            "access_key_env": "ACB_REHEARSAL_S3_ACCESS", "secret_key_env": "ACB_REHEARSAL_S3_SECRET", "allow_http_for_testing": True}}
        sensitive = b'{"api_key":"synthetic-private-fixture-value-1234567890"}\n'
        source = Path(info["workspace"]) / "sensitive.json"
        source.write_bytes(sensitive)
        config["workflow"]["read_paths"]["sensitive.json"] = {"sha256": digest(sensitive), "labels": ["sensitive"]}
        Path(info["config"]).write_text(json.dumps(config))
        info["config_data"] = config
        self.start(info)
        return info

    def start(self, info):
        env = dict(os.environ, ACB_REHEARSAL_S3_ACCESS=self.access, ACB_REHEARSAL_S3_SECRET=self.secret)
        log = open(Path(info["created"]) / "owner-stderr.log", "a")
        process = subprocess.Popen([sys.executable, "-I", "-m", "agent_circuit_breaker.owner", "serve", "--workspace", info["workspace"], "--state", info["state"], "--config", info["config"], "--socket", info["agent_socket"], "--agent-uid", str(os.getuid()), "--development"], stdout=subprocess.PIPE, stderr=log, text=True, env=env)
        log.close()
        self.processes.append(process)
        if not select.select([process.stdout], [], [], 15)[0] or not process.stdout.readline():
            raise RuntimeError("owner startup failed: " + (Path(info["created"]) / "owner-stderr.log").read_text())
        info["process"] = process

    def stop(self, info, *, kill=False):
        process = info["process"]
        process.kill() if kill else process.terminate()
        process.wait(timeout=10)

    def invoke(self, info, method, *, owner=False, **fields):
        if method in {"call", "commit"}:
            fields.setdefault("request_id", uuid.uuid4().hex)
        started = time.perf_counter()
        result = request(info["control_socket"] if owner else info["agent_socket"], {"method": method, **fields})
        self.latencies.append((time.perf_counter() - started) * 1000)
        return result

    def call(self, info, name, **arguments):
        return self.invoke(info, "call", name=name, arguments=arguments)

    def approve(self, info, pending, *, ttl=300):
        details = self.invoke(info, "inspect", owner=True, review_id=pending["review_id"])
        return self.invoke(info, "approve", owner=True, review_id=pending["review_id"], fingerprint=details["action_fingerprint"], ttl_seconds=ttl)

    def commit(self, info, pending):
        return self.invoke(info, "commit", review_id=pending["review_id"])

    def rows(self, info):
        with sqlite3.connect(info["config_data"]["database"]["path"]) as db:
            return db.execute("SELECT id,status FROM tickets ORDER BY id").fetchall()

    def object_bytes(self, key):
        return self.s3.get_object(Bucket=self.bucket, Key=key)["Body"].read()

    def objects(self, prefix):
        return [item["Key"] for item in self.s3.list_objects_v2(Bucket=self.bucket, Prefix=prefix).get("Contents", [])]

    def run(self):
        f = self.fixture("work")
        workspace = Path(f['workspace'])
        git_env = {'PATH': '/usr/bin:/bin', 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull,
                   'GIT_AUTHOR_NAME': 'ACB fixture', 'GIT_AUTHOR_EMAIL': 'fixture@example.invalid',
                   'GIT_COMMITTER_NAME': 'ACB fixture', 'GIT_COMMITTER_EMAIL': 'fixture@example.invalid'}
        def git(*args):
            subprocess.run(['/usr/bin/git', '-c', 'core.hooksPath=/dev/null', *args], cwd=workspace,
                           env=git_env, capture_output=True, check=True, timeout=10)
        git('init', '--template=')
        (workspace / 'tracked.txt').write_text('original fixture\n')
        git('add', 'tracked.txt'); git('commit', '-m', 'synthetic baseline')
        (workspace / 'tracked.txt').write_text('changed fixture\n')
        status = self.call(f, 'repository_status')
        self.check('repository status observes a real tracked-file change', status.get('outcome') == 'executed' and ' M tracked.txt' in status['result']['text'], 'benign')
        original = self.call(f, "read_file", path="incident.json")
        source = original["result"]["artifact"]
        self.check("source read matches actual bytes", original["result"]["text"].encode() == (Path(f["workspace"]) / "incident.json").read_bytes(), "benign")
        for tool, suffix in (("copy_artifact", "copy.json"), ("encode_artifact", "encoded.txt"), ("json_artifact", "canonical.json"), ("redact_artifact", "redacted.json")):
            result = self.call(f, tool, artifact_id=source["id"], path="reports/" + suffix)
            artifact = result["result"]["artifact"]
            self.check(tool + " wrote its actual authenticated bytes", result["outcome"] == "executed" and digest((Path(f["workspace"]) / artifact["path"]).read_bytes()) == artifact["sha256"], "benign")
        report = self.call(f, "write_report", sources=[source["id"]], path="reports/incident.md")
        self.check("fixed report contains source data", "synthetic failed login" in (Path(f["workspace"]) / "reports/incident.md").read_text(), "benign")
        for path in ("../escape.txt", "reports/../../escape.txt", "/tmp/acb-should-not-exist", "reports/.hidden", "reports/../escape.txt"):
            denied = self.call(f, "copy_artifact", artifact_id=source["id"], path=path)
            self.check("traversal refused: " + path, denied.get("decision") == "BLOCK" and denied.get("executor_started") is False and not (Path(f["created"]) / "escape.txt").exists(), "attack")
        for payload in ({"method": "approve", "review_id": "forged"}, {"method": "status", "principal": "owner"}, {"method": "declassify", "artifact_id": source["id"]}):
            denied = request(f["agent_socket"], payload)
            self.check("agent cannot grant owner authority: " + payload["method"], denied.get("decision") == "ERROR", "attack")
        sensitive = self.call(f, "read_file", path="sensitive.json")["result"]["artifact"]
        encoded = self.call(f, "encode_artifact", artifact_id=sensitive["id"], path="reports/private-encoded.txt")["result"]["artifact"]
        denied = self.call(f, "publish_artifact", artifact_id=encoded["id"], destination="archive")
        self.check("encoded sensitive bytes never arrive at S3", denied["decision"] == "BLOCK" and not self.objects("work/"), "attack")
        redacted = self.call(f, "redact_artifact", artifact_id=sensitive["id"], path="reports/review-me.json")["result"]["artifact"]
        redacted_bytes = (Path(f["workspace"]) / redacted['path']).read_bytes()
        self.check('JSON redaction actually removes the synthetic secret', json.loads(redacted_bytes)['api_key'] == '[REDACTED]' and b'synthetic-private-fixture-value' not in redacted_bytes, 'benign')
        self.check("redaction preserves classification until owner review", redacted["labels"] == ["sensitive"], "invariant")
        public = self.invoke(f, "declassify", owner=True, artifact_id=redacted["id"], path="reports/public.json", labels=["public"], sha256=redacted["sha256"], reason="reviewed synthetic redacted example")
        self.check("reviewed declassification creates exact new artifact", public["result"]["artifact"]["labels"] == ["public"] and (Path(f["workspace"]) / "reports/public.json").read_bytes() == (Path(f["workspace"]) / "reports/review-me.json").read_bytes(), "benign")
        pending = self.call(f, "publish_artifact", artifact_id=public["result"]["artifact"]["id"], destination="archive")
        self.check("publication waits with no object present", pending["decision"] == "PENDING_APPROVAL" and not self.objects("work/"), "attack")
        self.approve(f, pending)
        published = self.commit(f, pending)
        expected = (Path(f["workspace"]) / "reports/public.json").read_bytes()
        self.check("approved S3 object contains exact reviewed bytes", published.get("outcome") == "executed" and self.object_bytes("work/reports/public.json") == expected, "benign")
        self.check("approval replay creates no additional S3 object", self.commit(f, pending)["decision"] == "BLOCK" and self.objects("work/") == ["work/reports/public.json"], "attack")
        args = {"operation": "close_ticket", "parameters": {"id": 1, "status": "closed-" + str(self.random.randrange(1000))}}
        change = self.call(f, "database_change", **args)
        self.check("SQLite preview leaves original database unchanged", self.rows(f)[0] == (1, "open") and change["review"]["database_preview"]["rows_affected"] == 1, "invariant")
        self.approve(f, change)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: self.commit(f, change), range(2)))
        self.check("concurrent approvals cause exactly one database effect", sum(r["decision"] == "ALLOW" for r in results) == 1 and self.rows(f) == [(1, args["parameters"]["status"]), (2, "open"), (3, "closed")], "attack")
        before = self.invoke(f, "status")
        self.stop(f); self.start(f)
        after = self.invoke(f, "status")
        self.check("restart retains run and consumed effects", before["run_id"] == after["run_id"] and before["effects"] == after["effects"], "invariant")
        self.check("restart does not restore consumed approval", self.commit(f, change)["decision"] == "BLOCK" and self.rows(f)[1] == (2, "open"), "attack")
        stale = self.call(f, "database_change", operation="close_ticket", parameters={"id": 2, "status": "closed"})
        self.approve(f, stale)
        with sqlite3.connect(f["config_data"]["database"]["path"]) as db:
            db.execute("UPDATE tickets SET status='owner-edit' WHERE id=3")
        self.check("database mutation invalidates approved snapshot", self.commit(f, stale)["decision"] == "BLOCK" and self.rows(f)[1] == (2, "open"), "attack")
        expired = self.call(f, "database_change", operation="close_ticket", parameters={"id": 2, "status": "closed"})
        self.approve(f, expired, ttl=1)
        time.sleep(1.05)
        self.check("expired approval never changes database", self.commit(f, expired)["decision"] == "BLOCK" and self.rows(f)[1] == (2, "open"), "attack")
        last = self.call(f, "database_change", operation="close_ticket", parameters={"id": 2, "status": "closed"})
        self.approve(f, last); self.commit(f, last)
        over = self.call(f, "database_change", operation="close_ticket", parameters={"id": 3, "status": "unauthorized"})
        self.check("cumulative row budget preserves third row", over["decision"] == "BLOCK" and self.rows(f)[2] == (3, "owner-edit"), "attack")
        bundle = self.invoke(f, "export", owner=True)
        retained = self.root / "independent-evidence.json"
        retained.write_text(json.dumps(bundle))
        key = (Path(f["state"]) / "provenance.key").read_bytes()
        self.check("independently retained evidence verifies", verify_bundle(json.loads(retained.read_text()), key)["verified"], "invariant")
        bundle["payload"]["events"] = []
        try:
            verify_bundle(bundle, key)
            detected = False
        except ValueError:
            detected = True
        self.check("tampered exported evidence is rejected", detected, "attack")
        self.stop(f)
        self.export_budget()
        self.interrupted_publication()

    def export_budget(self):
        f = self.fixture("limit", export_limit=80)
        source = self.call(f, "read_file", path="incident.json")["result"]["artifact"]
        pending = self.call(f, "publish_artifact", artifact_id=source["id"], destination="archive")
        self.approve(f, pending); self.commit(f, pending)
        copy = self.call(f, "copy_artifact", artifact_id=source["id"], path="reports/second.json")["result"]["artifact"]
        denied = self.call(f, "publish_artifact", artifact_id=copy["id"], destination="archive")
        self.check("cumulative export budget prevents second object", denied["decision"] == "BLOCK" and self.objects("limit/") == ["limit/incident.json"], "attack")
        self.stop(f)

    def server_integrity(self):
        """Require a server that really checks SigV4, checksum and conditional PUT."""
        config = {'endpoint': self.endpoint, 'bucket': self.bucket, 'region': 'us-east-1', 'prefix': 'integrity',
                  'access_key_env': 'ACB_REHEARSAL_S3_ACCESS', 'secret_key_env': 'ACB_REHEARSAL_S3_SECRET', 'allow_http_for_testing': True}
        saved = {key: os.environ.get(key) for key in ('ACB_REHEARSAL_S3_ACCESS', 'ACB_REHEARSAL_S3_SECRET')}
        try:
            os.environ['ACB_REHEARSAL_S3_ACCESS'] = self.access
            os.environ['ACB_REHEARSAL_S3_SECRET'] = self.secret
            publisher = S3Publisher(config)
            publisher.publish('object.txt', b'exact reviewed bytes')
            try:
                publisher.publish('object.txt', b'forbidden overwrite')
                overwrite_denied = False
            except ExecutionUncertain:
                overwrite_denied = True
            self.check('S3 conditional PUT refuses overwrite and retains original', overwrite_denied and self.object_bytes('integrity/object.txt') == b'exact reviewed bytes', 'attack')
            os.environ['ACB_REHEARSAL_S3_SECRET'] = 'deliberately-wrong-synthetic-signing-key'
            try:
                publisher.publish('bad-signature.txt', b'must not arrive')
                signature_denied = False
            except ExecutionUncertain:
                signature_denied = True
            self.check('S3 verifies signature and refuses wrong signing key', signature_denied and 'integrity/bad-signature.txt' not in self.objects('integrity/'), 'attack')
        finally:
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def interrupted_publication(self):
        destination = urlsplit(self.endpoint)
        received = threading.Event()
        release = threading.Event()
        class DropAfterEffect(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_PUT(self):
                data = self.rfile.read(int(self.headers["Content-Length"]))
                upstream = http.client.HTTPConnection(destination.hostname, destination.port, timeout=10)
                try:
                    upstream.request("PUT", self.path, body=data, headers=dict(self.headers))
                    response = upstream.getresponse(); response.read()
                    if response.status == 200:
                        received.set()
                    release.wait(15)
                    self.close_connection = True
                finally:
                    upstream.close()
        proxy = http.server.ThreadingHTTPServer(("127.0.0.1", 0), DropAfterEffect)
        thread = threading.Thread(target=proxy.serve_forever, daemon=True); thread.start()
        f = self.fixture("crash", endpoint="http://127.0.0.1:" + str(proxy.server_port))
        try:
            source = self.call(f, "read_file", path="incident.json")["result"]["artifact"]
            pending = self.call(f, "publish_artifact", artifact_id=source["id"], destination="archive")
            self.approve(f, pending)
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(self.commit, f, pending)
                self.check("fault fixture observed real S3 acceptance", received.wait(10), "fault")
                self.stop(f, kill=True)
                try:
                    future.result(timeout=5)
                except (ValueError, OSError):
                    pass
            self.check("object exists despite interrupted owner", self.object_bytes("crash/incident.json") == (Path(f["workspace"]) / "incident.json").read_bytes(), "fault")
            self.start(f)
            status = self.invoke(f, "status")
            refused = self.commit(f, pending)
            self.check("crash leaves budget charged and retry refused", status["effects"]["export_bytes"] == len(self.object_bytes("crash/incident.json")) and refused["decision"] == "BLOCK" and self.objects("crash/") == ["crash/incident.json"], "fault")
            self.stop(f)
        finally:
            release.set(); proxy.shutdown(); proxy.server_close(); thread.join(timeout=5)

    def close(self):
        for process in self.processes:
            if process.poll() is None:
                process.kill(); process.wait(timeout=5)
        for key in self.objects(""):
            self.s3.delete_object(Bucket=self.bucket, Key=key)
        self.s3.delete_bucket(Bucket=self.bucket)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--s3-endpoint", help="existing disposable S3 server on loopback; never AWS")
    parser.add_argument("--seed", type=int, default=172)
    parser.add_argument("--verify-signature", action="store_true", help="require real SigV4 enforcement (e.g. MinIO, not Moto)")
    args = parser.parse_args()
    moto = None
    endpoint = args.s3_endpoint
    if endpoint and (urlsplit(endpoint).scheme != "http" or urlsplit(endpoint).hostname != "127.0.0.1"):
        parser.error("rehearsal permits only a disposable HTTP S3 server on 127.0.0.1")
    with tempfile.TemporaryDirectory(prefix="acb172-", dir="/tmp") as temporary, tempfile.TemporaryFile() as log:
        root = Path(temporary).resolve()
        if endpoint is None:
            port = free_port(); endpoint = f"http://127.0.0.1:{port}"
            moto = subprocess.Popen([sys.executable, "-m", "moto.server", "-H", "127.0.0.1", "-p", str(port)], stdout=log, stderr=log)
            for _ in range(150):
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=.1):
                        break
                except OSError:
                    time.sleep(.05)
            else:
                moto.kill(); moto.wait(); raise RuntimeError("local S3 emulator failed to start")
        rehearsal = Rehearsal(root, endpoint, seed=args.seed)
        error = None
        try:
            rehearsal.run()
            if args.verify_signature:
                rehearsal.server_integrity()
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
        finally:
            rehearsal.close()
            if moto:
                moto.terminate(); moto.wait(timeout=5)
        times = sorted(rehearsal.latencies)
        results = {"version": __version__, "seed": args.seed, "environment": sys.platform, "s3": "Moto loopback emulator" if moto else "supplied loopback S3 server",
                   "checks": len(rehearsal.records), "passed": sum(r["passed"] for r in rehearsal.records), "error": error,
                   "latency_ms": {"samples": len(times), "p50": round(statistics.median(times), 3) if times else None, "p95": round(times[min(len(times)-1, int(len(times)*.95))], 3) if times else None},
                   "scenarios": rehearsal.records, "limitations": ["synthetic corpus, not a comparative detector benchmark", "same-UID local development; Linux deployment isolation is a separate check"]}
        if args.output:
            args.output.write_text(json.dumps(results, indent=2) + "\n")
        print(json.dumps({k: v for k, v in results.items() if k != "scenarios"}, indent=2))
        return 1 if error else 0


if __name__ == "__main__":
    raise SystemExit(main())
