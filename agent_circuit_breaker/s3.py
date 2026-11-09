"""Bounded S3 PUT publisher with SigV4, checksums and conditional creation.

Only owner configuration supplies endpoint and credentials. A response reports
server acceptance; independent observation is used in the release rehearsal.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
from datetime import datetime, timezone
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from agent_circuit_breaker.runtime import ExecutionUncertain
from agent_circuit_breaker.workflow import digest, relative_path


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class S3Publisher:
    def __init__(self, configuration: dict):
        allowed = {"endpoint", "region", "bucket", "prefix", "access_key_env", "secret_key_env", "session_token_env", "allow_http_for_testing"}
        if not isinstance(configuration, dict) or set(configuration) - allowed:
            raise ValueError("invalid S3 destination fields")
        required = {"endpoint", "region", "bucket", "prefix", "access_key_env", "secret_key_env"}
        if not required <= set(configuration) or any(not isinstance(configuration[k], str) for k in required):
            raise ValueError("S3 destination requires string endpoint, region, bucket, prefix and credential environment names")
        self.config = dict(configuration)
        self.endpoint = self.config["endpoint"].rstrip("/")
        endpoint = urlsplit(self.endpoint)
        if endpoint.scheme not in {"http", "https"} or not endpoint.hostname or endpoint.username or endpoint.password or endpoint.query or endpoint.fragment or endpoint.path:
            raise ValueError("S3 endpoint must be an HTTP(S) origin without credentials")
        if endpoint.scheme != "https" and self.config.get("allow_http_for_testing") is not True:
            raise ValueError("S3 requires HTTPS; HTTP is only for explicitly configured local rehearsals")
        self.bucket = self.config["bucket"]
        if not isinstance(self.bucket, str) or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", self.bucket):
            raise ValueError("invalid S3 bucket")
        self.prefix = relative_path(self.config["prefix"])
        self.region = self.config["region"]
        if not isinstance(self.region, str) or not re.fullmatch(r"[a-z0-9-]{1,64}", self.region):
            raise ValueError("invalid S3 region")
        for name in ("access_key_env", "secret_key_env"):
            variable = self.config[name]
            if not isinstance(variable, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", variable):
                raise ValueError("credentials must reference owner environment variables")
        token_env = self.config.get("session_token_env")
        if token_env is not None and (not isinstance(token_env, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", token_env)):
            raise ValueError("invalid session token environment variable")

    def target(self, path: str) -> dict:
        key = self.prefix + "/" + relative_path(path)
        return {"endpoint": self.endpoint, "region": self.region, "bucket": self.bucket, "key": key}

    def publish(self, path: str, data: bytes) -> dict:
        target = self.target(path)
        access = os.environ.get(self.config["access_key_env"], "")
        secret = os.environ.get(self.config["secret_key_env"], "")
        if not access or not secret:
            raise ValueError("S3 owner credentials are unavailable")
        now = datetime.now(timezone.utc)
        day, timestamp = now.strftime("%Y%m%d"), now.strftime("%Y%m%dT%H%M%SZ")
        path_uri = "/" + self.bucket + "/" + quote(target["key"], safe="/-_.~")
        checksum = digest(data)
        headers = {"host": urlsplit(self.endpoint).netloc, "x-amz-date": timestamp,
                   "x-amz-content-sha256": checksum,
                   "x-amz-checksum-sha256": base64.b64encode(bytes.fromhex(checksum)).decode(),
                   "if-none-match": "*", "content-type": "application/octet-stream"}
        if self.config.get("session_token_env"):
            token = os.environ.get(self.config["session_token_env"], "")
            if not token:
                raise ValueError("S3 owner session token is unavailable")
            headers["x-amz-security-token"] = token
        names = ";".join(sorted(headers))
        canonical_headers = "".join(f"{name}:{headers[name].strip()}\n" for name in sorted(headers))
        request_hash = digest(("PUT\n" + path_uri + "\n\n" + canonical_headers + "\n" + names + "\n" + checksum).encode())
        scope = f"{day}/{self.region}/s3/aws4_request"
        string_to_sign = f"AWS4-HMAC-SHA256\n{timestamp}\n{scope}\n{request_hash}"
        key = ("AWS4" + secret).encode()
        for item in (day, self.region, "s3", "aws4_request"):
            key = hmac.new(key, item.encode(), hashlib.sha256).digest()
        signature = hmac.new(key, string_to_sign.encode(), hashlib.sha256).hexdigest()
        headers["authorization"] = f"AWS4-HMAC-SHA256 Credential={access}/{scope}, SignedHeaders={names}, Signature={signature}"
        request = Request(self.endpoint + path_uri, data=data, method="PUT", headers=headers)
        try:
            # Never forward owner credentials to an HTTP redirect or environment proxy.
            with build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=15) as response:
                if response.status != 200 or not response.headers.get("ETag"):
                    raise ValueError("S3 response did not establish acceptance")
                reported = response.headers.get("x-amz-checksum-sha256")
                if reported and reported != headers["x-amz-checksum-sha256"]:
                    raise ValueError("S3 checksum response mismatch")
                return {**target, "sha256": checksum, "bytes": len(data), "etag": response.headers["ETag"],
                        "evidence": "S3 server accepted conditional PUT; no automatic retries"}
        except Exception as exc:
            # Even failure responses may follow a remote effect. Reconcile explicitly.
            raise ExecutionUncertain("S3 publication outcome is uncertain; inspect the exact object before reconciliation") from exc
