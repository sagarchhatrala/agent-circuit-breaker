# Owner route added in v1.7.2

For separate execution authority, use the [owner service](OWNER_SERVICE.md) with
distinct UIDs and the [container recipe](../examples/owner/README.md). It adds
trusted cumulative effect accounting, registered SQLite operations, S3 publication,
reviewed declassification and signed evidence. The existing Workflow boundary and
limitations below continue to apply. OS/mount/network restrictions must prevent
the agent from bypassing the owner.

# Typed workflow security and limits

The bounded claim is: **even when an agent follows a malicious instruction, actions
outside its explicit permissions cannot start through ACB's trusted execution path.**
It depends on a trusted adapter, executor and inaccessible owner policy/state. It is
not a claim about tools that bypass that path or processes sharing the owner's OS
identity and filesystem authority.

## Explicit contract

`Workflow` accepts owner configuration: principal; exact read paths with content
SHA-256 and labels; report directory; destination names with allowed labels; optional
repository status. `preview()` exposes that contract and schemas. Goal text is
metadata. No model, low risk score, `safe`, `read_only`, `principal`, or resource label
supplied in tool arguments grants authority. Extra argument fields are refused.

Files are opened with POSIX directory descriptors and no-follow flags beneath a
pinned root. Hidden/configuration paths, traversal, ambiguous paths, symlinks,
hardlinks and special files are refused. Writes create new files exclusively;
mutating an artifact invalidates its version. File data is bounded to 1 MiB. The
owner must create the allowed report directory. General shell/program execution
remains `UNKNOWN` when unresolved; there is no broad executable-name allowlist.

`repository_status` invokes system Git through a fixed child from a pinned directory
descriptor. It makes a private bounded snapshot of Git index/HEAD/refs/objects,
excluding repository configuration, hooks and alternate object sources. This avoids
Git clean-filter execution during status. Global/system configuration, inherited Git
environment, fsmonitor, pagers, hooks and submodule traversal are disabled. Snapshot
limits are 64 MiB and 10,000 files; worktree/split-index/alternate-object layouts may
abstain or fail. It reports tracked status, not a full unrestricted `git status`.

## Provenance

Owner classification binds source labels to exact source bytes. Authenticated
versioned records bind output path, digest, source IDs and transformation. Copies,
Base64 and the fixed report renderer preserve the union of labels, including across
tools and same-tool publication. The final outbound executor re-reads and hashes the
exact bytes. Destination changes are checked independently of tool identity.

The agent API has no free-form transformation, arbitrary report content, or
`declassify` operation. Sensitive and unknown outputs cannot be exported. A separate
owner-authorized declassification workflow would be required; v1.7.0 does not offer
one. Do not edit records or lower policy labels to simulate declassification.
Arbitrary Python, shell, model summaries and custom encodings are not tracked.

The provenance key and database must be inaccessible to the agent. HMAC detects
record tampering without the key; it cannot prevent a same-identity attacker from
reading the key, deleting state, or rolling back all state. Runtime SQLite performs
structural integrity checks; it is not immutable audit or a hardware trust boundary.
Keep backups, policy and process isolation under trusted operator control.

## Runtime state and outcomes

`RuntimeGate` binds canonical action, resource, principal/capability and policy.
Consumption/start is atomic; capability expiry is rechecked at start. Suspension,
revocation, policy changes, expired approvals, substitutions and replay prevent
execution. Started-but-unresolved and explicitly uncertain effects block subsequent
authority after restart. A failure cannot be treated as proof that no remote effect
occurred: remote adapters raise `ExecutionUncertain`.

New typed workflows opt into compact persisted trajectory evidence to avoid nesting
all historical evaluations in every event. Each canonical proposal, decision,
current evaluation, summary and findings remains recorded. Returned proposal
decisions still include full trajectory evidence. Default public RuntimeGate event
shape remains unchanged. Full-history evaluation and SQLite locking still add cost
with longer runs; this is not an unbounded high-throughput distributed service.

## Injection and catalog checks

Injection matching is additional evidence. Tests distinguish benign prevention
discussion, direct credential-upload requests, and an intentionally missed indirect
“recovery bundle” instruction. The latter is denied by destination permissions and
sensitivity regardless of the matcher. Legacy hash-based taint now includes same-tool
matches, but does not claim arbitrary encoding tracking; typed provenance supplies
the supported transformation guarantees.

A malformed catalog quarantines the session/clears the registered bridge's prior
catalog. New, missing and changed tools require review. `CatalogPinStore.approve`
requires the digest of the reviewed complete catalog. Restart after a reviewed
update; quarantine is not silently cleared. Legacy TOFU is visible, not independent
trust verification. Server descriptions, names and annotations are untrusted data.

Generated host commands use an absolute interpreter with Python `-I` isolation.
A project-local module or `PYTHONPATH` cannot replace the installed adapter. The
installed interpreter/package itself must remain protected. One MCP server holds a
nonblocking OS lock on its private state directory for its lifetime; a second server
fails busy rather than creating another run. Process exit releases the lock, not
consumed or unresolved authority.

## Local UI

The demo binds loopback on an available port and requires a random owner bearer
capability for data/control. Mutation also requires an exact Origin, Host and JSON
content type. It serves no CORS permissions, renders tool content via `textContent`,
and uses a restrictive CSP. The capability is supplied in a URL fragment and removed
from the visible URL; never give the launch URL to an untrusted agent process.

A loopback listener is not authorization, and a temporary directory is not an OS
sandbox. The demo has no untrusted agent process at all: its fixed fixture executor
can read synthetic files, transform them and contact only its own fixed collector.
It mounts no home, keys, private context, Docker socket or production data. Native
host integration deployments need their own OS/process isolation.
