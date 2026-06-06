# Redis High-Availability Operations Guide

> How AccessGate uses Redis, what high-availability (HA) topologies the current
> code supports today, and how to run Redis so that an AccessGate deployment
> survives a Redis failure with the smallest possible user impact.

This guide is for operators running AccessGate in staging or production. It is
**operations documentation**, not a code change. Where a topology would require
code changes that do **not** exist today, this guide flags them explicitly as
follow-ups so you do not deploy something the binary cannot talk to.

Roadmap: [#85](https://github.com/accessgate/accessgate/issues/85).

---

## 1. What AccessGate stores in Redis

AccessGate-auth uses Redis as its **session state store**. All keys are written
through a single client in [`internal/redis/redis.go`](../internal/redis/redis.go),
using the key layout and TTLs defined in
[`pkg/session/session.go`](../pkg/session/session.go) and configured in
[`internal/auth/config/config.go`](../internal/auth/config/config.go).

Every value AccessGate stores in Redis has a TTL. AccessGate never relies on a
key living forever.

| Data | Key prefix | Value | TTL (default) | Source of the TTL |
| --- | --- | --- | --- | --- |
| **Session** | `auth:session:<id>` | JSON: tokens + OIDC claims (`pkg/session/session.go` `Session`) | `session_ttl_seconds` = **36000** (10h) | `config.go` `ApplyDefaults` |
| **PKCE / login-flow state** | `auth:pkce:<state>` | JSON: in-flight OIDC login state (`PKCEState`) | `session_pkce_ttl_seconds` = **300** (5m) | `config.go` `ApplyDefaults` |
| **Refresh lock** | `auth:refresh_lock:<sessionID>` | `"1"` sentinel, written `SET NX` | `session_refresh_lock_ttl_seconds` = **15** | `config.go` `ApplyDefaults` |
| **Revocation** | `auth:revoked:<id>` | `"1"` sentinel | caller-supplied `ttl` (per `SetRevoked`) | `redis.go` `SetRevoked` |
| **Replay cache** | `auth:replay:<key>` | `"1"` sentinel | caller-supplied `ttl` (per `RecordReplay`) | `redis.go` `RecordReplay` |

The prefix (`auth:` above) is the configurable `session_redis_prefix`
(default `auth`); the per-type segments (`:session:`, `:pkce:`, etc.) come from
`KeyLayout` in `pkg/session/session.go`.

Two access patterns are worth calling out for HA, because they behave
differently from simple `GET`/`SET`:

- **`SET NX` refresh lock** — `obtainRefreshLock` in `redis.go` uses
  `SetArgs{Mode: "NX", TTL: ttl}`. This is a single-key, single-round-trip
  conditional write. Its correctness under failover is discussed in
  [Section 3](#3-refresh-lock-correctness-under-ha).
- **`SCAN` over the session keyspace** — `FindSessionBySubjectEmail` and
  `DeleteSessionsBySubjectEmail` in `redis.go` walk `auth:session:*` with
  `SCAN` (count 200) to support "find/logout all sessions for this user". On a
  **Redis Cluster** this is a multi-slot operation and would need rework (see
  [Section 2](#2-topology-matrix)).

### Durability implications: session state, not a system of record

Redis here is the **runtime session cache**, not the source of truth. The source
of truth for identity is the OIDC IdP; the source of truth for a user's session
is the signed session cookie (`__Host-ess_session`) plus the server-side record
in Redis. If Redis loses data:

- **Active users are logged out.** Their cookie still decodes to a session ID,
  but `getSession` returns `redis.Nil` (treated as "not found"), so the request
  is unauthenticated and the user must log in again.
- **In-flight logins fail.** A lost `auth:pkce:*` key breaks the callback for
  that one login attempt; the user simply retries.
- **No business data is lost.** AccessGate stores no orders, no user records, no
  audit-of-record in Redis. The blast radius of total Redis data loss is
  "everyone re-authenticates," not "data corruption."

This framing drives the persistence guidance in
[Section 4](#4-persistence--eviction): you are protecting **availability and
session continuity**, not durability of a system of record. A few seconds of
lost writes on failover is an annoyance (some users re-login), not a data
integrity incident.

---

## 2. Topology matrix

There are three common Redis topologies. The critical column is **"Supported by
current code"**, because AccessGate connects with a **plain single-node client**.

In `internal/redis/redis.go`, `New` does:

```go
opts, err := redis.ParseURL(url)      // parses redis_url
client := redis.NewClient(opts)       // PLAIN single-node client
client.Ping(ctx)                       // startup health check
```

`redis.NewClient` is **not** Sentinel-aware and **not** Cluster-aware. It opens
a connection pool to **one** endpoint. That single fact determines what works
today.

| Topology | What it is | Pros | Cons | Supported by current code? |
| --- | --- | --- | --- | --- |
| **Single node** | One Redis process. The default; what `docker-compose.yml` runs. | Simplest; lowest latency; no failover edge cases. | No HA — if the node dies, all sessions are unavailable until it restarts. | **Yes.** This is exactly what `redis.NewClient` expects. Default and dev mode. |
| **Managed Redis w/ failover behind one endpoint** | A managed service (e.g. cloud provider Redis) that presents **one stable DNS/VIP endpoint** and fails over to a replica internally. | HA without app changes; provider handles replication and promotion. | Brief unavailability during failover; you don't control failover timing. | **Yes — no code change.** `redis_url` points at the one endpoint; go-redis reconnects through it after failover. **Recommended for production.** |
| **Redis Sentinel** | Sentinels monitor a primary + replicas and tell clients the current primary. | Self-hosted HA; automatic primary election. | Client must speak the Sentinel protocol to discover the primary. | **No — code follow-up required.** Needs `redis.NewFailoverClient` (master name + sentinel addrs) instead of `redis.NewClient`. Not implemented today. |
| **Redis Cluster** | Data sharded across multiple primaries, each with replicas. | Horizontal scale + HA. | Multi-key ops must stay within a hash slot; `SCAN` spans nodes. | **No — code follow-up required.** Needs `redis.NewClusterClient`, **plus** changes to the cross-slot `SCAN` in `FindSessionBySubjectEmail` / `DeleteSessionsBySubjectEmail` and any future multi-key operations. Not implemented today. |

### Code follow-ups (not available today)

These are explicitly **not** shipped. Do not assume the binary can do them:

1. **Sentinel support** — would replace `redis.NewClient(opts)` in `redis.go`
   `New` with `redis.NewFailoverClient(&redis.FailoverOptions{MasterName: ..., SentinelAddrs: ...})`,
   plus config keys to carry the master name and sentinel addresses (today only
   a single `redis_url` is parsed).
2. **Cluster support** — would replace the client with
   `redis.NewClusterClient(&redis.ClusterOptions{Addrs: ...})` **and** rework
   the keyspace `SCAN` in `redis.go`, because `SCAN` against a cluster only
   covers the node it is issued to. Single-key operations (session/PKCE/lock/
   revoked/replay GET/SET/DEL) are already cluster-safe because each touches
   exactly one key.

Until those land, the only HA path that requires **zero code change** is a
**managed Redis (or any HA setup) that presents a single endpoint** and handles
failover behind it.

---

## 3. Refresh-lock correctness under HA

AccessGate serialises concurrent token refreshes for the same session with a
short-lived lock. In `internal/auth/service/service.go`, both `Refresh` and
`EnsureFreshSessionByID` call:

```go
ok, err := s.refreshLock.Obtain(ctx, sessionID, s.cfg.SessionRefreshLockTTLSeconds)
...
defer func() { _ = s.refreshLock.Release(ctx, sessionID) }()
```

`Obtain` is the `SET NX` in `redis.go` (`obtainRefreshLock`), with TTL
`session_refresh_lock_ttl_seconds` (default **15**).

### Correct on a single node

On one Redis node, `SET key value NX` is the canonical correct primitive for a
single-holder lock: exactly one concurrent caller gets `OK`; everyone else gets a
nil reply and `ok == false`. AccessGate relies on this and nothing stronger.

### What async-replication failover can do to it

Managed Redis, Sentinel, and Cluster all use **asynchronous** replication by
default. Sequence that breaks the lock's exclusivity:

1. Request A on the primary does `SET NX` and acquires the lock. `OK`.
2. The primary **fails before** that write replicates to the replica.
3. A replica is promoted to primary. The new primary has **no** lock key.
4. Request B (same session) does `SET NX` on the new primary and **also**
   acquires the lock.

For a brief window, **two refreshes can run for the same session.** This is an
inherent property of async replication, not an AccessGate bug. It is the same
class of problem the Redlock literature describes.

### Why the blast radius is small (by design)

AccessGate is built so a momentary double-acquire is benign, not catastrophic:

- **The lock TTL is only 15 seconds.** A lost/duplicated lock self-heals within
  that window — there is no way for a stale lock to wedge a session for long.
- **Refresh re-validates freshness, twice.** Before doing any work, `Refresh`
  checks `sess.NeedsRefresh(...)` and returns early if the token isn't actually
  near expiry. `EnsureFreshSessionByID` goes further: after acquiring the lock it
  **re-reads the session and re-checks `NeedsRefresh`** (the double-checked-locking
  pattern in `service.go`). So if two holders briefly coexist, the second one
  typically sees an already-refreshed session and does nothing.
- **Worst case is one redundant IdP refresh call**, possibly rotating the refresh
  token once more than necessary — not a security failure and not data loss.

### Redlock — an option, not implemented

A multi-node lock algorithm (**Redlock**) would acquire the lock on a majority of
independent Redis primaries to survive single-node failover. AccessGate does
**not** implement Redlock; `Obtain` is a single-node `SET NX`. Given the 15s TTL
and the freshness re-validation above, the single-node lock is an accepted,
documented trade-off. Redlock is a possible future follow-up if you ever require
strict single-flight refresh across a partitioned cluster; treat it as out of
scope for current deployments.

---

## 4. Persistence & eviction

Because every AccessGate value is **TTL'd session state** (not a system of
record — see [Section 1](#durability-implications-session-state-not-a-system-of-record)),
your persistence choice trades operational simplicity against how many users
re-authenticate after a restart or failover.

### Persistence modes

| Mode | Behaviour | Effect on AccessGate |
| --- | --- | --- |
| **Ephemeral (no persistence)** | Nothing written to disk. A restart starts empty. | All active sessions lost on restart → everyone re-logins. **This is what the quickstart uses on purpose** (see below). |
| **RDB snapshots** | Periodic point-in-time dumps. | A crash loses sessions created since the last snapshot. Fine for sessions: those users re-login. Low overhead. |
| **AOF (append-only file)** | Each write logged; replayed on restart. | Best session continuity across restarts. Higher disk I/O. Use `appendfsync everysec` — losing ≤1s of session writes is harmless here. |

For most production AccessGate deployments, **RDB or AOF-`everysec` is plenty**.
You are not protecting a ledger; you are reducing how often users have to log in
again. Do not over-engineer durability for ephemeral session data.

### The quickstart deliberately disables persistence

In [`deployments/docker/docker-compose.yml`](../deployments/docker/docker-compose.yml),
Redis runs with:

```yaml
command: ["redis-server", "--save", "", "--appendonly", "no"]
```

`--save ""` disables RDB; `--appendonly no` disables AOF. This is **intentional**
for a local, throwaway dev stack: it keeps the container stateless so
`docker compose down && up` always starts clean. **Do not copy this command into
production** — it is the "lose all sessions on every restart" configuration.

### Eviction: never evict live sessions

Set an explicit `maxmemory` and choose the eviction policy carefully. The danger
is silently evicting **valid, non-expired sessions** under memory pressure, which
logs users out unpredictably.

- **Recommended:** `maxmemory-policy volatile-ttl` (or `volatile-lru`). All
  AccessGate keys carry a TTL, so a `volatile-*` policy evicts the
  closest-to-expiry keys first, which is the least disruptive choice.
- **Avoid:** `noeviction` in front of a too-small `maxmemory` — writes start
  failing, so **new logins and refreshes error out** instead of degrading
  gracefully.
- **Best of all:** **size memory so you never evict live sessions.** Estimate:

  ```
  required memory ≈ peak concurrent sessions × per-session size × overhead factor
  ```

  Per-session size is dominated by the JSON `Session` value — access/refresh/ID
  tokens plus claims. Measure a representative session
  (`MEMORY USAGE auth:session:<id>`) and multiply by your peak. Add headroom for
  PKCE, revocation, and replay keys (all small and short-lived) and for Redis
  overhead. If you provision for peak, eviction never triggers and sessions only
  ever leave Redis when their TTL expires or the user logs out.

---

## 5. Failover behaviour & client tuning

### What go-redis does on failover

AccessGate uses `github.com/redis/go-redis/v9`. The `*redis.Client` created in
`redis.go` maintains a **connection pool** and **auto-reconnects**: when the
endpoint drops (failover, restart, network blip), in-flight commands on dead
connections fail, and the client transparently dials new connections for
subsequent commands once the endpoint is reachable again. With a managed
single-endpoint setup, "reachable again" means "the provider has promoted a
replica behind the same DNS/VIP."

The current code constructs the client purely from `redis.ParseURL(redis_url)`
and does not override pool size, timeouts, or retry counts — it uses go-redis
defaults. If you need to tune these, that is a small code follow-up in
`redis.go` `New` (e.g. set `opts.PoolSize`, `opts.DialTimeout`,
`opts.ReadTimeout`, `opts.MaxRetries` on the parsed `opts` before
`redis.NewClient`). Sensible production targets:

| Setting | Why it matters on failover |
| --- | --- |
| `DialTimeout` / `ReadTimeout` / `WriteTimeout` | Bound how long a request waits on a dead primary before erroring. Keep low (e.g. a few hundred ms to ~1s) so failover surfaces as fast errors, not hung requests. |
| `MaxRetries` (+ backoff) | A small retry count lets a command ride through a brief reconnect without bubbling an error to the user. |
| `PoolSize` | Size for peak concurrency; too small serialises requests, too large wastes connections/file descriptors. |

### What users see during a failover

For the few seconds between primary loss and the client reconnecting to the
promoted node:

- **Authenticated requests** that need a session `GET` may briefly return **5xx**
  (Redis error) or behave as unauthenticated (**401**), depending on the calling
  path. Once reconnected, behaviour returns to normal **without** users having to
  re-login — provided the session data survived (persistence/replication;
  [Section 4](#4-persistence--eviction)).
- **In-flight logins** during the window may fail and need a retry (PKCE state
  read/write).
- **Token refreshes** in the window may hit the lock/replication edge case from
  [Section 3](#3-refresh-lock-correctness-under-ha) — bounded and benign.

### RTO / RPO (rule of thumb)

These depend on your Redis provider/topology, not on AccessGate, but to set
expectations:

- **RTO (time to recover):** roughly the provider's failover detection +
  promotion time **plus** go-redis reconnect — typically **single-digit to a few
  tens of seconds** for managed Redis. During this window expect transient
  5xx/401.
- **RPO (data you can lose):** with async replication, the **last few writes**
  before the primary died may be lost (RPO > 0). For AccessGate that means a
  handful of just-created sessions may need to re-login. With AOF-`everysec`,
  on-disk RPO is ≤ ~1s. There is **no** business-data RPO concern because Redis
  holds only session state.

---

## 6. Monitoring

Watch Redis itself **and** AccessGate's view of it.

### Redis-side metrics (from `INFO` / your provider)

| Metric | What to watch for |
| --- | --- |
| **Latency** (command latency, `latency` / p99) | Rising latency precedes timeouts; AccessGate session reads are on the hot path of every authenticated request. |
| **Memory** (`used_memory`, `used_memory_rss` vs `maxmemory`) | Approaching `maxmemory` risks eviction of live sessions. Alert well before the ceiling. |
| **Evictions** (`evicted_keys`) | Should be **~0** in a correctly sized deployment. **Any sustained eviction means users are being logged out** — treat as a sizing incident ([Section 4](#eviction-never-evict-live-sessions)). |
| **Connected clients** (`connected_clients`) | A jump can indicate pool churn (reconnect storms after a blip) or a connection leak. |
| **Replication** (`master_link_status`, replica lag) | Lag widens the failover RPO window for sessions and the refresh-lock edge case. |

### AccessGate-side health

AccessGate exposes its own readiness signal that depends directly on Redis. In
[`internal/auth/httpserver/server.go`](../internal/auth/httpserver/server.go),
`GET /readyz` calls the configured `Pinger.Ping` (the Redis `Ping` in
`redis.go`, `Store.Ping`) with a **2-second timeout**:

- Redis reachable → `200 ok`.
- Redis `Ping` fails or times out → **`503 unhealthy`** (and the failure is
  logged: `readyz: ping failed: ...`).

Wire `/readyz` into your orchestrator's readiness probe so that an
AccessGate-auth instance that has lost Redis is taken out of rotation until the
ping succeeds again. (`GET /healthz` and `GET /livez` are liveness signals and do
**not** gate on Redis — use `/readyz` for Redis dependency health.) Also scrape
the store operation counters (`SessionStoreOp` in `redis.go`) for per-operation
success/failure rates.

---

## 7. Recommendations

| Environment | Recommendation | Code change needed? |
| --- | --- | --- |
| **Dev / local / CI** | **Single node.** Use the quickstart `docker-compose.yml` as-is (persistence off — sessions are disposable). | None. |
| **Production (preferred)** | **Managed Redis with failover behind one endpoint.** Point `redis_url` at the single managed endpoint; let the provider handle replication + promotion. Enable RDB or AOF-`everysec`; set `maxmemory` sized for peak sessions with `maxmemory-policy volatile-ttl`; never let live sessions be evicted. Probe `/readyz`. | **None** — works with today's `redis.NewClient`. |
| **Production (self-hosted HA)** | **Sentinel or Cluster** — only after the code follow-up lands. Sentinel needs `redis.NewFailoverClient`; Cluster needs `redis.NewClusterClient` **plus** rework of the cross-slot `SCAN`. | **Yes** — see [Section 2 follow-ups](#code-follow-ups-not-available-today). Do not deploy these expecting the current binary to connect. |

**Bottom line:** today, the zero-code-change HA story is **managed Redis behind a
single endpoint**. Self-managed Sentinel/Cluster are real options but are gated
on the code follow-ups documented above. Across every topology, AccessGate's
Redis is **session state, not a system of record** — design for fast recovery and
"re-login at worst," not for ledger-grade durability.

---

### Related docs

- [`docs/CONFIG-KEYS.md`](./CONFIG-KEYS.md) — `redis_url` and the session/PKCE/
  refresh-lock TTL keys referenced throughout this guide.
- [`docs/ARCHITECTURE.md`](./ARCHITECTURE.md) — where the session store sits in
  the auth service.
