# Review: cilium/cilium PR #44767 — BPF_MAP_TYPE_SK_STORAGE for IPv4/IPv6 socket revNAT

| | |
|---|---|
| **PR** | [cilium/cilium#44767](https://github.com/cilium/cilium/pull/44767) |
| **Author** | venk8 |
| **Branch** | `lbfix` → `main` (head `8f64a80`) |
| **Size** | 35 files · +533 / −178 |
| **Reviewed** | 2026-07-04 |
| **Verdict** | **Needs changes** |
| **Method** | 8 finder angles, 8 verification passes (5 confirmed, 3 refuted); includes triage of an external review's 11 comments |

**TL;DR.** The direction is right — per-socket storage is the natural home for connected-socket revNAT state, and the dual-lookup fallback gives a safe rollback story. But the sk_storage entry drops the peer binding that the old LRU key provided implicitly, and five confirmed issues (findings 1–5) all trace back to that one gap. Two viable fixes for finding 1 are laid out in §6 — a self-validating entry (store the backend tuple) or a pair of lifecycle guards (connected-state gate + delete on non-service connect); the PR currently does neither.

---

## 1. The core design gap: entries outlive the association they describe

The legacy LRU map keys each entry by *who the translation is about*. The reverse path builds the lookup key from the current packet's peer, so a hit simultaneously proves the socket was LB'd **and** that the stored translation applies to this exact peer. Stale entries are harmless — they can only be found by the backend they describe.

```
Legacy LRU map:      (cookie, backend addr, backend port) → (VIP, port, rev_nat_index)
New sk_storage:      socket                               → (VIP, port, rev_nat_index)
```

The sk_storage entry is keyed by the socket alone; the backend appears nowhere in it. A hit now only proves "this socket was translated toward *some* backend at *some* point." The follow-up check is self-referential — it looks the service up by the stored value and confirms the stored frontend still exists, never that the stored translation matches the packet in hand.

**And the entry's lifetime is the socket's, not the connection's.** An sk_storage entry is freed only when the kernel destroys the socket itself. One socket can host many successive associations — `connect()` to service A, `AF_UNSPEC` disconnect, `connect()` to B, unconnected `sendto()` — all on the same fd. Nothing clears the entry between them: the forward path returns `-ENXIO` before reaching `sock4_update_revnat` when the new destination isn't a service, and `sock4_delete_revnat` (invoked from `cgroup/sock_release`, i.e. socket close — where the kernel frees sk_storage anyway) touches only the LRU map. The entry's validity window (one service association) is shorter than its storage window (the socket's whole life). The old design had the same storage lifetime but was immune, because an expired association could never be *found* by a different peer.

---

## 2. Confirmed correctness findings

### F1 · Stale sk_storage entry rewrites the peer address — `CONFIRMED, critical`

`bpf/bpf_sock.c:626` (`__sock4_xlate_rev`; v6 twin at ~1271)

The sk_storage entry is consulted *before* the destination-keyed LRU lookup, is never validated against the current peer, and is never cleared on disconnect/reconnect. Scenario: a UDP socket `connect()`s to service A, disconnects (`AF_UNSPEC`), reconnects to a plain non-service address X. `getpeername()`/`recvmsg()` finds A's entry, service A still exists with a matching `rev_nat_index`, so the peer is rewritten to A's VIP even though the socket talks to X. `key.address` (X) is computed but never compared with `val->address`.

**Fix:** either make the entry self-validating (store the backend tuple, compare against the current peer) or add both lifecycle guards (connected-state gate on the read + delete on non-service connect) — see §6. The PR currently does neither.

### F2 · Termination matcher destroys sockets Cilium never load-balanced — `CONFIRMED, critical`

`bpf/bpf_sock_term.c:70` (`matches_v4` / `matches_v6`)

`matches_v4/v6` dropped the "cookie exists in the revnat map" guard and match purely on `skc_daddr`/`skc_dport` == deleted-backend addr:port. A pod connected *directly* to the backend IP:port (never via a service VIP) now gets destroyed — and the sweep also fires when a backend merely goes non-alive while still serving direct traffic. The netlink fallback in the same PR still enforces the guard (`checkSockInRevNat`), so the two destroyers disagree, and the documented contract in `termination.go:192` ("also tracked in the sock rev nat map") is violated.

**Fix:** augment rather than replace — address match *and* cookie-in-map (concrete diff in §7). That keeps the reconnect fix the new test covers while preserving the managed-socket guard.

### F3 · Unconnected UDP sockets are never terminated anymore — `CONFIRMED, critical`

`bpf/bpf_sock_term.c:70`; test coverage deleted in `bpf/tests/destroy_sock_socket_lb.c`

An unconnected socket that `sendto()`s a ClusterIP still gets an LRU revnat entry (the sendmsg path writes it), and the old cookie matcher destroyed it when its backend was deleted. Its `skc_daddr` is 0, so the new matcher can never match, and the netlink fallback can't cover it either (socket-diag destination is empty for unconnected sockets). The rewritten BPF test deleted exactly the assertions that would have caught this.

**Fix:** same as F2 — the combined matcher in §7 covers the `skc_daddr == 0` case via the map lookup; restore the deleted test assertions.

### F4 · LRU map halved and capped on a false premise — `CONFIRMED, high`

`pkg/loadbalancer/config.go:379` · `pkg/option/config.go:517` · `bpf/node_config.h` · `pkg/loadbalancer/maps/types.go:982`

The new comment says "connected UDP sockets are not tracked in the SockRevNAT table", but `sock{4,6}_update_revnat` still writes the LRU map unconditionally — and must, because the netlink destroyer's `ExistsSockRevNat` reads it. So load on the map is unchanged while capacity is halved (262144 → 131072) *and* `min(getEntries(…), default)` removes upward dynamic scaling that previously reached `LimitTableMax` (16M) on large nodes. Result: more LRU eviction → reverse-translation misses and unreliable termination checks. `SockRevNat4MapSize = 256 * 1024` in types.go is now inconsistent with everything else.

**Fix:** keep sizing unchanged until the LRU write is actually gated for connected sockets; align the constants; correct the comment. This matches jrife's versioning plan on the thread, which keeps the dual-write in version N and defers scaling down "once the LRU hash is only used for non-connected UDP" — i.e. N+1, not this PR.

### F5 · Netlink destroyer is blind to sockets that survive only via sk_storage — `CONFIRMED, high (netlink-fallback kernels)`

`pkg/loadbalancer/reconciler/termination.go:240` (`checkSockInRevNat` → `ExistsSockRevNat`)

Pre-PR, an LRU-evicted socket was broken anyway, so skipping it was moot. Post-PR, a connected socket keeps working via sk_storage after its LRU entry is evicted (made likelier by F4), but `ExistsSockRevNat` reads only the LRU maps — sk_storage can't be queried by cookie from userspace. On kernels without `bpf_sock_destroy`, the destroyer skips the socket and it keeps talking to a deleted backend. A new failure mode created by moving the source of truth without moving the readers.

---

## 3. Cleanup findings

### F6 · v4/v6 copy-paste; field-by-field copy instead of struct assignment

`bpf/bpf_sock.c:157` and ~701. The `sk_storage_get(F_CREATE)` + `memcmp` + three-field copy block appears verbatim in both `sock4_update_revnat` and `sock6_update_revnat` (the lookup/delete pairs repeat in both `xlate_rev`s too). Factor a shared `__always_inline` helper and replace the field copies with `*sk_val = val;`. The memcmp-before-write itself is fine — write avoidance, and the copy correctly never runs on the F_CREATE path.

### F7 · Test shims duplicate registry.Cell; dependency not bundled

`pkg/maps/registry/test_helper.go:10`; 8 test files + `repl/main.go`. `NewTestRegistry`/`StartTest` re-implement what `registry.Cell` already provides, and every other touched test just adds the cell. The scatter exists because lbmaps gained a hard `*registry.MapRegistry` dependency without bundling it. Bundle `registry.Cell` into the LB maps module (or a shared test composition) and drop the shims.

### F8 · Reformat-only hunks unrelated to the feature

`bpf/bpf_sock.c:191` (`sock{4,6}_delete_revnat` re-indent) · `pkg/loadbalancer/repl/main.go:83` · `bpf/tests/destroy_sock_socket_lb.c` (blank line). Move to a separate cleanup commit or drop.

---

## 4. Triage of the external review's comments

Point-by-point validity of the other review that was shared, checked against the PR head and kernel/repo facts.

| # | Claim (their severity) | Verdict | Assessment |
|---|---|---|---|
| 1 | Missing `HAVE_SK_STORAGE` guard breaks kernels < 5.2 *(Critical)* | **Partial** | The description/implementation mismatch is real — no probe or macro exists anywhere in the tree. But the load-failure claim fails on versions: Cilium's documented minimum is kernel ≥ 5.10, and `BPF_MAP_TYPE_SK_STORAGE` (v5.2) plus the cgroup/sock_addr helper protos (v5.3) predate it. Both jrife ("no probe is necessary") and ti-mo ("Cilium 1.19 already targets kernel 5.10… the `HAVE_SK_STORAGE` macro also won't fly due to #27446") said so on the thread — the probe was deliberately removed. Not a blocker; fix the PR description instead. |
| 2 | `F_CREATE` template + redundant memcmp/copy *(Critical)* | **Valid (minor)** | Correctly concludes "not a bug." Folded into F6 — the actionable part is `*sk_val = val;` and a shared v4/v6 helper. Misfiled as critical. |
| 3 | `delete_revnat` doesn't clean sk_storage *(Critical)* | **Partial** | `sock*_delete_revnat` runs from `cgroup/sock_release` — socket close — where the kernel frees sk_storage anyway, so there is no leak and no "socket reuse" hazard (a new socket gets fresh storage). Adding `sk_storage_delete` there is harmless symmetry but does *not* fix the real staleness bug, which is the reconnect path (F1) that never passes through release. |
| 4 | `sock_common` CO-RE stub is fragile / BTF may be absent *(Important)* | **Partial** | BTF is effectively guaranteed here: `bpf_sock_term` already requires the `bpf_sock_destroy` kfunc (kernel ≥ 6.4), which implies kernel BTF. The `in6_addr_stub` name mismatch is a non-issue — CO-RE field relocations resolve the `skc_v6_daddr` offset by access path, and `memcmp` never touches inner fields. Worth a code comment; not a blocker. |
| 5 | `unsafe` in test; use `unix.Connect` instead *(Important)* | **Partial** | Fair to want the raw syscall gone, but the suggestion doesn't work: `x/sys/unix` has no `Sockaddr` for `AF_UNSPEC`, which is why the raw `SYS_CONNECT` is there. Keep it, add a one-line comment saying so. |
| 6 | Halved default shifts memory budget to CT/NAT/Neigh maps *(Important)* | **Valid** | Good catch on the shared-budget side effect (visible in the config_test.go deltas) and on needing a release note. But it understates the problem: the halving's premise is false (F4) — the LRU map's load is unchanged because the dual-write remains. |
| 7 | `NewSockRevNat*StMap` panics on error *(Important)* | **Valid (minor)** | Hive style is to propagate errors. The panic exists because the `mapDesc` ctor signature can't return one — which is itself a sign the registry-backed maps are shoehorned into that mechanism (the adapter closure also discards its `maxEntries` argument). Extending `mapDesc` fixes both. |
| 8 | Whitespace changes mixed with functional changes *(Nit)* | **Valid** | Agreed — same as F8. |
| 9 | Blank line removed in `mock_bpf_sock_destroy` *(Nit)* | **Valid** | Trivial; folded into F8. |
| 10 | 128-byte test padding is a verifier stack-bounds workaround *(Nit)* | **Partial** | Right that it needs a comment, wrong about why. The padding exists because `preserve_access_index` relocates field offsets against the *kernel's* `sock_common` (~136 bytes), which is larger than the local stub — both the test's writes and the program's reads land beyond the stub, and the padding provides that room. Document that, and note it silently depends on the kernel struct staying under ~176 bytes. |
| 11 | Missing `Signed-off-by`; release-note label *(Process)* | **Valid** | Confirmed: the bot flagged commits `1b93793` and `85c372c`, and `dont-merge/needs-release-note-label` is still on the PR. |

**Corrections to its "what's good" table:**

- *"Map size reduction is justified since connected sockets now use sk_storage"* — incorrect; the LRU write is unconditional and load-bearing (F4).
- *"Socket destroyer eliminates false positives from stale map entries"* — it fixes the reconnect false positive but introduces both an over-match (F2) and an under-match (F3); the guard should have been augmented, not replaced.
- It missed the most severe issues entirely: F1, F2, F3, and F5.

---

## 5. Refuted claims — don't chase these

- **Kernel gating as a load blocker** — sk_storage (v5.2) and its sock_addr helpers (v5.3) predate Cilium's 5.10 minimum. The only action is updating the PR description, which promises probing that doesn't exist.
- **Dual-write as dead work** — the connect-time LRU write is required by the netlink destroyer's `ExistsSockRevNat`; skipping it would break termination. (Which is exactly why the sizing rationale in F4 fails.)
- **`MapReplacements` mutation in `removeUnusedMaps`** — it only prunes the per-call embedded copy that `populateMapReplacements` rebuilds from the caller's intact top-level map on every load; no caller-visible side effect.

---

## 6. Fixing F1 — with or without storing the backend address

Context from the PR thread: jrife originally proposed a richer `ipv4_sk_meta` value carrying `backend_address/backend_port`, then withdrew it — *"we can save memory and not have to store the backend address in the sock metadata after all."* That withdrawal was specifically about `bpf_sock_term`, where it is correct: a connected socket's own `skc_daddr/skc_dport` already names its backend, so the destroyer can read it from the socket. It was never established for the reverse-translation path, and it doesn't transfer there — that path asks the opposite question ("does the stored entry apply to this peer?"), and the entry carries only the frontend VIP, so there is nothing to compare the peer against. Two ways to close F1:

### Option A — self-validating entry (store the backend tuple)

```c
struct ipv4_revnat_sk_entry {
	__be32 backend_addr;   /* who this translation is about   */
	__be16 backend_port;
	__be32 address;        /* frontend VIP                    */
	__be16 port;
	__u16  rev_nat_index;
};
```

The reverse path checks `val->backend == current peer` before rewriting — restoring exactly the guarantee the old LRU key encoded, for ~6 extra bytes per socket. Stale state becomes *harmless* rather than needing to be *impossible*: immune to missed lifecycle paths, kernel sockets that bypass cgroup hooks, and state divergence across agent upgrades. It also lets the termination iterator do `sk_storage_get(sk)` + backend compare, fixing F2's over-match while keeping the reconnect fix.

### Option B — lifecycle guards (no backend stored)

Both guards are required together — each covers a distinct hole:

**Guard 1 — gate the read on the socket being connected** (fixes disconnect-then-`recvfrom`; no cgroup hook fires on `AF_UNSPEC` disconnect, so nothing else can):

```c
val = NULL;
if (ctx_full->sk && ctx_full->sk->state == BPF_TCP_ESTABLISHED)
	val = sk_storage_get(&cilium_lb4_reverse_sk_st, ctx_full->sk, 0, 0);
if (!val)
	val = map_lookup_elem(&cilium_lb4_reverse_sk, &key);
```

Connected UDP also reports `BPF_TCP_ESTABLISHED`; unconnected sockets fall through to the peer-keyed LRU lookup, which is correct for them and matches jrife's N+1 plan where the LRU map serves only non-connected UDP.

**Guard 2 — invalidate on every connect** (fixes reconnect-to-non-service; the socket is legitimately ESTABLISHED there, so guard 1 can't help). Don't patch each early-exit of `__sock4_xlate_fwd` (`-ENXIO`, `-EPERM`, L7 `return 0`, …) — delete unconditionally at the top of connect handling and let `sock4_update_revnat` re-create on successful translation:

```c
/* A connect() replaces whatever this socket previously talked to. */
if (ctx->sk)
	sk_storage_delete(&cilium_lb4_reverse_sk_st, ctx->sk);
```

Mirror both in the v6 twins. Option B saves the extra bytes but is the enumeration approach: correctness depends on "every connect passes the cgroup hook," and jrife has already flagged kernel-socket cgroup-hook weirdness (#21541) and upgrade divergence as open questions. **Option A is the robust choice; Option B is acceptable if the memory argument wins. The PR as written does neither — the entry is trusted unconditionally, which is F1.**

---

## 7. Fixing F2/F3 — restore the guard, keep the reconnect fix

Provenance first, because it decides how this should land. The matcher rewrite mixes three different things:

- **A real pre-existing bug on main, genuinely fixed here:** the old cookie-based matcher destroys a socket that reconnected away from the deleted backend, because its stale LRU entry only dies at socket close. `TestPrivilegedSocketDestroyersReconnected` is the first test to pin this down.
- **Two new regressions (F2, F3) introduced by the rewrite — not by socket storage:** the new matcher never touches sk_storage; it replaced the revnat-membership guard with an address check instead of combining them. On main, a direct non-LB connection is spared and an unconnected `sendto()` socket is destroyed; this PR flips both.
- **F1/F5 are the actual sk_storage side effects** — they have no counterpart on main.

Because the reconnect fix is independent of the sk_storage feature and is a stable-branch backport candidate, it is worth its own commit (arguably its own PR), with the sk_storage work rebased on top.

### The combined matcher

```c
static __always_inline bool matches_v4(void *sk)
{
	struct sock_common *skc = sk;
	struct ipv4_revnat_tuple key = {};
	bool addr_match, unconnected;

	if (!skc)
		return false;

	addr_match = skc->skc_daddr == cilium_sock_term_filter.address.addr4 &&
		     skc->skc_dport == bpf_htons(cilium_sock_term_filter.port);
	unconnected = !skc->skc_daddr;

	/* Connected to something other than the deleted backend: spare it,
	 * even if a stale revnat entry for this cookie still lingers.
	 */
	if (!addr_match && !unconnected)
		return false;

	/* Only destroy sockets that socket-LB actually translated toward
	 * this backend. Also covers unconnected sendmsg sockets, whose
	 * skc_daddr is 0 but whose association is recorded in the map.
	 */
	key.address = cilium_sock_term_filter.address.addr4;
	key.port    = bpf_htons(cilium_sock_term_filter.port);
	key.cookie  = get_socket_cookie(sk);

	return map_lookup_elem(&cilium_lb4_reverse_sk, &key);
}
```

`matches_v6` mirrors this with the `memcmp` on `skc_v6_daddr` and a zeroed `union v6addr` for the unconnected test. The map key is the unchanged `ipv4_revnat_tuple` — (socket cookie, backend address, backend port) — which the legacy write in `sock4_update_revnat` still populates for all paths, so the guard works today on both branches.

| Socket | Address gate | Map guard | Result |
|---|---|---|---|
| Connected via service to the deleted backend | match | entry exists | destroyed ✓ |
| Reconnected elsewhere, stale entry lingers | no match, not unconnected | — | spared ✓ (the pre-existing bug, fixed) |
| Direct connection, never LB'd (F2) | match | no entry | spared ✓ |
| Unconnected, `sendto()` via service (F3) | `daddr == 0` | entry exists | destroyed ✓ (coverage restored) |

Knock-on work in the same commit: restore the `insert4`/`insert6`/`setup()` scaffolding in `bpf/tests/destroy_sock_socket_lb.c` and assert all four rows above (the spared-when-address-only case never had a test, on main either); regenerate `pkg/datapath/bpf/sockterm_bpf{el,eb}.{go,o}` since the sockterm object ships precompiled. Note the restored guard makes termination depend on the LRU entry existing at sweep time (F5's territory) — one more reason the F4 map shrink must not land in this PR. In jrife's N+1 world the map guard here becomes `bpf_sk_storage_get()` + backend compare, which requires the backend in the value — i.e. §6 Option A sets up the N+1 termination story and Option B doesn't.

---

## 8. Pre-merge checklist

1. Close F1 via §6 Option A (backend tuple in the value, validated against the current peer) or Option B (connected-state gate + delete on non-service connect).
2. Restore the managed-socket guard in `matches_v4/v6` per §7, re-cover unconnected UDP in the BPF test, and consider splitting the reconnect fix into its own backportable commit (F2, F3).
3. Revert or re-justify the LRU sizing changes; fix the false comment and the stale `SockRevNat4MapSize` constants (F4).
4. Decide the story for netlink-fallback kernels whose sockets survive via sk_storage (F5) — the backend-tuple entry plus keeping the LRU write makes this tractable.
5. Cleanups: shared v4/v6 helper + struct assignment (F6); bundle `registry.Cell` and drop the test shims (F7); split out whitespace churn (F8); comment the CO-RE stub and the 128-byte test padding; propagate errors from the registry map constructors.
6. Process: sign off all commits, add the release-note blurb, and update the PR description to drop the nonexistent probing/`HAVE_SK_STORAGE` claims.

---

# Re-review — head `b9a85da` (2026-07-04)

The branch was updated to address the findings above. **Verdict: right design decisions, but the change is only half-propagated — as pushed, the agent fails to load socket-LB at startup, and the new destroyer matcher is not in the shipped object.**

## Properly fixed

- **F1 — fixed via §6 Option A, done right.** New `ipv{4,6}_sk_storage_entry` carries `backend_address`/`backend_port`; `__sock4_xlate_rev` honors the entry only when `sk_val->backend_address == dst_ip && sk_val->backend_port == dst_port`, else falls back to the LRU lookup. Self-validating — covers disconnect and reconnect without lifecycle hooks.
- **F4 — cleanly reverted.** Default back to `CTMapEntriesGlobalAnyDefault`, `min()` cap removed, honest TODO ("reduce once connected sockets rely solely on sk_storage"), `config_test.go` expectations reverted.
- **F6 — fixed.** `*sk_val = sk_init` struct assignment; `bpf_alignchecker.c` updated with the new types.

## New blockers

### B1 · Go side still describes the old 8/20-byte value — socket-LB fails to load

`pkg/datapath/maps/maps_generated.go` still has `ValueSize: 8, Value: "ipv4_revnat_entry"` for `cilium_lb4_reverse_sk_st` (20 for v6), `mapkv.btf` was not regenerated (`ipv4_sk_storage_entry` is absent from it), and `NewSockRevNat4StMap` still uses the 8-byte `SockRevNat4Value`. The agent creates and pins the st maps with the old value size; `bpf_sock.o`, compiled at runtime against the new 16/40-byte struct, fails the pinned-map compatibility check → socket-LB does not load.

**Fix:** add Go value structs with the backend fields, update the lbmaps constructors, re-run the `pkg/datapath/maps` codegen (mapkv.btf + maps_generated.go).

### B2 · sockterm objects not regenerated — and won't compile when they are

`pkg/datapath/bpf/sockterm_bpf{el,eb}.{o,go}` are unchanged, so the shipped destroyer still runs the v1 address-only matcher; the new sk_storage matcher in `bpf_sock_term.c` is dead code (which is also why privileged tests still pass). On regeneration the compile fails: the code calls `bpf_sk_storage_get(...)`, but outside the test harness only `sk_storage_get` is declared (`bpf/include/bpf/helpers.h:126`); `bpf_sk_storage_get` exists only as the BPF-test mock. The declared prototype also takes `struct bpf_sock *` while the iterator supplies a kernel `struct sock *` — needs a cast or a tracing-flavored declaration.

**Fix:** rename the calls, resolve the prototype, re-run the bpf2go generation for sockterm.

### B3 · Matcher dropped the current-destination check — the reconnect bug returns

The v2 matcher is "st backend == filter, else cookie-in-LRU-map." Neither branch consults what the socket is connected to *now* (the `sock_common` stub fields are now unused):

- **Stale st entry:** connect(service→backend B), reconnect to plain address X. The st entry (backend B) survives — the F1 fix compares against the *packet peer* in xlate_rev, but here the entry is compared against the *filter*, so a sweep for B destroys the socket now talking to X.
- **Cookie fallback:** sockets without an st entry (connected pre-upgrade, or sendmsg-only) hit the pure cookie lookup — exactly the pre-PR matcher, i.e. the original main-branch reconnect bug v1 fixed. Concretely: `TestPrivilegedSocketDestroyersReconnected` seeds only the LRU map, so once the sockterm object is regenerated, that test **fails** on the BPF destroyer path.

**Fix:** the §7 combination — keep v1's `skc_daddr/skc_dport == filter` gate (with the `daddr == 0` allowance for unconnected sockets) **and** the managed check (st backend match or cookie-in-map). Each half guards a failure the other cannot.

## Smaller leftovers

- `bpf/node_config.h` still says `131072` while the restored Go default is 262144 — revert the node_config halving too.
- The BPF unit test never exercises the cookie fallback with a seeded map entry (`setup()`/`insert4` still deleted) — the unconnected-UDP destroy path (F3) is implemented but untested; re-seed and assert the §7 four-case table.
- `bpf_alignchecker.c` has the new C types but no matching Go structs are registered, so the align check does nothing for them yet — hook them up with the B1 structs.
- Unchanged from the first review: F5 (much less material now that sizing is reverted), F7 (registry test shims), F8 (whitespace hunks), and process items (sign-offs, release-note label, PR description still promising probing/`HAVE_SK_STORAGE`).

## Updated checklist

1. **B1:** Go value structs + lbmaps constructors + `pkg/datapath/maps` codegen regen.
2. **B2:** `bpf_sk_storage_get` → `sk_storage_get` (or tracing declaration), regenerate sockterm bpf2go artifacts.
3. **B3:** reinstate the daddr/dport gate combined with the managed check; re-seed the BPF test; run `make tests-privileged` (expect `TestPrivilegedSocketDestroyersReconnected` to fail until B3 is fixed).
4. Revert `node_config.h` map sizes; register align-checker Go structs.
5. Carry-overs: F7, F8, sign-offs, release-note label, PR description.
