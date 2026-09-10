# Address index fast build verification

The Fast Builder's data transformation and its recovery protocol have separate
proof obligations. Gobra supports mutable Go code through access permissions.
The useful boundary here is deterministic computation over owned buffers,
followed by database and filesystem operations. See the
[Gobra tutorial](https://github.com/viperproject/gobra/blob/master/docs/tutorial.md)
for its permission model and modular function contracts.

## Checked properties

`addrindexlevels.gobra` checks two functions in
`blockchain/indexers/addrindexlevels.go`.

For `addrLevelEntryCounts`, every input from zero through
`MaxInt64 / txEntrySize` satisfies:

* The function terminates.
* The level entry counts sum to `numEntries`.
* The result is empty exactly when `numEntries` is zero.
* Every level contains a positive number of entries.
* Level zero contains at most `level0MaxEntries` entries.
* Each higher level is half full or full, with capacity doubling per level.
* The loop's entry counts, slice length, and doubled capacity fit in a
  signed 64-bit integer.

For `addrLevelValues`, the input is a buffer of complete serialized entries,
with length at most `MaxInt64`. The proof checks:

* The function terminates and every slice access is within bounds.
* Reading the returned levels from highest to lowest yields exactly the
  original bytes, in order.
* Input bytes are unchanged.
* The returned level ranges are disjoint and cover the input buffer.
* Each level contains complete entries and satisfies the level size rules.

The contract preserves permission to the input bytes and returns permission
to the new slice headers. A ghost result records the level entry counts.
Using Gobra's slice identity operator `===`, the contract identifies the
exact input slice for every returned level. The level counts determine
adjacent ranges from the start to the end of the buffer. This accounts for
byte order and coverage. The ghost result is erased before comparison with
the Go source.

The level count input bound follows from `len(entries) / txEntrySize` on a
target with 64-bit `int`. Arithmetic bounds are explicit in the proof.
Gobra's experimental `--overflow` pass raises an internal exception for the
level proof in the tool version below.

`addrindexentries.go` checks four functions in
`blockchain/indexers/addrindexentries.go`:

* `addrEntryBlockID` reads the block ID using the little-endian expression
  over the first four bytes.
* `appendAddrEntry` copies one entry into the destination at the write
  offset, preserving the surrounding bytes and source bytes.
* `appendAddrLevelEntries` preserves the destination prefix and appends
  exactly the complete entries whose block ID is at most `baseBlockID`,
  in their original order.
* `appendAddrRecordEntries` preserves the destination prefix and appends
  every staged record's entry payload, in record order.

Both loops terminate, preserve their source bytes, and keep every access
within bounds. The append functions receive the reserved buffer and a write
offset. Their contracts require ownership of all destination bytes and enough
length for the input entries, with the buffer length bounded by `MaxInt64`.
The functions write within that length and return the next offset. Their
contracts return ownership of the buffer and preserve the bytes before the
starting offset and after the returned offset. The builder allocates the
buffer at its full reserved length and passes `entries[:entryOffset]` to
`addrLevelValues`. A checked buffer predicate ties ghost snapshots of the
destination and entry bytes to the owned buffers. The loop invariants use
this predicate to track the destination contents.
A ghost sequence also records the bytes of each staged record, with a checked
permission predicate for each record. The byte array pointer conversion
shares the record's storage.

`addrindexrange.go` checks three functions in
`blockchain/indexers/addrindexrange.go`, with `--overflow` enabled:

* `addrBuildScanRange` starts at the height after `completed` and ends at
  the target or the chunk limit. A completed scan produces an empty range.
  Its contract covers `-1 <= completed <= target <= MaxInt32`, with a
  nonnegative target. The position after `MaxInt32` remains representable.
* `addrBuildBlockID` maps heights from `-1` through `MaxInt32` to height
  plus one, including the empty index and genesis.
* `addrScanHeight` accepts a nonnegative cursor exactly when it is at most
  the end height. An accepted cursor fits in `int32` and converts exactly.
  The end height must be between zero and `MaxInt32`.

## Builder correctness argument

For one address, let `E` be the existing entries read from highest level to
lowest, `S` be the sorted staged entry payloads, and `b` be `baseBlockID`.
The intended transformation in `buildAddrLevelValues` is:

```text
entries = filter(E, blockID <= b) ++ S
levels  = addrLevelValues(entries)
```

The entry contracts establish the filtering and payload append operations.
The partition contract establishes the level layout. The builder calls the
entry functions in batches of at most `addrStagingInterruptCheckRecords`,
checking cancellation before each batch.

The checked ghost theorem `addrReplayEntries` proves replay idempotence
when every entry in `S` has `blockID > b`. Its helper proofs establish that
filtering distributes over concatenation, filtering twice is idempotent,
and filtering entries after the base yields an empty sequence. Replaying
the same `S` therefore produces the same entry bytes.

Applying this theorem to recovery requires that partial writes retain the
complete base prefix. `writeAddrIndexToDB` writes all levels for an address
inside one database transaction and keeps staging records until the
completed tip has been flushed. The caller loops, cancellation, and these
database operations remain outside the source proofs.

A complete proof should compose the following contracts:

| Code | Required property | Evidence in this worktree |
| --- | --- | --- |
| `stageAddrBlock`, `indexBlock`, `addrRecord.less` | Every scanned transaction contributes the same address entries as incremental indexing, once, in block and transaction order | Source review and record and parity tests |
| `appendAddrEntry`, `appendAddrLevelEntries`, `appendAddrRecordEntries` | Preserve base entries and append exactly the staged payloads in order, with ownership of all writable destination bytes | Gobra source proofs, capacity checks, and checked replay theorem |
| `buildAddrLevelValues` | Compose batches and levels, validate inputs, and handle cancellation | Parity, batch boundary, cancellation, and replay tests |
| `addrLevelEntryCounts`, `addrLevelValues` | Preserve all bytes and produce the specified level sizes | Gobra proof tied to Go source |
| `addrBuildScanRange`, `addrBuildBlockID`, `addrScanHeight` | Bound chunks, preserve height conversions, and stop before narrowing an exhausted cursor | Gobra source proofs with overflow checks |
| `scanAddrHeightRange`, `addrStager.add` | Workers cover each requested height once and serialize writes per shard | Source review, end to end tests, and scan boundary regression |
| `checkpoint`, `openAddrStager`, `FastBuild`, index drop paths | A durable manifest identifies durable shard prefixes, and staging survives until the database completion or drop is durable | Checkpoint resume, interrupted drop, reorganization, and flush failure tests |

The remaining concurrency proof needs ownership of worker-local
`writeIndexData`, one lock invariant per shard, and exclusive staging
lifecycle ownership. The current caller waits for all scan workers before
checkpointing or closing the stager. Mutation can be specified at these
boundaries directly.

The recovery proof must distinguish database transaction visibility from
durability. It needs contracts for `Update`, `Flush`, file `Sync`, rename,
and directory sync. Checkpoint success must describe a durable completed
height and the matching shard prefixes. A failed checkpoint can mutate the
in-memory manifest, so callers must abandon that attempt. The current
callers return on failure.

Chain reads must describe one stable main chain during scanning, and
transaction index block IDs must agree with height plus one. The normal
manager path invokes the builder during chain initialization. Concurrent
chain changes during a separate call to `FastBuild` are outside this
argument. Filesystem crash guarantees also depend on the platform,
particularly the Windows directory sync exception in `syncAddrBuildDir`.
These assumptions and external operations are not covered by the source
proofs. Parity with the incremental insertion algorithm also remains a
separate proof obligation.

## Run

Requirements are Go, Java 21, Z3 4.16.0, and Gobra. This proof was checked
with Gobra commit `d2c5af5450540c502855e53f4a5af1ba7630c41f`, distributed in
the [Gobra IDE tools release](https://github.com/viperproject/gobra-ide/releases/tag/v-2026-09-09-0721).
Download and extract its `GobraToolsLinux.zip` asset to obtain
`server/server.jar`. The archive SHA-256 is:

```text
961317133e87f19b7a4db5d53fa55f3386177ab989c8825d014aec7dd910c57d
```

From the repository root:

```sh
GOBRA_JAR=/path/to/server/server.jar \
Z3_EXE=/path/to/z3 \
./verification/gobra/verify.sh
```

Set `GOBRA_JAVA` to the Java executable if it is not on `PATH`. Tool paths
may be absolute or relative to the directory where the runner is invoked.
The runner uses temporary files and succeeds only when the source proofs,
source comparison, and capacity regression checks pass.

The capacity checks verify callers that append twice into the same backing
buffer. They also require Gobra to reject assertions that overwritten bytes
retain their initial values, for both entry loops. The tests accept only the
two expected assertion failures. Timeouts and unrelated errors fail the run.

## Connection to the Go source

All proof helpers have checked bodies. The level proof uses `.gobra`
syntax. The entry and range proofs use Go files with Gobra annotations in
comments and an `ignore` build constraint. Gobra verifies these explicit
inputs and erases their ghost code.

`sourcecheck` requires every listed function, type, and constant to match
the production Go declarations. It compares normalized Go tokens, keeping
operators, conversion operands, variadic expansion, and type definitions.
Grouped parameters and unused proof result names are normalized. It also
loads the compiled source package with `go/types` to check references to
predeclared names, including `append`, `copy`, `int`, and `nil`.

The pinned Gobra eraser drops conversion operands and omits parentheses
around pointer conversions. For the annotated Go proofs, the checker first
compares the complete Go code to production, with operands intact. It
rejects comments in conversion statements and conditions, then compares
against ghost erasure using the eraser's conversion representation. Executable annotations
elsewhere must also agree with the erased code. Unexpected declarations
and missing proof members fail the check. Tests cover changed conversion
operands, executable annotations, and missing declarations.

The Go tests cover the destination write range, multi-batch replay,
cancellation, malformed entries, and decoder compatibility with the address
index byte order.

This relies on Gobra's translation and verification machinery and Z3.
Successful allocation and execution follow the verifier's Go model.
