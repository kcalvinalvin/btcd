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
The runner uses temporary files and succeeds only when the source proofs
and source comparison pass.

## Connection to the Go source

All proof helpers have checked bodies. The level proof uses `.gobra`
syntax. Gobra verifies this input and erases its ghost code.

`sourcecheck` requires every listed function, type, and constant to match
the production Go declarations. It compares normalized Go tokens, keeping
operators, conversion operands, variadic expansion, and type definitions.
Grouped parameters and unused proof result names are normalized. It also
loads the compiled source package with `go/types` to check references to
predeclared names, including `append`, `copy`, `int`, and `nil`.

The Go tests cover the destination write range, multi-batch replay,
cancellation, malformed entries, and decoder compatibility with the address
index byte order.

This relies on Gobra's translation and verification machinery and Z3.
Successful allocation and execution follow the verifier's Go model.
