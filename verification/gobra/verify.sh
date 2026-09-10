#!/usr/bin/env bash
set -euo pipefail

: "${GOBRA_JAR:?Set GOBRA_JAR to the Gobra or Gobra IDE server jar}"
gobra_jar=$(realpath -- "$GOBRA_JAR")
gobra_java=$(realpath -- "$(command -v "${GOBRA_JAVA:-java}")")
gobra_z3=$(realpath -- "$(command -v "${Z3_EXE:-z3}")")
gobra_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
gobra_tmp_dir=$(mktemp -d)
trap 'rm -rf -- "$gobra_tmp_dir"' EXIT

for proof in addrindexlevels.gobra addrindexentries.go addrindexrange.go; do
	cp "$gobra_root/verification/gobra/$proof" "$gobra_tmp_dir/"
	cd "$gobra_tmp_dir"
	overflow=()
	if [[ "$proof" = addrindexrange.go ]]; then
		overflow=(--overflow)
	fi
	"$gobra_java" -Xss128m -Xmx2g -cp "$gobra_jar" \
		viper.gobra.GobraRunner \
		--z3Exe "$gobra_z3" \
		--checkConsistency --noassumeInjectivityOnInhale --chop 100 \
		--eraseGhost --logLevel INFO --packageTimeout 120s --assertTimeout 10000 \
		"${overflow[@]}" -i "$gobra_tmp_dir/$proof"
done

cd "$gobra_root"
go run ./verification/gobra/sourcecheck \
	-source blockchain/indexers/addrindexlevels.go \
	-source blockchain/indexers/addrindex.go \
	-source blockchain/indexers/addrindexentries.go \
	-source blockchain/indexers/addrindexstaging.go \
	-source blockchain/indexers/addrindexrange.go \
	-source blockchain/indexers/addrindexbuild.go \
	"$gobra_tmp_dir/addrindexlevels.gobra.ghostLess" \
	"$gobra_tmp_dir/addrindexentries.go" \
	"$gobra_tmp_dir/addrindexrange.go"

GOBRA_JAR="$gobra_jar" GOBRA_JAVA="$gobra_java" Z3_EXE="$gobra_z3" \
	go test ./verification/gobra -run '^TestAddrEntryCapacity$' -count=1
