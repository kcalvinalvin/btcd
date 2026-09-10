// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package gobra_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyToolPaths(t *testing.T) {
	runner, err := os.ReadFile("verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"absolute", "relative", "PATH"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			root := filepath.Join(dir, "repo")
			caller := filepath.Join(dir, "caller")
			tools := filepath.Join(dir, "tool directory")
			for _, path := range []string{caller, tools, filepath.Join(root, "verification/gobra")} {
				if err := os.MkdirAll(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			files := map[string]string{
				filepath.Join(root, "verification/gobra/verify.sh"):             string(runner),
				filepath.Join(root, "verification/gobra/addrindexlevels.gobra"): "package indexers\n",
				filepath.Join(root, "verification/gobra/addrindexrange.go"):     "package indexers\n",
				filepath.Join(tools, "server.jar"):                              "jar\n",
				filepath.Join(tools, "z3"):                                      "#!/usr/bin/env bash\nexit 0\n",
				filepath.Join(tools, "java"): `#!/usr/bin/env bash
set -euo pipefail
while (( $# )); do
	case "$1" in
		-cp) [[ "$2" = /* && -f "$2" ]] || exit 11 ;;
		--z3Exe) [[ "$2" = /* ]] || exit 12
			"$2" --version ;;
		-i) [[ -f "$2" ]] || exit 13
			printf 'package indexers\n' > "$2.ghostLess" ;;
	esac
	shift
done
`,
				filepath.Join(tools, "go"): `#!/usr/bin/env bash
set -euo pipefail
[[ "$PWD" = "$GOBRA_TEST_ROOT" ]]
case "$1" in
	run) [[ -f "${!#}" ]]
		printf 'sourcecheck reached\n' ;;
	*) exit 14 ;;
esac
`,
			}
			for path, contents := range files {
				if err := os.WriteFile(path, []byte(contents), 0700); err != nil {
					t.Fatal(err)
				}
			}
			toolPath := func(name string) string {
				path := filepath.Join(tools, name)
				if mode == "absolute" {
					return path
				}
				relative, err := filepath.Rel(caller, path)
				if err != nil {
					t.Fatal(err)
				}
				return relative
			}
			t.Setenv("GOBRA_JAR", toolPath("server.jar"))
			t.Setenv("GOBRA_JAVA", toolPath("java"))
			t.Setenv("Z3_EXE", toolPath("z3"))
			t.Setenv("GOBRA_TEST_ROOT", root)
			path := tools + string(os.PathListSeparator) + os.Getenv("PATH")
			if mode == "PATH" {
				t.Setenv("GOBRA_JAVA", "")
				t.Setenv("Z3_EXE", "")
				path = filepath.Dir(toolPath("java")) + string(os.PathListSeparator) + path
			}
			t.Setenv("PATH", path)
			command := exec.Command("bash", filepath.Join(root, "verification/gobra/verify.sh"))
			command.Dir = caller
			output, err := command.CombinedOutput()
			if err != nil || !strings.Contains(string(output), "sourcecheck reached") {
				t.Fatalf("runner error = %v\n%s", err, output)
			}
		})
	}
}
