// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckBindings(t *testing.T) {
	tests := []struct {
		name         string
		sourcePrefix string
		extra        string
		wantErr      string
	}{
		{
			name:  "predeclared",
			extra: "import \"fmt\"\nvar _ = fmt.Sprintf\n",
		},
		{
			name:    "append",
			extra:   "func append[S ~[]E, E any](s S, values ...E) S { return s }\n",
			wantErr: "append does not refer to Go's predeclared append",
		},
		{
			name:    "copy",
			extra:   "func copy(dst, src []byte) int { return 0 }\n",
			wantErr: "copy does not refer to Go's predeclared copy",
		},
		{
			name:    "int",
			extra:   "type int = int32\n",
			wantErr: "int does not refer to Go's predeclared int",
		},
		{
			name:    "byte",
			extra:   "type byte = uint16\n",
			wantErr: "byte does not refer to Go's predeclared byte",
		},
		{
			name:    "nil",
			extra:   "var nil = []int{1}\n",
			wantErr: "nil does not refer to Go's predeclared nil",
		},
		{
			name:         "excluded source",
			sourcePrefix: "//go:build ignore\n\n",
			wantErr:      "is not compiled into the source package",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			files := map[string]string{
				"go.mod": "module bindingstest\n\ngo 1.25\n",
				"addrindexlevels.go": test.sourcePrefix + `package indexers
func addrLevelEntryCounts(numEntries int) []int {
	if numEntries == 0 {
		return nil
	}
	return append([]int{}, numEntries)
}
func addrLevelValues(entries []byte) [][]byte {
	value := make([]byte, len(entries))
	copy(value, entries)
	return [][]byte{value}
}
`,
				"addrindex.go": "package indexers\nconst level0MaxEntries = 8\nconst txEntrySize = 4 + 4 + 4\n",
				"extra.go":     "package indexers\n" + test.extra,
			}
			for name, contents := range files {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
					t.Fatal(err)
				}
			}
			err := checkBindings([]string{
				"addrLevelEntryCounts", "addrLevelValues", "level0MaxEntries", "txEntrySize",
			}, filepath.Join(dir, "addrindexlevels.go"),
				filepath.Join(dir, "addrindex.go"))
			if test.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %v, want %q", err, test.wantErr)
			}
		})
	}
}
