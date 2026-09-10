// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package gobra_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestAddrEntryCapacity(t *testing.T) {
	jar := os.Getenv("GOBRA_JAR")
	if jar == "" {
		t.Skip("Set GOBRA_JAR to run Gobra capacity checks")
	}
	jar, err := filepath.Abs(jar)
	if err != nil {
		t.Fatal(err)
	}
	toolPath := func(variable, fallback string) string {
		t.Helper()
		name := os.Getenv(variable)
		if name == "" {
			name = fallback
		}
		path, err := exec.LookPath(name)
		if err != nil {
			t.Fatal(err)
		}
		path, err = filepath.Abs(path)
		if err != nil {
			t.Fatal(err)
		}
		return path
	}
	java := toolPath("GOBRA_JAVA", "java")
	z3 := toolPath("Z3_EXE", "z3")
	proof, err := os.ReadFile("addrindexentries.go")
	if err != nil {
		t.Fatal(err)
	}
	const fixtureName = "addrindexentries_capacity.gobra"
	fixture, err := os.ReadFile(filepath.Join("testdata", fixtureName))
	if err != nil {
		t.Fatal(err)
	}
	const changedByte = "assert backing[0] == 1"
	var expectedLines []int
	for line, contents := range strings.Split(string(fixture), "\n") {
		if strings.Contains(contents, changedByte) {
			expectedLines = append(expectedLines, line+1)
		}
	}
	if len(expectedLines) != 2 {
		t.Fatal("capacity fixture must check both append helpers")
	}
	for _, unchanged := range []bool{false, true} {
		t.Run(fmt.Sprintf("unchanged=%t", unchanged), func(t *testing.T) {
			dir := t.TempDir()
			caller := string(fixture)
			if unchanged {
				caller = strings.ReplaceAll(caller, changedByte, "assert backing[0] == 0")
			}
			for name, contents := range map[string][]byte{
				"addrindexentries.go": proof,
				fixtureName:           []byte(caller),
			} {
				if err := os.WriteFile(filepath.Join(dir, name), contents, 0600); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			command := exec.CommandContext(ctx, java,
				"-Xss128m", "-Xmx2g", "-cp", jar, "viper.gobra.GobraRunner",
				"--z3Exe", z3, "--checkConsistency", "--noassumeInjectivityOnInhale",
				"--chop", "100",
				"--logLevel", "INFO", "--packageTimeout", "120s", "--assertTimeout", "10000",
				"-i", filepath.Join(dir, "addrindexentries.go"), filepath.Join(dir, fixtureName))
			command.Dir = dir
			output, err := command.CombinedOutput()
			log := regexp.MustCompile(`\x1b\[[0-9;]*m`).ReplaceAllString(string(output), "")
			if !unchanged {
				if err != nil || !strings.Contains(log, "Gobra found 0 errors.") {
					t.Fatalf("capacity proof error = %v\n%s", err, log)
				}
				return
			}
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 || ctx.Err() != nil {
				t.Fatalf("expected a verification failure, got %v\n%s", err, log)
			}
			pattern := regexp.MustCompile(`Error at: <[^>\n]*addrindexentries_capacity\.gobra:(\d+):\d+> Assert might fail\.\s+Assertion backing\[0\] == 0 might not hold\.`)
			matches := pattern.FindAllStringSubmatch(log, -1)
			if len(matches) != len(expectedLines) || !strings.Contains(log, "Gobra found 2 errors.") {
				t.Fatalf("expected only the two assertions about unchanged bytes to fail\n%s", log)
			}
			seen := make(map[int]bool)
			for _, match := range matches {
				line, err := strconv.Atoi(match[1])
				if err != nil {
					t.Fatal(err)
				}
				seen[line] = true
			}
			for _, line := range expectedLines {
				if !seen[line] {
					t.Fatalf("missing assertion failure at line %d\n%s", line, log)
				}
			}
		})
	}
}
