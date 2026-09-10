// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

func parseTestProof(t *testing.T, source string) *ast.File {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "proof.go",
		"package indexers\n"+source, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	return file
}

func TestCheckErasure(t *testing.T) {
	tests := []struct {
		name      string
		annotated string
		erased    string
		wantErr   string
	}{
		{
			name:      "conversion",
			annotated: "func f(h int32) int64 { return int64(h) }",
			erased:    "func f(h int32) int64 { return int64() }",
		},
		{
			name:      "pointer conversion",
			annotated: "func f(r *[33]byte) { record := (*[33]byte)(r) }",
			erased:    "func f(r *[33]byte) { record := *[33]byte() }",
		},
		{
			name:      "conversion annotation",
			annotated: "func f(h int32) int64 { return int64(h /*@ + 1 @*/) }",
			erased:    "func f(h int32) int64 { return int64() }",
			wantErr:   "comments inside conversions",
		},
		{
			name:      "nested conversion annotation",
			annotated: "func f(h int32) uint32 { return uint32(int64(h) /*@ + 1 @*/) }",
			erased:    "func f(h int32) uint32 { return uint32() }",
			wantErr:   "comments inside conversions",
		},
		{
			name:      "wrapped conversion annotation",
			annotated: "func f(h int32) int64 { return /*@ int64(1 + @*/ int64(h) /*@ ) @*/ }",
			erased:    "func f(h int32) int64 { return int64() }",
			wantErr:   "comments inside conversions",
		},
		{
			name:      "wrapped condition annotation",
			annotated: "func f(h int32) bool { if /*@ int64(1 + @*/ int64(h) /*@ ) @*/ > 0 { return true }; return false }",
			erased:    "func f(h int32) bool { if int64() > 0 { return true }; return false }",
			wantErr:   "comments inside conversions",
		},
		{
			name:      "executable annotation",
			annotated: "func f(h int32) int64 { /*@ return 0 @*/ return int64(h) }",
			erased:    "func f(h int32) int64 { return 0; return int64() }",
			wantErr:   "differs",
		},
		{
			name:      "missing function",
			annotated: "func f() {}",
			erased:    "",
			wantErr:   "declarations differ",
		},
		{
			name:      "extra variable",
			annotated: "func f() {}",
			erased:    "func f() {}\nvar bound = 0",
			wantErr:   "only functions, types, and constants",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := checkErasure(parseTestProof(t, test.annotated), parseTestProof(t, test.erased))
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

func TestCompareConversionOperands(t *testing.T) {
	original := declarations(parseTestProof(t, "func f(h int32) int64 { return int64(h) }"))
	mutant := declarations(parseTestProof(t, "func f(h int32) int64 { return int64(h+1) }"))
	if err := compareDeclaration(original["f"], mutant["f"]); err == nil {
		t.Fatal("accepted a changed conversion operand")
	}
}

func TestCompareDeclarationSyntax(t *testing.T) {
	tests := []struct {
		name     string
		original string
		verified string
		decl     string
		equal    bool
	}{
		{
			name:     "grouped parameters and unused results",
			original: "func f(a, b int64) (int64, int64) { return a, b }",
			verified: "func f(a int64, b int64) (x int64, y int64) { return a, b }",
			decl:     "f",
			equal:    true,
		},
		{
			name:     "variadic expansion",
			original: "func f(s []any) []any { return append(s, s...) }",
			verified: "func f(s []any) []any { return append(s, s) }",
			decl:     "f",
		},
		{
			name:     "type alias",
			original: "type record [33]byte",
			verified: "type record = [33]byte",
			decl:     "record",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			original := declarations(parseTestProof(t, test.original))
			verified := declarations(parseTestProof(t, test.verified))
			err := compareDeclaration(original[test.decl], verified[test.decl])
			if (err == nil) != test.equal {
				t.Fatalf("error = %v, want equal = %v", err, test.equal)
			}
		})
	}
}
