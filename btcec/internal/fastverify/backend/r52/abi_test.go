// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package r52

import (
	"testing"
	"unsafe"
)

// TestFieldABI guards the field layout consumed by the amd64 assembly.
func TestFieldABI(t *testing.T) {
	var f fe
	if got := unsafe.Sizeof(f); got != 40 {
		t.Fatalf("fe size: got %d want 40", got)
	}
}
