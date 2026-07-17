// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package r52

import (
	"testing"
	"unsafe"
)

// TestPointABI guards the field and point layouts consumed by the amd64
// assembly implementations.
func TestPointABI(t *testing.T) {
	var f fe
	if got := unsafe.Sizeof(f); got != 40 {
		t.Fatalf("fe size: got %d want 40", got)
	}

	var a affinePoint
	if got := unsafe.Sizeof(a); got != 80 {
		t.Fatalf("affinePoint size: got %d want 80", got)
	}
	if got := unsafe.Offsetof(a.X); got != 0 {
		t.Fatalf("affinePoint.X offset: got %d want 0", got)
	}
	if got := unsafe.Offsetof(a.Y); got != 40 {
		t.Fatalf("affinePoint.Y offset: got %d want 40", got)
	}

	var j jacobianPoint
	if got := unsafe.Sizeof(j); got != 128 {
		t.Fatalf("jacobianPoint size: got %d want 128", got)
	}
	if got := unsafe.Offsetof(j.X); got != 0 {
		t.Fatalf("jacobianPoint.X offset: got %d want 0", got)
	}
	if got := unsafe.Offsetof(j.Y); got != 40 {
		t.Fatalf("jacobianPoint.Y offset: got %d want 40", got)
	}
	if got := unsafe.Offsetof(j.Z); got != 80 {
		t.Fatalf("jacobianPoint.Z offset: got %d want 80", got)
	}
	if got := unsafe.Offsetof(j.Inf); got != 120 {
		t.Fatalf("jacobianPoint.Inf offset: got %d want 120", got)
	}
}
