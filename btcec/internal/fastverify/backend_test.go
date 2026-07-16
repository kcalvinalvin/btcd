// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package fastverify

import "testing"

func TestSelectBackends(t *testing.T) {
	want := backendSelection{
		ecdsaVerify:   backendR52,
		schnorrVerify: backendR52,
	}
	if got := selectBackends(); got != want {
		t.Fatalf("backend selection: got %+v want %+v", got, want)
	}
}
