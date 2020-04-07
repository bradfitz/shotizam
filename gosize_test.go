// Copyright 2020 Brad Fitzpatrick. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import "testing"

func TestGoPackageOfName(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"_type..eq.crypto/elliptic.CurveParams", "crypto/elliptic"},
		{"_context.(*emptyCtx).Err", "context"},
		{"_tailscale.com/control/controlclient.(*Client).mapRoutine", "tailscale.com/control/controlclient"},
		{"_compress/gzip.(*Reader).Read", "compress/gzip"},
		{"_tailscale.com/logtail/backoff..inittask", "tailscale.com/logtail/backoff"},
		{"_tailscale.com/logtail/backoff..stmp_0", "tailscale.com/logtail/backoff"},
		{"_type..eq.[24]internal/cpu.option", "internal/cpu"},
		{"_type..hash.github.com/tailscale/wireguard-go/wgcfg.Endpoint", "github.com/tailscale/wireguard-go/wgcfg"},
	}
	for _, tt := range tests {
		got := goPackageOfName(tt.in)
		if got != tt.want {
			t.Errorf("pkg(%q) = %q; want %q", tt.in, got, tt.want)
		}
	}
}
