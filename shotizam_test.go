// Copyright 2020 Brad Fitzpatrick. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestAnalyze(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode; builds binaries")
	}
	for _, tt := range []struct{ goos, goarch string }{
		{"linux", "amd64"},
		{"linux", "arm64"},
		{"darwin", "amd64"},
		{"darwin", "arm64"},
		{"windows", "amd64"},
	} {
		tt := tt
		t.Run(tt.goos+"-"+tt.goarch, func(t *testing.T) {
			t.Parallel()
			bin := filepath.Join(t.TempDir(), "hello")
			cmd := exec.Command("go", "build", "-o", bin, "./testdata/hello")
			cmd.Env = append(os.Environ(), "GOOS="+tt.goos, "GOARCH="+tt.goarch, "CGO_ENABLED=0")
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("build: %v\n%s", err, out)
			}
			data, err := os.ReadFile(bin)
			if err != nil {
				t.Fatal(err)
			}
			im, segs, err := analyze(data)
			if err != nil {
				t.Fatal(err)
			}
			checkSegments(t, im, segs)
		})
	}
}

// checkSegments checks that segs exactly cover the file and that
// nearly all bytes are explained.
func checkSegments(t *testing.T, im *image, segs []Segment) {
	var pos, unexplained, padding int64
	found := map[string]bool{}
	for _, s := range segs {
		if s.Off != pos {
			t.Fatalf("segment at %d; want %d", s.Off, pos)
		}
		if s.Size <= 0 {
			t.Fatalf("segment at %d has size %d", s.Off, s.Size)
		}
		pos += s.Size
		switch {
		case s.What == "unknown":
			t.Errorf("unknown bytes at %d, size %d", s.Off, s.Size)
		case s.What == "padding":
			padding += s.Size
		case s.Name == "" && s.Pkg == "":
			unexplained += s.Size
		}
		found[s.What+" "+s.Name] = true
	}
	if pos != int64(len(im.data)) {
		t.Fatalf("segments cover %d bytes; file is %d", pos, len(im.data))
	}
	if frac := float64(unexplained) / float64(pos-padding); frac > 0.01 {
		t.Errorf("%d of %d non-padding bytes (%.2f%%) have no name or package", unexplained, pos-padding, 100*frac)
	}
	for _, want := range []string{
		"text main.main",
		"funcname main.main",
		"pcln main.(*Greeter).Greet",
		"type main.Greeter",
		"type *main.Greeter",
		"itab go:itab.main.stringer,fmt.Stringer",
		"string main.main",
		"dwarf-info main.main",
	} {
		if !found[want] {
			t.Errorf("no segment for %q", want)
		}
	}
}

func TestPkgOf(t *testing.T) {
	im := &image{modules: []string{"gopkg.in/yaml.v3", "github.com/foo/bar"}}
	for _, tt := range []struct{ name, want string }{
		{"main.main", "main"},
		{"net/http.(*Server).Serve", "net/http"},
		{"github.com/foo/bar/baz.Func", "github.com/foo/bar/baz"},
		{"github.com/foo/bar.(*T[github.com/x/y.Z]).M", "github.com/foo/bar"},
		{"gopkg.in/yaml.v3.Marshal", "gopkg.in/yaml.v3"},
		{"type:.eq.net/netip.Addr", "net/netip"},
		{"*net/http.Request", "net/http"},
		{"[]*net/http.Request", "net/http"},
		{"map[string]net/netip.Prefix", ""}, // key is unqualified
		{"go:itab.*os.File,io.Reader", "os"},
		{"struct { key dnsmessage.section; elem string }", ""},
		{"[8]struct { key dnsmessage.RCode; elem string }", ""},
		{"*struct { sync.Mutex; val conn.Endpoint }", ""},
		{"func(int) error", ""},
		{"interface { Foo() }", ""},
		{"int", ""},
		{"_cgo_init", ""},
		{"go:buildid", ""},
	} {
		if got := im.pkgOf(tt.name); got != tt.want {
			t.Errorf("pkgOf(%q) = %q; want %q", tt.name, got, tt.want)
		}
	}
}
