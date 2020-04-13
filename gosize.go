// Copyright 2020 Brad Fitzpatrick. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package gosize analyzes the size of Go binaries.
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strings"
)

// objdump -D ./ipn-go-bridge/tmp/libipn-go.ios:arm64.a > objdump

var (
	printPkg = flag.String("print-pkg", "", "package to print detailed stats for")
)

func main() {
	flag.Parse()
	if flag.NArg() != 1 {
		log.SetFlags(0)
		log.Fatalf("Usage: gosize <file.{a,txt}>")
	}
	fileName := flag.Arg(0)
	var objText io.Reader
	if strings.HasSuffix(fileName, ".txt") {
		f, err := os.Open(fileName)
		if err != nil {
			log.Fatal(err)
		}
		objText = f
	} else {
		cmd := exec.Command("objdump", "-D", fileName)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			log.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			log.Fatal(err)
		}
		objText = stdout
	}
	bs := bufio.NewScanner(objText)

	var curName string
	var inPkg string
	var size int64
	var pkgSize = map[string]int64{}
	var nameSize = map[string]map[string]int64{} // pkg -> name -> size
	for bs.Scan() {
		line := bs.Bytes()
		if isUnitHeader(line) {
			curName = strings.TrimRight(bs.Text()[len("0000000000000000 "):], ":\n")
			inPkg = goPackageOfName(curName)
			if inPkg != "" {
				if nameSize[inPkg] == nil {
					nameSize[inPkg] = map[string]int64{}
				}
			}
			size = 0
			continue
		}
		if inPkg == "" {
			continue
		}
		if len(bytes.TrimSpace(line)) == 0 {
			pkgSize[inPkg] += int64(size)
			nameSize[inPkg][curName] = int64(size)
			continue
		}
		if len(line) >= len("       0: ff 20 47 6f                   u") &&
			line[8] == ':' {
			ins := line[10 : 10+3*7]
			var hb int
			for _, b := range ins {
				if isHexChar(b) {
					hb++
				}
			}
			size += int64(hb / 2)
		}
	}
	if err := bs.Err(); err != nil {
		log.Fatal(err)
	}
	printSortedMap(pkgSize)

	if *printPkg != "" {
		fmt.Printf("\nPackage %s:\n", *printPkg)
		printSortedMap(nameSize[*printPkg])
	}
}

// _type..eq.crypto/elliptic.CurveParams
// _vendor/golang.org/x/net/route.errInvalidAddr
// _context.(*emptyCtx).Err
// _compress/gzip.(*Reader).Read
// _go.itab.*tailscale.com/wgengine.fakeTun,github.com/tailscale/wireguard-go/tun.Device
// _tailscale.com/control/controlclient.(*Client).mapRoutine
// _tailscale.com/control/controlclient..stmp_12
// _tailscale.com/derp/derpmap.init
// _tailscale.com/derp/derpmap.init.0
// _tailscale.com/logtail.PublicID.String
// _tailscale.com/logtail.errBufferFull
// _tailscale.com/logtail.init
// _tailscale.com/logtail/backoff.(*Backoff).BackOff
// _tailscale.com/logtail/backoff.(*Backoff).BackOff.stkobj
// _tailscale.com/logtail/backoff..inittask
// _tailscale.com/logtail/backoff..stmp_0
func goPackageOfName(name string) string {
	if name == "" {
		return ""
	}
	if name[0] != '_' && name[0] != '<' {
		return ""
	}
	name = name[1:]
	if strings.HasPrefix(name, "go.") {
		// Skip for now.
		return ""
	}
	if strings.HasPrefix(name, "type..eq.[") {
		i := strings.Index(name, "]")
		name = name[i+1:]
	}
	name = strings.TrimPrefix(name, "type..eq.")
	dot := -1
	for i := 0; i < len(name); i++ {
		b := name[i]
		if b == '/' {
			dot = -1
			continue
		}
		if b == '.' && dot == -1 {
			dot = i
		}
	}
	if dot != -1 {
		name = name[:dot]
		if strings.HasPrefix(name, "struct {") ||
			strings.HasPrefix(name, "$") {
			return ""
		}
		name = strings.TrimPrefix(name, "type..hash.")
		if strings.HasPrefix(name, "_cgoexp_") {
			return "cgo-export"
		}
		path, err := url.PathUnescape(name)
		if err != nil {
			return name
		}
		return path
	}
	return ""
}

func isUnitHeader(line []byte) bool {
	const hexLen = 16
	if len(line) < hexLen+len(" x:") ||
		line[hexLen] != ' ' {
		return false
	}
	for i := 0; i < hexLen; i++ {
		if !isHexChar(line[i]) {
			return false
		}
	}
	return true
}

func isHexChar(b byte) bool {
	return ('0' <= b && b <= '9') ||
		('a' <= b && b <= 'f') ||
		('A' <= b && b <= 'F')
}

func printSortedMap(m map[string]int64) {
	var sum int64
	var kk []string
	for k, n := range m {
		kk = append(kk, k)
		sum += n
	}
	sort.Slice(kk, func(i, j int) bool { return m[kk[i]] > m[kk[j]] })
	for i, k := range kk {
		if i == 250 {
			return
		}
		fmt.Printf("%5d (%5.02f%%) %v\n", m[k], float64(m[k])*100/float64(sum), k)
	}
}
