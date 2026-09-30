// Copyright 2020 Brad Fitzpatrick. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"debug/buildinfo"
	"encoding/binary"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// image is a parsed binary: its file bytes, how its virtual addresses
// map to file offsets, its sections and symbols, and the blame
// accumulated for its bytes.
type image struct {
	data    []byte
	bm      *blameMap
	order   binary.ByteOrder
	ptrSize int

	goVersion string // e.g. "go1.27.1", or empty if unknown
	goMinor   int    // e.g. 27 for go1.27.1; 0 if unknown
	modules   []string

	maps   []mapping // sorted by addr
	sects  []section // sorted by file offset (only sections with file bytes)
	syms   []symbol  // sorted by addr
	byName map[string]*symbol

	// textKind is the What value used for executable code.
	textKind string

	arch string    // GOARCH, if known
	pcln *pclntab  // or nil if not found
	refs *refIndex // or nil if not built

	// inferredSizes is whether symbol sizes were inferred from the
	// next symbol's address, and thus include any padding.
	inferredSizes bool

	macho  *machoInfo // or nil if not Mach-O
	fixups []uint64   // addresses of pointers the dynamic loader must adjust
}

// mapping describes a range of virtual addresses backed by file bytes.
type mapping struct {
	addr uint64
	size uint64 // bytes backed by the file
	off  int64
}

type section struct {
	name string
	addr uint64 // or zero if not loaded
	off  int64  // file offset
	size int64  // bytes in file
}

type symbol struct {
	name string
	addr uint64
	size uint64
	text bool   // symbol is executable code
	what string // What for the symbol's bytes, or empty to not blame them
	end  uint64 // end of the section containing the symbol
}

func newImage(data []byte) *image {
	im := &image{
		data:     data,
		bm:       newBlameMap(data),
		byName:   make(map[string]*symbol),
		textKind: "text",
	}
	if bi, err := buildinfo.Read(bytes.NewReader(data)); err == nil {
		im.goVersion = bi.GoVersion
		im.goMinor = goMinorVersion(bi.GoVersion)
		if bi.Main.Path != "" {
			im.modules = append(im.modules, bi.Main.Path)
		}
		for _, d := range bi.Deps {
			im.modules = append(im.modules, d.Path)
		}
		// Longest first, so the most specific module matches.
		sort.Slice(im.modules, func(i, j int) bool { return len(im.modules[i]) > len(im.modules[j]) })
	}
	return im
}

var goVersionRx = regexp.MustCompile(`go1\.(\d+)`)

func goMinorVersion(v string) int {
	m := goVersionRx.FindStringSubmatch(v)
	if m == nil {
		return 0
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

// atLeast reports whether the binary was built by Go 1.minor or later.
// If the version is unknown, it's assumed to be recent.
func (im *image) atLeast(minor int) bool {
	return im.goMinor == 0 || im.goMinor >= minor
}

func (im *image) addMapping(addr, size uint64, off int64) {
	if size == 0 {
		return
	}
	im.maps = append(im.maps, mapping{addr, size, off})
}

func (im *image) addSection(name string, addr uint64, off, size int64) {
	if size <= 0 || off < 0 || off >= int64(len(im.data)) {
		return
	}
	im.sects = append(im.sects, section{name, addr, off, size})
	im.bm.addBreak(off)
	im.bm.addBreak(off + size)
}

// addSymbol adds a symbol. If what is non-empty, the symbol's bytes
// are blamed to it. sectEnd is the end address of the symbol's
// section, used to bound the extent of zero-sized carrier symbols.
func (im *image) addSymbol(name string, addr, size uint64, text bool, what string, sectEnd uint64) {
	im.syms = append(im.syms, symbol{name, addr, size, text, what, sectEnd})
}

// finishTables sorts the tables after a file format parser fills
// them in.
func (im *image) finishTables() {
	sort.Slice(im.maps, func(i, j int) bool { return im.maps[i].addr < im.maps[j].addr })
	sort.Slice(im.sects, func(i, j int) bool { return im.sects[i].off < im.sects[j].off })
	sort.SliceStable(im.syms, func(i, j int) bool {
		a, b := &im.syms[i], &im.syms[j]
		if a.addr != b.addr {
			return a.addr < b.addr
		}
		return a.size > b.size
	})
	for i := range im.syms {
		s := &im.syms[i]
		if s.size == 0 && isCarrierSym(s.name) {
			// Carrier symbols often have no size. They extend
			// to the next symbol or the end of their section.
			end := s.end
			for j := i + 1; j < len(im.syms); j++ {
				if a := im.syms[j].addr; a > s.addr {
					end = min(end, a)
					break
				}
			}
			if end > s.addr {
				s.size = end - s.addr
			}
		}
		if _, dup := im.byName[s.name]; !dup {
			im.byName[s.name] = s
		}
	}
}

// blameSymbols blames the bytes of each symbol with a What.
func (im *image) blameSymbols() {
	for i := range im.syms {
		s := &im.syms[i]
		if s.what == "" || s.size == 0 {
			continue
		}
		size := s.size
		if s.text && im.inferredSizes {
			size = im.trimTextPadding(s.addr, s.addr+s.size) - s.addr
		}
		b := im.symBlame(s.what, s.name)
		if isCarrierSym(s.name) {
			// Carrier symbols cover many smaller symbols that
			// the linker didn't emit individually; they're
			// broken down further by the Go analysis.
			im.blameAddrContainer(levelSymbol, s.addr, size, b)
		} else {
			im.blameAddr(levelSymbol, s.addr, size, b)
		}
	}
}

// addrOff returns the file offset of addr.
func (im *image) addrOff(addr uint64) (int64, bool) {
	i := sort.Search(len(im.maps), func(i int) bool { return im.maps[i].addr+im.maps[i].size > addr })
	if i == len(im.maps) {
		return 0, false
	}
	m := &im.maps[i]
	if addr < m.addr {
		return 0, false
	}
	return m.off + int64(addr-m.addr), true
}

// bytesAt returns the n file-backed bytes at addr, or nil if they
// aren't all in the file.
func (im *image) bytesAt(addr uint64, n int) []byte {
	off, ok := im.addrOff(addr)
	if !ok || n < 0 {
		return nil
	}
	end, ok := im.addrOff(addr + uint64(n) - 1)
	if n > 0 && (!ok || end != off+int64(n)-1) {
		return nil
	}
	return im.data[off : off+int64(n)]
}

func (im *image) u8(addr uint64) uint8 {
	if b := im.bytesAt(addr, 1); b != nil {
		return b[0]
	}
	return 0
}

func (im *image) u16(addr uint64) uint16 {
	if b := im.bytesAt(addr, 2); b != nil {
		return im.order.Uint16(b)
	}
	return 0
}

func (im *image) u32(addr uint64) uint32 {
	if b := im.bytesAt(addr, 4); b != nil {
		return im.order.Uint32(b)
	}
	return 0
}

func (im *image) u64(addr uint64) uint64 {
	if b := im.bytesAt(addr, 8); b != nil {
		return im.order.Uint64(b)
	}
	return 0
}

// uptr reads a pointer-sized word at addr.
func (im *image) uptr(addr uint64) uint64 {
	if im.ptrSize == 4 {
		return uint64(im.u32(addr))
	}
	return im.u64(addr)
}

// cstring returns the NUL-terminated string at addr, without the NUL.
func (im *image) cstring(addr uint64) (string, bool) {
	off, ok := im.addrOff(addr)
	if !ok {
		return "", false
	}
	i := bytes.IndexByte(im.data[off:], 0)
	if i < 0 {
		return "", false
	}
	return string(im.data[off : off+int64(i)]), true
}

// blameAddr claims the file bytes backing [addr, addr+size).
func (im *image) blameAddr(level int8, addr, size uint64, b Blame) {
	im.blameAddrSpan(level, addr, size, b, false)
}

// blameAddrContainer is like blameAddr but claims the range as a
// container. See blameMap.addContainer.
func (im *image) blameAddrContainer(level int8, addr, size uint64, b Blame) {
	im.blameAddrSpan(level, addr, size, b, true)
}

func (im *image) blameAddrSpan(level int8, addr, size uint64, b Blame, container bool) {
	for size > 0 {
		i := sort.Search(len(im.maps), func(i int) bool { return im.maps[i].addr+im.maps[i].size > addr })
		if i == len(im.maps) {
			return
		}
		m := &im.maps[i]
		if addr < m.addr {
			// Skip the unmapped hole.
			skip := m.addr - addr
			if skip >= size {
				return
			}
			addr, size = m.addr, size-skip
		}
		n := min(size, m.addr+m.size-addr)
		im.bm.addSpan(level, m.off+int64(addr-m.addr), int64(n), b, container)
		addr += n
		size -= n
	}
}

// symAt returns the symbol containing addr, or nil.
func (im *image) symAt(addr uint64) *symbol {
	i := sort.Search(len(im.syms), func(i int) bool { return im.syms[i].addr > addr })
	// Look backwards for a symbol that covers addr, preferring
	// non-empty ones.
	for j := i - 1; j >= 0 && j >= i-8; j-- {
		s := &im.syms[j]
		if addr >= s.addr && addr < s.addr+s.size {
			return s
		}
	}
	return nil
}

func (im *image) lookup(name string) *symbol { return im.byName[name] }

// sectionAt returns the name of the section containing file offset off.
func (im *image) sectionAt(off int64) string {
	i := sort.Search(len(im.sects), func(i int) bool { return im.sects[i].off+im.sects[i].size > off })
	// Sections may overlap (e.g. Mach-O segments and sections), so
	// prefer the last (innermost) one that starts at or before off.
	best := ""
	for j := i; j < len(im.sects) && im.sects[j].off <= off; j++ {
		if off < im.sects[j].off+im.sects[j].size {
			best = im.sects[j].name
		}
	}
	return best
}

// symBlame returns the blame for a symbol of the given kind.
func (im *image) symBlame(what, name string) Blame {
	return Blame{What: what, Name: name, Pkg: im.pkgOf(name)}
}

// pkgOf returns the Go package path for the symbol name, or the empty
// string if there doesn't seem to be one.
func (im *image) pkgOf(name string) string {
	name = trimSymPrefix(name)
	if name == "" {
		return ""
	}
	// Generic instantiation arguments contain other package paths.
	if i := strings.IndexByte(name, '['); i >= 0 {
		name = name[:i]
	}
	// Known module paths may contain dots in their last element
	// (e.g. "gopkg.in/yaml.v3"), which the heuristic below would
	// get wrong.
	for _, m := range im.modules {
		if len(name) > len(m) && strings.HasPrefix(name, m) {
			switch name[len(m)] {
			case '.':
				return m
			case '/':
				return m + pkgPrefix(name[len(m):])
			}
		}
	}
	return pkgPrefix(name)
}

// pkgPrefix returns the package path prefix of a symbol name using
// the standard heuristic: the text up to the first dot after the last
// slash.
//
// It returns the empty string for names that aren't qualified by a
// package path, such as unnamed composite type strings like
// "struct { mu sync.Mutex }" or "func(int) error".
func pkgPrefix(name string) string {
	lastSlash := strings.LastIndexByte(name, '/')
	dot := strings.IndexByte(name[lastSlash+1:], '.')
	var pkg string
	switch {
	case dot >= 0:
		pkg = name[:lastSlash+1+dot]
	case lastSlash >= 0:
		pkg = name
	}
	if strings.ContainsAny(pkg, " {}()[]*;,") {
		return ""
	}
	return pkg
}

func trimSymPrefix(name string) string {
	for {
		switch {
		case strings.HasPrefix(name, "type:.eq."):
			name = name[len("type:.eq."):]
		case strings.HasPrefix(name, "type:.hash."):
			name = name[len("type:.hash."):]
		case strings.HasPrefix(name, "type:"):
			name = name[len("type:"):]
		case strings.HasPrefix(name, "go:itab."):
			name = name[len("go:itab."):]
		case strings.HasPrefix(name, "go:"), strings.HasPrefix(name, "_cgo"), strings.HasPrefix(name, "x_cgo"):
			return ""
		case strings.HasPrefix(name, "*"), strings.HasPrefix(name, "[]"):
			name = strings.TrimLeft(name, "*[]")
		case strings.HasPrefix(name, "map["):
			name = name[len("map["):]
		case strings.HasPrefix(name, "chan "):
			name = name[len("chan "):]
		case strings.HasPrefix(name, "[") && strings.Contains(name, "]"):
			name = name[strings.IndexByte(name, ']')+1:]
		default:
			return name
		}
	}
}

type addrRange struct{ lo, hi uint64 }

// unclaimed returns the address ranges within [lo, hi) not claimed
// by any non-container span at minLevel or above. The range must be
// contiguous in the file.
func (im *image) unclaimed(lo, hi uint64, minLevel int8) []addrRange {
	loOff, ok := im.addrOff(lo)
	if !ok {
		return nil
	}
	hiOff := loOff + int64(hi-lo)
	var claimed []span
	for _, s := range im.bm.spans {
		if s.level >= minLevel && !s.container && s.off < hiOff && s.off+s.size > loOff {
			claimed = append(claimed, s)
		}
	}
	sort.Slice(claimed, func(i, j int) bool { return claimed[i].off < claimed[j].off })
	var gaps []addrRange
	pos := loOff
	for _, s := range claimed {
		if s.off > pos {
			gaps = append(gaps, addrRange{lo + uint64(pos-loOff), lo + uint64(s.off-loOff)})
		}
		pos = max(pos, s.off+s.size)
	}
	if pos < hiOff {
		gaps = append(gaps, addrRange{lo + uint64(pos-loOff), hi})
	}
	return gaps
}

// sortIdx sorts idxs by key.
func sortIdx(idxs []int, key func(int) uint64) {
	sort.Slice(idxs, func(i, j int) bool { return key(idxs[i]) < key(idxs[j]) })
}
