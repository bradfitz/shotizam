// Copyright 2020 Brad Fitzpatrick. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"sort"
)

// pclntab is a parsed Go 1.18+ pclntab. See cmd/link/internal/ld/pcln.go
// for how it's written and runtime/symtab.go for how it's read.
type pclntab struct {
	im *image
	md *moduleData // or nil

	hdr     uint64 // address of pcHeader
	magic   uint32
	quantum int
	nfunc   int
	nfiles  int

	funcnametab uint64
	cutab       uint64
	filetab     uint64
	pctab       uint64
	functab     uint64 // aka pclntable in moduledata
	end         uint64 // end of the functab region, including _func structs

	textStart uint64
	funcs     []*funcInfo
}

type funcInfo struct {
	name string
	pkg  string

	entry, end uint64 // PC range; end is the next func's entry
	addr       uint64 // address of the _func struct
	size       uint64 // size of the _func struct including pcdata and funcdata offsets

	nameOff   uint32
	pcsp      uint32
	pcfile    uint32
	pcln      uint32
	cuOffset  uint32
	startLine int32 // Go 1.20+
	pcdata    []uint32
	funcdata  []uint32 // relative to gofunc; ^0 means none
}

func (f *funcInfo) blame(what string) Blame {
	return Blame{What: what, Name: f.name, Pkg: f.pkg}
}

var pcdataNames = []string{"unsafepoint", "stackmap", "inltree", "arglive", "panicbounds"}

var funcdataNames = []string{"argsptrmaps", "localsptrmaps", "stackobjects", "inltree", "opendefer", "arginfo", "arglive", "wrapinfo"}

func pcdataWhat(i int) string {
	if i < len(pcdataNames) {
		return "pcdata-" + pcdataNames[i]
	}
	return fmt.Sprintf("pcdata-%d", i)
}

func funcdataWhat(i int) string {
	if i < len(funcdataNames) {
		return "funcdata-" + funcdataNames[i]
	}
	return fmt.Sprintf("funcdata-%d", i)
}

// parsePclntab parses the pclntab whose pcHeader is at hdr.
func (im *image) parsePclntab(hdr uint64, md *moduleData) (*pclntab, error) {
	if !im.validPCHeader(hdr) {
		return nil, fmt.Errorf("invalid pcHeader at %#x", hdr)
	}
	ps := uint64(im.ptrSize)
	t := &pclntab{
		im:      im,
		md:      md,
		hdr:     hdr,
		magic:   im.u32(hdr),
		quantum: int(im.u8(hdr + 6)),
	}
	w := hdr + 8
	word := func() uint64 {
		v := im.uptr(w)
		w += ps
		return v
	}
	t.nfunc = int(word())
	t.nfiles = int(word())
	t.textStart = word()
	t.funcnametab = hdr + word()
	t.cutab = hdr + word()
	t.filetab = hdr + word()
	t.pctab = hdr + word()
	t.functab = hdr + word()

	if t.textStart == 0 {
		switch {
		case md != nil:
			t.textStart = md.text
		case im.lookup("runtime.text") != nil:
			t.textStart = im.lookup("runtime.text").addr
		}
	}
	if !(t.funcnametab <= t.cutab && t.cutab <= t.filetab && t.filetab <= t.pctab && t.pctab <= t.functab) {
		return nil, fmt.Errorf("pcHeader offsets out of order")
	}

	fixedSize := uint64(44) // Go 1.20+
	nfuncdataOff := uint64(43)
	if t.magic == pclnMagic118 {
		fixedSize, nfuncdataOff = 40, 39
	}

	t.end = t.functab + uint64(t.nfunc)*8 + 4
	for i := 0; i < t.nfunc; i++ {
		e := t.functab + uint64(i)*8
		f := &funcInfo{
			entry: t.textStart + uint64(im.u32(e)),
			end:   t.textStart + uint64(im.u32(e+8)),
			addr:  t.functab + uint64(im.u32(e+4)),
		}
		a := f.addr
		f.nameOff = im.u32(a + 4)
		f.pcsp = im.u32(a + 16)
		f.pcfile = im.u32(a + 20)
		f.pcln = im.u32(a + 24)
		npcdata := int(im.u32(a + 28))
		f.cuOffset = im.u32(a + 32)
		if t.magic != pclnMagic118 {
			f.startLine = int32(im.u32(a + 36))
		}
		nfuncdata := int(im.u8(a + nfuncdataOff))
		for j := 0; j < npcdata; j++ {
			f.pcdata = append(f.pcdata, im.u32(a+fixedSize+uint64(j)*4))
		}
		fdOff := a + fixedSize + uint64(npcdata)*4
		for j := 0; j < nfuncdata; j++ {
			f.funcdata = append(f.funcdata, im.u32(fdOff+uint64(j)*4))
		}
		f.size = fixedSize + uint64(npcdata+nfuncdata)*4
		f.name, _ = im.cstring(t.funcnametab + uint64(f.nameOff))
		f.pkg = im.pkgOf(f.name)
		t.end = max(t.end, a+f.size)
		t.funcs = append(t.funcs, f)
	}

	// Funcs whose names don't include a package (assembly funcs,
	// shape-based equality funcs, and so on) get the package of their
	// compilation unit.
	cuPkg := map[uint32]string{}
	for _, f := range t.funcs {
		if f.pkg != "" && f.cuOffset != ^uint32(0) {
			if _, ok := cuPkg[f.cuOffset]; !ok {
				cuPkg[f.cuOffset] = f.pkg
			}
		}
	}
	for _, f := range t.funcs {
		if f.pkg == "" {
			f.pkg = cuPkg[f.cuOffset]
		}
	}
	return t, nil
}

// blame attributes the bytes of the pclntab, the text it describes,
// and the funcdata it references.
func (t *pclntab) blame() {
	im := t.im
	ps := uint64(im.ptrSize)
	hdrSize := 8 + 8*ps
	im.blameAddr(levelStruct, t.hdr, hdrSize, Blame{What: "pcheader"})
	// The whole pclntab is a container, for padding detection.
	im.blameAddrContainer(levelSymbol, t.hdr, t.end-t.hdr, Blame{What: "pclntab"})

	for _, f := range t.funcs {
		// Text. The next func's entry includes any alignment
		// padding, so trim trailing padding bytes; the section's
		// container reports them as padding.
		im.blameAddr(levelSymbol, f.entry, im.trimTextPadding(f.entry, f.end)-f.entry, f.blame(im.textKind))
	}

	t.blameFuncnametab()
	fileOwner := t.blameCutab()
	t.blameFiletab(fileOwner)
	t.blamePctab()

	// functab and _func structs.
	for i, f := range t.funcs {
		im.blameAddr(levelStruct, t.functab+uint64(i)*8, 8, f.blame("functab"))
		fixed := f.size - uint64(len(f.pcdata)+len(f.funcdata))*4
		im.blameAddr(levelStruct, f.addr, fixed, f.blame("_func"))
		if n := uint64(len(f.pcdata)) * 4; n > 0 {
			im.blameAddr(levelStruct, f.addr+fixed, n, f.blame("_func-pcdata"))
		}
		if n := uint64(len(f.funcdata)) * 4; n > 0 {
			im.blameAddr(levelStruct, f.addr+fixed+uint64(len(f.pcdata))*4, n, f.blame("_func-funcdata"))
		}
	}
	im.blameAddr(levelStruct, t.functab+uint64(t.nfunc)*8, 4, Blame{What: "functab"})

	t.blameFuncdata()
	t.blameFindfunctab()
}

// blameFuncnametab blames each name in the funcnametab. Names of
// functions that were only inlined appear here too.
func (t *pclntab) blameFuncnametab() {
	im := t.im
	for a := t.funcnametab; a < t.cutab; {
		s, ok := im.cstring(a)
		if !ok {
			return
		}
		im.blameAddr(levelStruct, a, uint64(len(s))+1, im.symBlame("funcname", s))
		a += uint64(len(s)) + 1
	}
}

// blameCutab blames each compilation unit's portion of the cutab to
// that unit's package. It returns a map from filetab offset to the
// package of the first func that references that file.
func (t *pclntab) blameCutab() map[uint32]string {
	im := t.im
	cuPkg := map[uint32]string{}
	var offs []uint32
	for _, f := range t.funcs {
		if f.cuOffset == ^uint32(0) {
			continue
		}
		if _, ok := cuPkg[f.cuOffset]; !ok {
			cuPkg[f.cuOffset] = f.pkg
			offs = append(offs, f.cuOffset)
		}
	}
	sort.Slice(offs, func(i, j int) bool { return offs[i] < offs[j] })
	nEntries := uint32((t.filetab - t.cutab) / 4)
	for i, off := range offs {
		end := nEntries
		if i+1 < len(offs) {
			end = offs[i+1]
		}
		if end > off {
			pkg := cuPkg[off]
			im.blameAddr(levelStruct, t.cutab+uint64(off)*4, uint64(end-off)*4, Blame{What: "cutab", Name: pkg, Pkg: pkg})
		}
	}

	fileOwner := map[uint32]string{}
	for _, f := range t.funcs {
		if f.pcfile == 0 || f.cuOffset == ^uint32(0) {
			continue
		}
		seen := map[int32]bool{}
		t.decodePCTable(f.pcfile, func(val int32) {
			if seen[val] || val < 0 {
				return
			}
			seen[val] = true
			idx := uint64(f.cuOffset) + uint64(val)
			if idx >= uint64(nEntries) {
				return
			}
			fileOff := im.u32(t.cutab + idx*4)
			if _, ok := fileOwner[fileOff]; !ok {
				fileOwner[fileOff] = f.pkg
			}
		})
	}
	return fileOwner
}

func (t *pclntab) blameFiletab(fileOwner map[uint32]string) {
	im := t.im
	for a := t.filetab; a < t.pctab; {
		s, ok := im.cstring(a)
		if !ok {
			return
		}
		pkg := fileOwner[uint32(a-t.filetab)]
		im.blameAddr(levelStruct, a, uint64(len(s))+1, Blame{What: "filename", Name: s, Pkg: pkg})
		a += uint64(len(s)) + 1
	}
}

// blamePctab blames each pcvalue table to the first func that uses
// it. The linker deduplicates identical tables, so a table may be
// shared by many funcs.
func (t *pclntab) blamePctab() {
	im := t.im
	im.blameAddrContainer(levelSymbol+1, t.pctab, t.functab-t.pctab, Blame{What: "pctab"})
	seen := map[uint32]bool{}
	claim := func(f *funcInfo, off uint32, what string) {
		if off == 0 || seen[off] {
			return
		}
		seen[off] = true
		n := t.decodePCTable(off, nil)
		im.blameAddr(levelStruct, t.pctab+uint64(off), uint64(n), f.blame(what))
	}
	for _, f := range t.funcs {
		claim(f, f.pcsp, "pcsp")
		claim(f, f.pcfile, "pcfile")
		claim(f, f.pcln, "pcln")
		for i, off := range f.pcdata {
			claim(f, off, pcdataWhat(i))
		}
	}
}

// decodePCTable decodes the pcvalue table at pctab offset off, calling
// fn (if non-nil) with each value. It returns the size of the table
// in bytes, including its terminating zero byte.
func (t *pclntab) decodePCTable(off uint32, fn func(val int32)) int {
	start := t.pctab + uint64(off)
	b := t.im.bytesAt(start, int(t.functab-start))
	if b == nil {
		return 0
	}
	val := int32(-1)
	i := 0
	first := true
	for i < len(b) {
		uv, n := uvarint(b[i:])
		if n <= 0 {
			return i
		}
		if uv == 0 && !first {
			return i + 1
		}
		i += n
		first = false
		if uv&1 != 0 {
			uv = ^(uv >> 1)
		} else {
			uv >>= 1
		}
		val += int32(uv)
		_, n = uvarint(b[i:])
		if n <= 0 {
			return i
		}
		i += n
		if fn != nil {
			fn(val)
		}
	}
	return i
}

func uvarint(b []byte) (uint32, int) {
	var v uint32
	var shift uint
	for i, c := range b {
		if i == 5 {
			return 0, -1
		}
		v |= uint32(c&0x7f) << shift
		if c&0x80 == 0 {
			return v, i + 1
		}
		shift += 7
	}
	return 0, 0
}

// blameFuncdata blames the funcdata blobs in go:func.* to the first
// func that references each.
func (t *pclntab) blameFuncdata() {
	im := t.im
	md := t.md
	if md == nil || md.gofunc == 0 {
		return
	}
	gofunc := md.gofunc
	end := uint64(0)
	if s := im.lookup("go:func.*"); s != nil && s.addr == gofunc && s.size > 0 {
		end = gofunc + s.size
	} else {
		end = nextAddrAfter(gofunc, 0, md.findfunctab, md.epclntab, md.types, md.etypes)
	}

	type ref struct {
		off  uint32
		f    *funcInfo
		kind int
	}
	var refs []ref
	seen := map[uint32]bool{}
	for _, f := range t.funcs {
		for i, off := range f.funcdata {
			if off == ^uint32(0) || seen[off] {
				continue
			}
			seen[off] = true
			refs = append(refs, ref{off, f, i})
		}
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].off < refs[j].off })
	if end == 0 && len(refs) > 0 {
		end = gofunc + uint64(refs[len(refs)-1].off) + 1
	}
	if end > gofunc {
		im.blameAddrContainer(levelSymbol, gofunc, end-gofunc, Blame{What: "funcdata", Name: "go:func.*"})
	}
	for i, r := range refs {
		a := gofunc + uint64(r.off)
		limit := end
		if i+1 < len(refs) {
			limit = gofunc + uint64(refs[i+1].off)
		}
		size := limit - a
		if n, ok := t.funcdataSize(r.kind, a); ok && n < size {
			size = n
		}
		im.blameAddr(levelStruct, a, size, r.f.blame(funcdataWhat(r.kind)))
	}
}

// funcdataSize returns the exact size of the funcdata of the given
// kind at addr, if known.
func (t *pclntab) funcdataSize(kind int, addr uint64) (uint64, bool) {
	im := t.im
	switch kind {
	case 0, 1: // stack maps: int32 n, int32 nbit, then n bitmaps
		n := uint64(im.u32(addr))
		nbit := uint64(im.u32(addr + 4))
		return 8 + n*((nbit+7)/8), true
	case 2: // stack objects: uintptr count, then 16-byte records
		n := im.uptr(addr)
		return uint64(im.ptrSize) + 16*n, true
	case 7: // wrapinfo: uint32 text offset
		return 4, true
	}
	return 0, false
}

// blameFindfunctab blames each bucket of the findfunctab to the func
// at the start of the text the bucket covers.
func (t *pclntab) blameFindfunctab() {
	im := t.im
	md := t.md
	if md == nil || md.findfunctab == 0 || md.maxpc <= md.minpc {
		return
	}
	const bucketSize, subBuckets = 4096, 16
	span := md.maxpc - md.minpc
	nbuckets := (span + bucketSize - 1) / bucketSize
	n := (span + bucketSize/subBuckets - 1) / (bucketSize / subBuckets)
	total := 4*nbuckets + n
	im.blameAddrContainer(levelSymbol, md.findfunctab, total, Blame{What: "findfunctab"})

	fi := 0
	for b := uint64(0); b < nbuckets; b++ {
		pc := md.minpc + b*bucketSize
		for fi+1 < len(t.funcs) && t.funcs[fi+1].entry <= pc {
			fi++
		}
		bl := Blame{What: "findfunctab"}
		if fi < len(t.funcs) {
			f := t.funcs[fi]
			bl.Name, bl.Pkg = f.name, f.pkg
		}
		size := uint64(4 + subBuckets)
		if rem := total - b*(4+subBuckets); rem < size {
			size = rem
		}
		im.blameAddr(levelStruct, md.findfunctab+b*(4+subBuckets), size, bl)
	}
}

// trimTextPadding returns end, less any trailing padding between the
// code of the func at entry and the next func at end.
func (im *image) trimTextPadding(entry, end uint64) uint64 {
	code := im.bytesAt(entry, int(end-entry))
	if code == nil {
		return end
	}
	n := len(code)
	switch im.arch {
	case "amd64", "386":
		for n > 0 && code[n-1] == 0xcc {
			n--
		}
	case "arm64":
		for n >= 4 && code[n-1] == 0 && code[n-2] == 0 && code[n-3] == 0 && code[n-4] == 0 {
			n -= 4
		}
	}
	return entry + uint64(n)
}

// file returns the name of the source file containing f's entry.
func (t *pclntab) file(f *funcInfo) string {
	if f.pcfile == 0 || f.cuOffset == ^uint32(0) {
		return ""
	}
	idx := int32(-1)
	t.decodePCTable(f.pcfile, func(v int32) {
		if idx < 0 {
			idx = v
		}
	})
	if idx < 0 {
		return ""
	}
	i := uint64(f.cuOffset) + uint64(idx)
	if i >= (t.filetab-t.cutab)/4 {
		return ""
	}
	off := t.im.u32(t.cutab + i*4)
	if off == ^uint32(0) {
		return ""
	}
	s, _ := t.im.cstring(t.filetab + uint64(off))
	return s
}
