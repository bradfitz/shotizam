// Copyright 2020 Brad Fitzpatrick. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

// Type kinds. See internal/abi/type.go.
const (
	kindArray     = 17
	kindChan      = 18
	kindFunc      = 19
	kindInterface = 20
	kindMap       = 21
	kindPointer   = 22
	kindSlice     = 23
	kindString    = 24
	kindStruct    = 25
	kindUnsafePtr = 26
	kindMask      = 1<<5 - 1
)

// Type flags. See internal/abi/type.go.
const (
	tflagUncommon       = 1 << 0
	tflagExtraStar      = 1 << 1
	tflagGCMaskOnDemand = 1 << 4
)

// goType is a parsed type descriptor.
type goType struct {
	addr     uint64
	kind     uint8
	tflag    uint8
	ptrBytes uint64
	gcdata   uint64
	str      string
	pkg      string
	elem     *goType   // for pointer, slice, array, chan, map
	key      *goType   // for map
	fields   []*goType // for struct

	// referrers are the types that reference this one, in discovery
	// order, capped at a few.
	referrers []*goType
}

// typeWalker finds and blames type descriptors and the data they
// reference.
type typeWalker struct {
	im      *image
	md      *moduleData
	ps      uint64
	common  uint64 // size of abi.Type
	types   map[uint64]*goType
	order   []*goType // in discovery order
	queue   []*goType
	claimed map[uint64]bool // name and gcdata addresses already blamed
	names   map[uint64]bool // name addresses found during discovery
	itabs   []addrRange
}

// blameTypes blames the type descriptors, their names, and itabs.
func (im *image) blameTypes(md *moduleData) {
	if md.types == 0 || md.etypes <= md.types {
		return
	}
	ps := uint64(im.ptrSize)
	w := &typeWalker{
		im:      im,
		md:      md,
		ps:      ps,
		common:  4*ps + 16,
		types:   map[uint64]*goType{},
		claimed: map[uint64]bool{},
		names:   map[uint64]bool{},
	}
	im.blameAddrContainer(levelSymbol, md.types, md.etypes-md.types, Blame{What: "type", Name: "type:*"})

	// Seed with the typelinks.
	if md.typedesclen != 0 {
		// Go 1.27+: the typelinked descriptors are laid out
		// sequentially at the start of the types section.
		a := md.types + ps
		end := md.types + md.typedesclen
		for a < end {
			a = alignUp(a, ps)
			t := w.typeAt(a, nil)
			if t == nil {
				break
			}
			a += w.descriptorSize(t)
		}
	} else {
		for i := uint64(0); i < md.typelinks.len; i++ {
			off := uint64(im.u32(md.typelinks.ptr + 4*i))
			w.typeAt(md.types+off, nil)
		}
	}
	w.drain()
	w.walkItabs()
	w.drain()

	// Types reachable only from code or data (e.g. by new(T)) aren't
	// found by walking from the typelinks. Look for plausible type
	// descriptors in the remaining gaps.
	w.scanGaps()
	w.blameAll()
	w.blameOrphanNames()
}

func alignUp(a, n uint64) uint64 { return (a + n - 1) &^ (n - 1) }

func (w *typeWalker) inTypes(a uint64) bool {
	return a >= w.md.types && a < w.md.etypes
}

// typeAt returns the type at addr, parsing and queueing it if it's
// new. It returns nil if addr doesn't look like a type descriptor.
//
// The owner, if non-nil, is the type referencing this one. Unnamed
// types without a package of their own are blamed to their owner's.
func (w *typeWalker) typeAt(addr uint64, owner *goType) *goType {
	if t, ok := w.types[addr]; ok {
		if owner != nil && owner != t && len(t.referrers) < 4 {
			t.referrers = append(t.referrers, owner)
		}
		return t
	}
	if !w.inTypes(addr) {
		return nil
	}
	t := w.parseType(addr)
	if t == nil {
		return nil
	}
	if owner != nil {
		t.referrers = append(t.referrers, owner)
	}
	w.types[addr] = t
	w.order = append(w.order, t)
	w.queue = append(w.queue, t)
	return t
}

// typeOff returns the type at a TypeOff relative to md.types.
func (w *typeWalker) typeOff(off uint32, owner *goType) *goType {
	if off == 0 || off == ^uint32(0) {
		return nil
	}
	return w.typeAt(w.md.types+uint64(off), owner)
}

// parseType parses the common part of the type descriptor at addr,
// returning nil if it doesn't look valid.
func (w *typeWalker) parseType(addr uint64) *goType {
	im := w.im
	ps := w.ps
	if addr%ps != 0 || im.bytesAt(addr, int(w.common)) == nil {
		return nil
	}
	size := im.uptr(addr)
	ptrBytes := im.uptr(addr + ps)
	tflag := im.u8(addr + 2*ps + 4)
	align := im.u8(addr + 2*ps + 5)
	fieldAlign := im.u8(addr + 2*ps + 6)
	kind := im.u8(addr+2*ps+7) & kindMask
	equal := im.uptr(addr + 2*ps + 8)
	gcdata := im.uptr(addr + 3*ps + 8)
	strOff := im.u32(addr + 4*ps + 8)
	if kind == 0 || kind > kindUnsafePtr || ptrBytes > size || !validAlign(align) || !validAlign(fieldAlign) {
		return nil
	}
	if equal != 0 {
		// Equal is a func value: a pointer to a funcdesc that
		// points to the code.
		if fn := im.uptr(equal); fn < w.md.text || fn >= w.md.etext {
			return nil
		}
	}
	if ptrBytes != 0 && im.bytesAt(gcdata, 1) == nil && tflag&tflagGCMaskOnDemand == 0 {
		return nil
	}
	str, ok := w.nameStr(w.md.types + uint64(strOff))
	if !ok || str == "" {
		return nil
	}
	if tflag&tflagExtraStar != 0 {
		if !strings.HasPrefix(str, "*") {
			return nil
		}
		str = str[1:]
	}
	return &goType{addr: addr, kind: kind, tflag: tflag, ptrBytes: ptrBytes, gcdata: gcdata, str: str}
}

func validAlign(a uint8) bool {
	return a != 0 && a&(a-1) == 0 && a <= 64
}

// kindSize returns the size of the kind-specific type struct,
// including the common abi.Type.
func (w *typeWalker) kindSize(kind uint8) uint64 {
	ps := w.ps
	switch kind {
	case kindArray:
		return w.common + 3*ps
	case kindChan:
		return w.common + 2*ps
	case kindFunc:
		return w.common + ps // InCount, OutCount, and padding
	case kindInterface, kindStruct:
		return w.common + 4*ps // PkgPath and a slice
	case kindMap:
		switch {
		case w.im.atLeast(27):
			return w.common + 11*ps
		case w.im.atLeast(24):
			return w.common + 8*ps
		default:
			return w.common + 4*ps + 8
		}
	case kindPointer, kindSlice:
		return w.common + ps
	}
	return w.common
}

// descriptorSize returns the size of t's descriptor as laid out
// contiguously by the linker. See abi.Type.DescriptorSize.
func (w *typeWalker) descriptorSize(t *goType) uint64 {
	im := w.im
	n := w.kindSize(t.kind)
	mcount := uint64(0)
	if t.tflag&tflagUncommon != 0 {
		mcount = uint64(im.u16(t.addr + n + 4))
		n += 16
	}
	switch t.kind {
	case kindFunc:
		in, out := im.u16(t.addr+w.common), im.u16(t.addr+w.common+2)&(1<<15-1)
		n += uint64(in+out) * w.ps
	case kindInterface:
		n += im.uptr(t.addr+w.common+2*w.ps) * 8
	case kindStruct:
		n += im.uptr(t.addr+w.common+2*w.ps) * 3 * w.ps
	}
	return n + mcount*16
}

// drain processes queued types until there are none left.
func (w *typeWalker) drain() {
	for len(w.queue) > 0 {
		t := w.queue[0]
		w.queue = w.queue[1:]
		w.processType(t, false)
	}
}

// blameAll blames every discovered type. It runs after discovery so
// that unnamed types can be blamed to the package of any type that
// references them.
func (w *typeWalker) blameAll() {
	for _, t := range w.order {
		if t.pkg == "" {
			t.pkg = w.pkgOfType(t, 0)
		}
	}
	for _, t := range w.order {
		w.processType(t, true)
	}
}

// processType queues the types t references, recording t as their
// referrer. If blame is true, it also blames t's descriptor and the
// data it references.
func (w *typeWalker) processType(t *goType, blame bool) {
	im := w.im
	ps := w.ps
	a := t.addr
	kindSize := w.kindSize(t.kind)

	blameAddr := func(level int8, addr, size uint64, b Blame) {
		if blame {
			im.blameAddr(level, addr, size, b)
		}
	}
	claimName := func(addr uint64, b Blame) {
		if blame {
			w.claimName(addr, b)
		} else if addr != w.md.types {
			w.names[addr] = true
		}
	}
	claimNamePtr := func(addr uint64, b Blame) {
		if addr != 0 {
			claimName(addr, b)
		}
	}

	var refs []*goType
	ptr := func(off uint64) *goType {
		rt := w.typeAt(im.uptr(a+off), t)
		if rt != nil {
			refs = append(refs, rt)
		}
		return rt
	}
	switch t.kind {
	case kindArray:
		t.elem = ptr(w.common)
		ptr(w.common + ps)
	case kindChan, kindPointer, kindSlice:
		t.elem = ptr(w.common)
	case kindMap:
		t.key = ptr(w.common)
		t.elem = ptr(w.common + ps)
		ptr(w.common + 2*ps)
	}
	w.typeOff(im.u32(a+4*ps+12), t) // PtrToThis

	// Named types have their package in the uncommon type.
	var uncommon uint64
	if t.tflag&tflagUncommon != 0 {
		uncommon = a + kindSize
		if pp, ok := w.nameStr(w.md.types + uint64(im.u32(uncommon))); ok && !blame {
			t.pkg = pp
		}
	}
	b := Blame{What: "type", Name: t.str, Pkg: t.pkg}
	nameBlame := Blame{What: "type-name", Name: t.str, Pkg: t.pkg}

	blameAddr(levelStruct, a, kindSize, b)
	claimName(w.md.types+uint64(im.u32(a+4*ps+8)), nameBlame)
	if blame {
		w.claimGCData(t, b)
	}

	if uncommon != 0 {
		blameAddr(levelStruct, uncommon, 16, b)
		pkgName := w.md.types + uint64(im.u32(uncommon))
		if pkgName != w.md.types {
			pp, _ := w.nameStr(pkgName)
			claimName(pkgName, Blame{What: "type-pkgpath", Pkg: pp})
		}
		mcount := uint64(im.u16(uncommon + 4))
		moff := uint64(im.u32(uncommon + 8))
		m := uncommon + moff
		if mcount > 0 && mcount < 1<<14 {
			blameAddr(levelStruct, m, mcount*16, b)
			for i := uint64(0); i < mcount; i++ {
				claimName(w.md.types+uint64(im.u32(m+i*16)), nameBlame)
				w.typeOff(im.u32(m+i*16+4), t)
			}
		}
	}

	switch t.kind {
	case kindFunc:
		in, out := uint64(im.u16(a+w.common)), uint64(im.u16(a+w.common+2)&(1<<15-1))
		params := a + kindSize
		if uncommon != 0 {
			params += 16
		}
		if n := in + out; n > 0 && n < 1<<12 {
			blameAddr(levelStruct, params, n*ps, b)
			for i := uint64(0); i < n; i++ {
				w.typeAt(im.uptr(params+i*ps), t)
			}
		}
	case kindInterface:
		claimNamePtr(im.uptr(a+w.common), Blame{What: "type-pkgpath"})
		methods, n := im.uptr(a+w.common+ps), im.uptr(a+w.common+2*ps)
		if n > 0 && n < 1<<14 {
			blameAddr(levelStruct, methods, n*8, b)
			for i := uint64(0); i < n; i++ {
				claimName(w.md.types+uint64(im.u32(methods+i*8)), nameBlame)
				w.typeOff(im.u32(methods+i*8+4), t)
			}
		}
	case kindStruct:
		claimNamePtr(im.uptr(a+w.common), Blame{What: "type-pkgpath"})
		fields, n := im.uptr(a+w.common+ps), im.uptr(a+w.common+2*ps)
		if n > 0 && n < 1<<16 {
			blameAddr(levelStruct, fields, n*3*ps, b)
			for i := uint64(0); i < n; i++ {
				f := fields + i*3*ps
				claimNamePtr(im.uptr(f), nameBlame)
				if ft := w.typeAt(im.uptr(f+ps), t); ft != nil && !blame {
					t.fields = append(t.fields, ft)
				}
			}
		}
	}
}

// pkgOfType returns the package to blame for an unnamed type.
func (w *typeWalker) pkgOfType(t *goType, depth int) string {
	if t.pkg != "" || depth > 10 {
		return t.pkg
	}
	// Unnamed types take the package of their element (or key) type,
	// if it has one: []foo.T is blamed on foo.
	for _, e := range []*goType{t.elem, t.key} {
		if e != nil {
			if p := w.pkgOfType(e, depth+1); p != "" {
				return p
			}
		}
	}
	switch t.kind {
	case kindStruct, kindFunc, kindInterface:
	default:
		if p := w.im.pkgOf(t.str); p != "" {
			return p
		}
	}
	if b, ok := w.im.refs.referrer(t.addr); ok && b.Pkg != "" {
		return b.Pkg
	}
	for _, r := range t.referrers {
		if p := w.pkgOfType(r, depth+1); p != "" {
			return p
		}
	}
	// Otherwise, a struct (such as a map's internal group type) is
	// blamed on its first field type with a package.
	for _, f := range t.fields {
		if p := w.pkgOfType(f, depth+1); p != "" {
			return p
		}
	}
	return ""
}

// claimGCData blames the pointer bitmap referenced by t's GCData.
func (w *typeWalker) claimGCData(t *goType, b Blame) {
	if t.gcdata == 0 || t.ptrBytes == 0 || t.tflag&tflagGCMaskOnDemand != 0 || w.claimed[t.gcdata] {
		return
	}
	w.claimed[t.gcdata] = true
	n := (t.ptrBytes/w.ps + 7) / 8
	b.What = "gcbits"
	w.im.blameAddr(levelStruct, t.gcdata, n, b)
}

// nameSize returns the encoded size of the abi.Name at addr and its
// string, or false if it doesn't look like a valid name.
func (w *typeWalker) nameAt(addr uint64) (size uint64, s string, ok bool) {
	im := w.im
	flags := im.u8(addr)
	if flags&^0xf != 0 {
		return 0, "", false
	}
	b := im.bytesAt(addr+1, 10)
	if b == nil {
		return 0, "", false
	}
	l, n := uvarint(b)
	if n <= 0 || l > 1<<16 {
		return 0, "", false
	}
	strAddr := addr + 1 + uint64(n)
	sb := im.bytesAt(strAddr, int(l))
	if sb == nil || !utf8.Valid(sb) || hasControl(sb) {
		return 0, "", false
	}
	size = 1 + uint64(n) + uint64(l)
	if flags&(1<<1) != 0 { // has tag
		tb := im.bytesAt(addr+size, 10)
		if tb == nil {
			return 0, "", false
		}
		tl, tn := uvarint(tb)
		if tn <= 0 || tl > 1<<16 {
			return 0, "", false
		}
		size += uint64(tn) + uint64(tl)
	}
	if flags&(1<<2) != 0 { // has pkgPath
		size += 4
	}
	return size, string(sb), true
}

func (w *typeWalker) nameStr(addr uint64) (string, bool) {
	_, s, ok := w.nameAt(addr)
	return s, ok
}

// claimName blames the abi.Name at addr, a NameOff target.
func (w *typeWalker) claimName(addr uint64, b Blame) {
	if addr == w.md.types || w.claimed[addr] {
		return
	}
	size, s, ok := w.nameAt(addr)
	if !ok {
		return
	}
	w.claimed[addr] = true
	if b.What == "type-pkgpath" && b.Pkg == "" {
		b.Pkg = s
	}
	w.im.blameAddr(levelDetail, addr, size, b)
}

// walkItabs blames the itabs and queues the types they reference.
func (w *typeWalker) walkItabs() {
	im := w.im
	md := w.md
	ps := w.ps
	blameItab := func(a uint64) uint64 {
		typ := w.typeAt(im.uptr(a+ps), nil)
		inter := w.typeAt(im.uptr(a), typ)
		nfun := uint64(1)
		if inter != nil {
			nfun = max(1, im.uptr(inter.addr+w.common+2*ps))
		}
		size := 2*ps + 8 + nfun*ps
		b := Blame{What: "itab"}
		if inter != nil && typ != nil {
			b.Name = fmt.Sprintf("go:itab.%s,%s", typ.str, inter.str)
			b.Pkg = w.pkgOfType(typ, 0)
		}
		im.blameAddr(levelStruct, a, size, b)
		w.itabs = append(w.itabs, addrRange{a, a + size})
		return size
	}
	if md.itabsize != 0 {
		a := md.types + md.itaboffset
		end := a + md.itabsize
		for a < end {
			a = alignUp(a, ps)
			a += blameItab(a)
		}
		return
	}
	for i := uint64(0); i < md.itablinks.len; i++ {
		blameItab(im.uptr(md.itablinks.ptr + i*ps))
	}
}

// scanGaps looks for type descriptors in the parts of the types
// section not covered by any type, name, or itab found so far.
func (w *typeWalker) scanGaps() {
	for pass := 0; pass < 4; pass++ {
		found := 0
		for _, g := range w.gaps() {
			for a := alignUp(g.lo, w.ps); a+w.common <= g.hi; a += w.ps {
				if _, ok := w.types[a]; ok {
					continue
				}
				if t := w.typeAt(a, nil); t != nil {
					found++
					a += alignUp(w.descriptorSize(t), w.ps) - w.ps
				}
			}
		}
		w.drain()
		if found == 0 {
			break
		}
	}
}

// gaps returns the parts of the types section not covered by known
// types, names, or itabs.
func (w *typeWalker) gaps() []addrRange {
	var cov []addrRange
	for _, t := range w.order {
		cov = append(cov, addrRange{t.addr, t.addr + w.descriptorSize(t)})
	}
	for a := range w.names {
		if size, _, ok := w.nameAt(a); ok {
			cov = append(cov, addrRange{a, a + size})
		}
	}
	cov = append(cov, w.itabs...)
	sort.Slice(cov, func(i, j int) bool { return cov[i].lo < cov[j].lo })
	var gaps []addrRange
	pos := w.md.types
	for _, c := range cov {
		if c.lo > pos {
			gaps = append(gaps, addrRange{pos, c.lo})
		}
		pos = max(pos, c.hi)
	}
	if pos < w.md.etypes {
		gaps = append(gaps, addrRange{pos, w.md.etypes})
	}
	return gaps
}

// blameOrphanNames blames names in the types section that no type
// descriptor references (for example, names referenced only by code).
func (w *typeWalker) blameOrphanNames() {
	for _, g := range w.im.unclaimed(w.md.types, w.md.etypes, levelStruct) {
		for a := g.lo; a < g.hi; {
			size, s, ok := w.nameAt(a)
			if !ok || size < 3 || a+size > g.hi || s == "" {
				a++
				continue
			}
			w.im.blameAddr(levelDetail, a, size, Blame{What: "type-name", Name: s})
			a += size
		}
	}
}

func hasControl(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}
