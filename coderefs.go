// Copyright 2020 Brad Fitzpatrick. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import "sort"

// refIndex records, for data addresses referenced by code or by
// pointers in data, who first referenced them. It's used to blame
// data that has no symbol of its own (string literals, compiler
// generated statics, closure types) on the code that uses it.
type refIndex struct {
	by      map[uint64]Blame
	targets []uint64 // sorted keys of by

	// pending are pointers in data from bytes without a symbol, keyed
	// by target address. Once the pointing bytes are blamed (by
	// reference), their blame propagates to the target.
	pending map[uint64]uint64 // target -> address of pointer
}

// referrer returns the blame for the first referrer of addr.
func (r *refIndex) referrer(addr uint64) (Blame, bool) {
	if r == nil {
		return Blame{}, false
	}
	b, ok := r.by[addr]
	return b, ok
}

// targetsIn returns the sorted referenced addresses in [lo, hi).
func (r *refIndex) targetsIn(lo, hi uint64) []uint64 {
	if r == nil {
		return nil
	}
	i := sort.Search(len(r.targets), func(i int) bool { return r.targets[i] >= lo })
	j := sort.Search(len(r.targets), func(i int) bool { return r.targets[i] >= hi })
	return r.targets[i:j]
}

// buildRefIndex scans the code of every func, and the pointer-sized
// words of data sections, for references to non-text addresses.
func (im *image) buildRefIndex(arch string) *refIndex {
	r := &refIndex{by: map[uint64]Blame{}, pending: map[uint64]uint64{}}
	t := im.pcln
	if t == nil || t.md == nil {
		return r
	}
	md := t.md
	isData := func(a uint64) bool {
		if a >= md.text && a < md.etext {
			return false
		}
		_, ok := im.addrOff(a)
		return ok
	}
	add := func(a uint64, b Blame) {
		if _, ok := r.by[a]; !ok && isData(a) {
			r.by[a] = b
		}
	}

	for _, f := range t.funcs {
		code := im.bytesAt(f.entry, int(f.end-f.entry))
		if code == nil {
			continue
		}
		b := Blame{Name: f.name, Pkg: f.pkg}
		switch arch {
		case "amd64":
			scanAMD64(code, f.entry, func(a uint64) { add(a, b) })
		case "arm64":
			scanARM64(code, f.entry, im.order.Uint32, func(a uint64) { add(a, b) })
		}
	}

	// Pointers in data, such as string headers in composite
	// literals and static tables.
	ps := uint64(im.ptrSize)
	for _, rg := range [][2]uint64{{md.noptrdata, md.enoptrdata}, {md.data, md.edata}} {
		for a := rg[0]; a+ps <= rg[1]; a += ps {
			v := im.uptr(a)
			if v == 0 || !isData(v) {
				continue
			}
			if _, ok := r.by[v]; ok {
				continue
			}
			if s := im.symAt(a); s != nil {
				add(v, im.symBlame("", s.name))
			} else if _, ok := r.pending[v]; !ok {
				r.pending[v] = a
			}
		}
	}
	r.sortTargets()
	return r
}

func (r *refIndex) sortTargets() {
	r.targets = r.targets[:0]
	for a := range r.by {
		r.targets = append(r.targets, a)
	}
	sort.Slice(r.targets, func(i, j int) bool { return r.targets[i] < r.targets[j] })
}

// resolvePending gives pending pointer targets the blame of the bytes
// pointing to them, using the current blame. It reports whether any
// new referrers were found.
func (im *image) resolvePending(r *refIndex) bool {
	if len(r.pending) == 0 {
		return false
	}
	blameOf := im.addrBlamer()
	added := false
	for v, a := range r.pending {
		if _, ok := r.by[v]; ok {
			delete(r.pending, v)
			continue
		}
		b := blameOf(a)
		if b.Name == "" && b.Pkg == "" {
			continue
		}
		b.What = ""
		r.by[v] = b
		delete(r.pending, v)
		added = true
	}
	if added {
		r.sortTargets()
	}
	return added
}

// scanAMD64 calls fn with the target of each RIP-relative LEA, MOV,
// or MOVUPS in code, which starts at address pc. It doesn't fully
// decode instructions, so it can find false positives, but those
// are rare and filtered to plausible data addresses by the caller.
func scanAMD64(code []byte, pc uint64, fn func(uint64)) {
	for i := 0; i+6 <= len(code); i++ {
		j := i
		if c := code[j]; c >= 0x40 && c <= 0x4f { // REX
			j++
		}
		var modrm int
		switch {
		case code[j] == 0x8d || code[j] == 0x8b || code[j] == 0x89:
			modrm = j + 1
		case code[j] == 0x0f && j+1 < len(code) && (code[j+1] == 0x10 || code[j+1] == 0x11):
			modrm = j + 2
		default:
			continue
		}
		if modrm+5 > len(code) || code[modrm]&0xc7 != 0x05 {
			continue
		}
		d := code[modrm+1:]
		disp := int32(uint32(d[0]) | uint32(d[1])<<8 | uint32(d[2])<<16 | uint32(d[3])<<24)
		next := pc + uint64(modrm+5)
		fn(uint64(int64(next) + int64(disp)))
	}
}

// scanARM64 calls fn with the target of each ADRP followed by an ADD
// or load/store using the same register.
func scanARM64(code []byte, pc uint64, u32 func([]byte) uint32, fn func(uint64)) {
	for i := 0; i+8 <= len(code); i += 4 {
		ins := u32(code[i:])
		if ins&0x9f000000 != 0x90000000 { // ADRP
			continue
		}
		rd := ins & 0x1f
		immlo := uint64(ins>>29) & 3
		immhi := uint64(ins>>5) & 0x7ffff
		imm := int64((immhi<<2|immlo)<<43) >> 31 // sign extend 21 bits, then << 12
		page := uint64(int64((pc+uint64(i))&^0xfff) + imm)

		next := u32(code[i+4:])
		rn := (next >> 5) & 0x1f
		if rn != rd {
			continue
		}
		switch {
		case next&0xff800000 == 0x91000000: // ADD (immediate), 64-bit
			imm12 := uint64(next>>10) & 0xfff
			if next&(1<<22) != 0 {
				imm12 <<= 12
			}
			fn(page + imm12)
		case next&0x3b000000 == 0x39000000: // LDR/STR (unsigned immediate)
			size := next >> 30
			if next&(1<<26) != 0 && next&(1<<23) != 0 { // 128-bit SIMD
				size = 4
			}
			fn(page + (uint64(next>>10)&0xfff)<<size)
		}
	}
}

// blameByRefs blames the unclaimed parts of [lo, hi) to the code or
// data that references them. Each referenced address claims the bytes
// up to the next referenced address or the end of its gap.
func (im *image) blameByRefs(r *refIndex, lo, hi uint64, what string) {
	for _, g := range im.unclaimed(lo, hi, levelSymbol) {
		targets := r.targetsIn(g.lo, g.hi)
		for i, a := range targets {
			end := g.hi
			if i+1 < len(targets) {
				end = targets[i+1]
			}
			b, _ := r.referrer(a)
			b.What = what
			im.blameAddr(levelSymbol, a, end-a, b)
		}
	}
}
