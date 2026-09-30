// Copyright 2020 Brad Fitzpatrick. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"debug/macho"
	"encoding/binary"
	"fmt"
	"log"
	"strings"
)

// Mach-O load commands not defined by debug/macho.
const (
	lcSegment64          = 0x19
	lcDyldInfo           = 0x22
	lcDyldInfoOnly       = 0x80000022
	lcCodeSignature      = 0x1d
	lcFunctionStarts     = 0x26
	lcDataInCode         = 0x29
	lcDyldExportsTrie    = 0x80000033
	lcDyldChainedFixups  = 0x80000034
	lcSegmentSplitInfo   = 0x1e
	lcLinkerOptimization = 0x2e
)

var machoLoadCmdNames = map[uint32]string{
	0x1: "LC_SEGMENT", 0x2: "LC_SYMTAB", 0x5: "LC_UNIXTHREAD", 0xb: "LC_DYSYMTAB",
	0xc: "LC_LOAD_DYLIB", 0xe: "LC_LOAD_DYLINKER", 0x19: "LC_SEGMENT_64", 0x1b: "LC_UUID",
	0x1d: "LC_CODE_SIGNATURE", 0x1e: "LC_SEGMENT_SPLIT_INFO", 0x24: "LC_VERSION_MIN_MACOSX",
	0x25: "LC_VERSION_MIN_IPHONEOS", 0x26: "LC_FUNCTION_STARTS", 0x29: "LC_DATA_IN_CODE",
	0x2a: "LC_SOURCE_VERSION", 0x32: "LC_BUILD_VERSION", 0x80000022: "LC_DYLD_INFO_ONLY",
	0x22: "LC_DYLD_INFO", 0x80000028: "LC_MAIN", 0x80000033: "LC_DYLD_EXPORTS_TRIE",
	0x80000034: "LC_DYLD_CHAINED_FIXUPS", 0x8000001c: "LC_RPATH", 0x2e: "LC_LINKER_OPTIMIZATION_HINT",
}

// machoInfo holds Mach-O details needed after the Go analysis.
type machoInfo struct {
	segAddrs  []uint64 // segment vmaddrs, by load command order
	rebaseOff int64
	rebaseLen int64
	sigOff    int64 // code signature
	sigLen    int64
}

// loadMachO fills in im from a Mach-O file and blames its headers,
// load commands, sections, and link edit data.
func (im *image) loadMachO(f *macho.File) error {
	im.order = f.ByteOrder
	im.ptrSize = 4
	hdrSize := int64(28)
	if f.Magic == macho.Magic64 {
		im.ptrSize = 8
		hdrSize = 32
	}
	switch f.Cpu {
	case macho.CpuAmd64:
		im.arch = "amd64"
	case macho.CpuArm64:
		im.arch = "arm64"
	}
	im.macho = &machoInfo{}
	im.inferredSizes = true
	bm := im.bm
	bm.add(levelSection, 0, hdrSize, Blame{What: "macho-header"})
	im.addSection("(macho-header)", 0, 0, hdrSize)

	// Walk the raw load commands; debug/macho doesn't expose all
	// of them or their offsets.
	d := im.data
	o := f.ByteOrder
	off := hdrSize
	im.addSection("(macho-loadcmds)", 0, off, int64(f.Cmdsz))
	linkedit := func(name string, dataOff, size uint32) {
		if size == 0 {
			return
		}
		im.addSection("__LINKEDIT,"+name, 0, int64(dataOff), int64(size))
		bm.addContainer(levelSection, int64(dataOff), int64(size), Blame{What: name})
	}
	for i := 0; i < int(f.Ncmd) && off+8 <= int64(len(d)); i++ {
		cmd := o.Uint32(d[off:])
		size := int64(o.Uint32(d[off+4:]))
		if size < 8 {
			return fmt.Errorf("bad load command size %d", size)
		}
		name := machoLoadCmdNames[cmd]
		if name == "" {
			name = fmt.Sprintf("LC_%#x", cmd)
		}
		c := d[off : off+size]
		switch cmd {
		case lcSegment64:
			segName := cstr(c[8:24])
			name += " " + segName
			im.macho.segAddrs = append(im.macho.segAddrs, o.Uint64(c[24:]))
		case 0x1:
			im.macho.segAddrs = append(im.macho.segAddrs, uint64(o.Uint32(c[24:])))
		case uint32(macho.LoadCmdSymtab):
			symoff, nsyms, stroff, strsize := o.Uint32(c[8:]), o.Uint32(c[12:]), o.Uint32(c[16:]), o.Uint32(c[20:])
			entSize := uint32(12)
			if im.ptrSize == 8 {
				entSize = 16
			}
			linkedit("symtab", symoff, nsyms*entSize)
			linkedit("strtab", stroff, strsize)
			if err := im.loadMachOSymtab(f, int64(symoff), int(nsyms), int64(entSize), int64(stroff), int64(strsize)); err != nil {
				return err
			}
		case uint32(macho.LoadCmdDysymtab):
			indOff, nind := o.Uint32(c[56:]), o.Uint32(c[60:])
			linkedit("indirectsyms", indOff, nind*4)
			extOff, nExt := o.Uint32(c[64:]), o.Uint32(c[68:])
			linkedit("extrel", extOff, nExt*8)
			locOff, nLoc := o.Uint32(c[72:]), o.Uint32(c[76:])
			linkedit("locrel", locOff, nLoc*8)
		case lcDyldInfo, lcDyldInfoOnly:
			linkedit("rebase", o.Uint32(c[8:]), o.Uint32(c[12:]))
			linkedit("bind", o.Uint32(c[16:]), o.Uint32(c[20:]))
			linkedit("weak_bind", o.Uint32(c[24:]), o.Uint32(c[28:]))
			linkedit("lazy_bind", o.Uint32(c[32:]), o.Uint32(c[36:]))
			linkedit("export", o.Uint32(c[40:]), o.Uint32(c[44:]))
			im.macho.rebaseOff = int64(o.Uint32(c[8:]))
			im.macho.rebaseLen = int64(o.Uint32(c[12:]))
		case lcCodeSignature:
			im.macho.sigOff = int64(o.Uint32(c[8:]))
			im.macho.sigLen = int64(o.Uint32(c[12:]))
			linkedit("code_signature", o.Uint32(c[8:]), o.Uint32(c[12:]))
		case lcFunctionStarts, lcDataInCode, lcDyldExportsTrie, lcDyldChainedFixups, lcSegmentSplitInfo, lcLinkerOptimization:
			n := strings.ToLower(strings.TrimPrefix(name, "LC_"))
			linkedit(n, o.Uint32(c[8:]), o.Uint32(c[12:]))
		}
		bm.add(levelSection, off, size, Blame{What: "macho-loadcmd", Name: name})
		off += size
	}

	for _, s := range f.Sections {
		if s.Flags&0xff == 0x1 || s.Flags&0xff == 0xc || s.Flags&0xff == 0x12 { // S_ZEROFILL, S_GB_ZEROFILL, S_THREAD_LOCAL_ZEROFILL
			continue
		}
		name := s.Seg + "," + s.Name
		if s.Offset != 0 {
			im.addMapping(s.Addr, s.Size, int64(s.Offset))
			im.addSection(name, s.Addr, int64(s.Offset), int64(s.Size))
			bm.addContainer(levelSection, int64(s.Offset), int64(s.Size), Blame{What: machoSectionWhat(s)})
		}
	}
	return nil
}

// machoSectionWhat returns the default What for bytes of section s.
func machoSectionWhat(s *macho.Section) string {
	switch {
	case s.Flags&0x80000000 != 0: // S_ATTR_PURE_INSTRUCTIONS
		return "text"
	case s.Seg == "__DWARF":
		return "dwarf"
	}
	return strings.TrimPrefix(s.Name, "__")
}

func cstr(b []byte) string {
	if i := indexNUL(b); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// loadMachOSymtab reads the symbol table, adding its defined symbols
// to im and blaming the symbol table entries and names. Mach-O
// symbols have no sizes, so each extends to the next symbol in its
// section.
func (im *image) loadMachOSymtab(f *macho.File, symoff int64, nsyms int, entSize, stroff, strsize int64) error {
	d := im.data
	o := f.ByteOrder
	type rawSym struct {
		name  string
		value uint64
		sect  int
	}
	var syms []rawSym
	for i := 0; i < nsyms; i++ {
		e := d[symoff+int64(i)*entSize:]
		strx := int64(o.Uint32(e))
		typ := e[4]
		sect := int(e[5])
		var value uint64
		if entSize == 16 {
			value = o.Uint64(e[8:])
		} else {
			value = uint64(o.Uint32(e[8:]))
		}
		var name string
		if strx > 0 && strx < strsize {
			if j := indexNUL(d[stroff+strx : stroff+strsize]); j >= 0 {
				name = string(d[stroff+strx : stroff+strx+int64(j)])
				im.bm.add(levelSymbol, stroff+strx, int64(j)+1, im.symBlame("strtab", machoSymName(name)))
			}
		}
		im.bm.add(levelSymbol, symoff+int64(i)*entSize, entSize, im.symBlame("symtab", machoSymName(name)))
		if typ&0xe0 != 0 || typ&0x0e != 0x0e || sect == 0 || sect > len(f.Sections) {
			continue // stab, not defined in a section
		}
		syms = append(syms, rawSym{machoSymName(name), value, sect})
	}

	// Compute sizes from the next symbol in the same section.
	bySect := map[int][]int{}
	for i, s := range syms {
		bySect[s.sect] = append(bySect[s.sect], i)
	}
	for sect, idxs := range bySect {
		ms := f.Sections[sect-1]
		zerofill := ms.Flags&0xff == 0x1 || ms.Flags&0xff == 0xc
		text := ms.Flags&0x80000000 != 0
		what := ""
		if !zerofill {
			what = machoSectionWhat(ms)
		}
		sortIdx(idxs, func(i int) uint64 { return syms[i].value })
		end := ms.Addr + ms.Size
		for k, i := range idxs {
			s := syms[i]
			next := end
			for _, j := range idxs[k+1:] {
				if syms[j].value > s.value {
					next = syms[j].value
					break
				}
			}
			size := next - s.value
			if isCarrierSym(s.name) || isMarkerSym(s.name) {
				size = 0 // carriers are computed later; markers are empty
			}
			im.addSymbol(s.name, s.value, size, text, what, end)
		}
	}
	return nil
}

// machoSymName strips the leading underscore Mach-O adds to C symbol
// names. Go symbols on darwin are emitted with it too.
func machoSymName(s string) string {
	return strings.TrimPrefix(s, "_")
}

// blameMachODWARF blames the __DWARF segment's sections.
func (im *image) blameMachODWARF(f *macho.File) {
	sects := map[string]*dwarfSect{}
	for _, s := range f.Sections {
		if s.Seg != "__DWARF" || s.Offset == 0 {
			continue
		}
		off, size := int64(s.Offset), int64(s.Size)
		if name, ok := strings.CutPrefix(s.Name, "__zdebug_"); ok {
			b := im.data[off : off+size]
			if len(b) < 12 || string(b[:4]) != "ZLIB" {
				continue
			}
			usize := int64(binary.BigEndian.Uint64(b[4:]))
			im.bm.add(levelStruct, off, 12, Blame{What: "dwarf-chdr", Name: s.Name})
			ds, err := newZlibDWARFSect(name, im.data, off+12, size-12, usize)
			if err != nil {
				log.Printf("warning: decompressing %s: %v", s.Name, err)
				continue
			}
			sects[name] = ds
		} else if name, ok := strings.CutPrefix(s.Name, "__debug_"); ok {
			sects[name] = &dwarfSect{name: name, data: im.data[off : off+size], fileOff: off, fileSize: size}
		}
	}
	im.blameDWARF(sects)
}

// blameMachOFixups decodes the dyld rebase opcodes, recording each
// rebased pointer as a fixup and blaming the opcode bytes to the owner
// of the first pointer each opcode rebases.
func (im *image) blameMachOFixups(f *macho.File, lookup func(uint64) Blame) {
	mi := im.macho
	if mi == nil {
		return
	}
	im.blameCodeSignature()
	if mi.rebaseLen == 0 {
		return
	}
	ps := uint64(im.ptrSize)
	d := im.data[mi.rebaseOff : mi.rebaseOff+mi.rebaseLen]
	var addr uint64
	pending := 0 // start of opcodes not yet blamed
	for i := 0; i < len(d); {
		op, imm := d[i]&0xf0, uint64(d[i]&0x0f)
		i++
		uleb := func() uint64 {
			v, n := binary.Uvarint(d[i:])
			if n <= 0 {
				i = len(d)
				return 0
			}
			i += n
			return v
		}
		var first uint64
		var nfix int
		rebase := func() {
			if nfix == 0 {
				first = addr
			}
			nfix++
			im.fixups = append(im.fixups, addr)
		}
		switch op {
		case 0x00: // DONE
			i = len(d)
		case 0x10: // SET_TYPE_IMM
		case 0x20: // SET_SEGMENT_AND_OFFSET_ULEB
			off := uleb()
			if int(imm) < len(mi.segAddrs) {
				addr = mi.segAddrs[imm] + off
			}
		case 0x30: // ADD_ADDR_ULEB
			addr += uleb()
		case 0x40: // ADD_ADDR_IMM_SCALED
			addr += imm * ps
		case 0x50: // DO_REBASE_IMM_TIMES
			for n := imm; n > 0; n-- {
				rebase()
				addr += ps
			}
		case 0x60: // DO_REBASE_ULEB_TIMES
			for n := uleb(); n > 0; n-- {
				rebase()
				addr += ps
			}
		case 0x70: // DO_REBASE_ADD_ADDR_ULEB
			rebase()
			addr += uleb() + ps
		case 0x80: // DO_REBASE_ULEB_TIMES_SKIPPING_ULEB
			n, skip := uleb(), uleb()
			for ; n > 0; n-- {
				rebase()
				addr += skip + ps
			}
		default:
			log.Printf("warning: unknown rebase opcode %#x", op)
			i = len(d)
		}
		// Opcodes that only set up state are blamed along with the
		// next opcode that rebases something.
		if nfix > 0 || i == len(d) {
			b := Blame{What: "rebase"}
			if nfix > 0 {
				b = lookup(first)
				b.What = "rebase"
			}
			im.bm.add(levelStruct, mi.rebaseOff+int64(pending), int64(i-pending), b)
			pending = i
		}
	}
}

// isMarkerSym reports whether name is a linker-defined symbol marking
// the start or end of a region, rather than data of its own.
func isMarkerSym(name string) bool {
	switch name {
	case "runtime.text", "runtime.etext", "runtime.rodata", "runtime.erodata",
		"runtime.types", "runtime.etypes", "runtime.noptrdata", "runtime.enoptrdata",
		"runtime.data", "runtime.edata", "runtime.bss", "runtime.ebss",
		"runtime.noptrbss", "runtime.enoptrbss", "runtime.end", "runtime.epclntab",
		"runtime.covctrs", "runtime.ecovctrs", "runtime.egcdata", "runtime.egcbss",
		"runtime.itablink", "runtime.eitablink", "runtime.typelink", "runtime.etypelink",
		"go:buildid", "runtime.gcdata", "runtime.gcbss":
		return true
	}
	return false
}

// blameCodeSignature blames each page hash in the code signature's
// code directories to the owner of the start of the page it covers.
// See the SuperBlob and CodeDirectory structures in Apple's
// cs_blobs.h; all fields are big-endian.
func (im *image) blameCodeSignature() {
	mi := im.macho
	if mi.sigLen < 12 || mi.sigOff+mi.sigLen > int64(len(im.data)) {
		return
	}
	be := binary.BigEndian
	sig := im.data[mi.sigOff : mi.sigOff+mi.sigLen]
	if be.Uint32(sig) != 0xfade0cc0 { // CSMAGIC_EMBEDDED_SIGNATURE
		return
	}
	var segs []Segment // resolved lazily, once
	blameOfOff := func(off int64) Blame {
		if segs == nil {
			segs = im.bm.resolve()
		}
		i := sortSearchSegs(segs, off)
		if i < len(segs) {
			return segs[i].Blame
		}
		return Blame{}
	}
	count := int(be.Uint32(sig[8:]))
	for i := 0; i < count && 12+8*i+8 <= len(sig); i++ {
		boff := int64(be.Uint32(sig[12+8*i+4:]))
		if boff+44 > int64(len(sig)) || be.Uint32(sig[boff:]) != 0xfade0c02 { // CSMAGIC_CODEDIRECTORY
			continue
		}
		cd := sig[boff:]
		hashOff := int64(be.Uint32(cd[16:]))
		nCode := int64(be.Uint32(cd[28:]))
		hashSize := int64(cd[36])
		pageShift := cd[39]
		if pageShift == 0 || hashSize == 0 {
			continue
		}
		for p := int64(0); p < nCode; p++ {
			off := mi.sigOff + boff + hashOff + p*hashSize
			if off+hashSize > mi.sigOff+mi.sigLen {
				break
			}
			b := blameOfOff(p << pageShift)
			b.What = "code_signature"
			im.bm.add(levelStruct, off, hashSize, b)
		}
	}
}
