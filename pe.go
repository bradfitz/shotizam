// Copyright 2020 Brad Fitzpatrick. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"debug/pe"
	"encoding/binary"
	"log"
	"strings"
)

// loadPE fills in im from a PE file and blames its headers, sections,
// and COFF symbol table.
func (im *image) loadPE(f *pe.File) error {
	im.order = binary.LittleEndian
	im.inferredSizes = true
	var imageBase uint64
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		im.ptrSize = 8
		imageBase = oh.ImageBase
	case *pe.OptionalHeader32:
		im.ptrSize = 4
		imageBase = uint64(oh.ImageBase)
	default:
		im.ptrSize = 8
	}
	switch f.Machine {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		im.arch = "amd64"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		im.arch = "arm64"
	case pe.IMAGE_FILE_MACHINE_I386:
		im.arch = "386"
	}

	d := im.data
	bm := im.bm
	lfanew := int64(binary.LittleEndian.Uint32(d[0x3c:]))
	bm.add(levelSection, 0, lfanew, Blame{What: "dos-header"})
	im.addSection("(dos-header)", 0, 0, lfanew)
	coff := lfanew + 4
	bm.add(levelSection, lfanew, 4+20, Blame{What: "pe-header"})
	optOff := coff + 20
	bm.add(levelSection, optOff, int64(f.SizeOfOptionalHeader), Blame{What: "pe-optional-header"})
	shOff := optOff + int64(f.SizeOfOptionalHeader)
	im.addSection("(pe-headers)", 0, lfanew, shOff+int64(len(f.Sections))*40-lfanew)
	for i, s := range f.Sections {
		bm.add(levelSection, shOff+int64(i)*40, 40, Blame{What: "pe-shdr", Name: s.Name})
	}

	for _, s := range f.Sections {
		if s.Size == 0 || s.Offset == 0 {
			continue
		}
		addr := imageBase + uint64(s.VirtualAddress)
		im.addMapping(addr, uint64(peDataSize(s)), int64(s.Offset))
		// The raw size is rounded up to the file alignment;
		// the rounding is reported as padding.
		im.addSection(s.Name, addr, int64(s.Offset), int64(s.Size))
		bm.addContainer(levelSection, int64(s.Offset), int64(s.Size), Blame{What: peSectionWhat(s)})
	}

	// COFF symbol table and string table.
	if f.PointerToSymbolTable != 0 && f.NumberOfSymbols != 0 {
		symOff := int64(f.PointerToSymbolTable)
		symSize := int64(f.NumberOfSymbols) * 18
		im.addSection("(coff-symtab)", 0, symOff, symSize)
		strOff := symOff + symSize
		if strOff+4 <= int64(len(d)) {
			strSize := int64(binary.LittleEndian.Uint32(d[strOff:]))
			im.addSection("(coff-strtab)", 0, strOff, strSize)
			bm.add(levelSection, strOff, strSize, Blame{What: "strtab"})
		}
		type rawSym struct {
			name string
			addr uint64
			sect int
		}
		var syms []rawSym
		for i := int64(0); i < int64(f.NumberOfSymbols); i++ {
			e := d[symOff+i*18 : symOff+i*18+18]
			var name string
			if binary.LittleEndian.Uint32(e) == 0 {
				so := strOff + int64(binary.LittleEndian.Uint32(e[4:]))
				if so < int64(len(d)) {
					if j := indexNUL(d[so:]); j >= 0 {
						name = string(d[so : so+int64(j)])
						bm.add(levelSymbol, so, int64(j)+1, im.symBlame("strtab", name))
					}
				}
			} else {
				name = cstr(e[:8])
			}
			bm.add(levelSymbol, symOff+i*18, 18, im.symBlame("symtab", name))
			sect := int(int16(binary.LittleEndian.Uint16(e[12:])))
			naux := int64(e[17])
			for j := int64(1); j <= naux; j++ {
				bm.add(levelSymbol, symOff+(i+j)*18, 18, im.symBlame("symtab", name))
			}
			i += naux
			if sect <= 0 || sect > len(f.Sections) {
				continue
			}
			s := f.Sections[sect-1]
			syms = append(syms, rawSym{name, imageBase + uint64(s.VirtualAddress) + uint64(binary.LittleEndian.Uint32(e[8:])), sect})
		}
		bySect := map[int][]int{}
		for i, s := range syms {
			bySect[s.sect] = append(bySect[s.sect], i)
		}
		for sect, idxs := range bySect {
			s := f.Sections[sect-1]
			sortIdx(idxs, func(i int) uint64 { return syms[i].addr })
			end := imageBase + uint64(s.VirtualAddress) + uint64(peDataSize(s))
			text := s.Characteristics&pe.IMAGE_SCN_CNT_CODE != 0
			for k, i := range idxs {
				sy := syms[i]
				next := end
				for _, j := range idxs[k+1:] {
					if syms[j].addr > sy.addr {
						next = syms[j].addr
						break
					}
				}
				size := next - sy.addr
				if isCarrierSym(sy.name) || isMarkerSym(sy.name) {
					size = 0
				}
				im.addSymbol(sy.name, sy.addr, size, text, peSectionWhat(s), end)
			}
		}
	}
	return nil
}

// peDataSize returns the size of the meaningful data in section s,
// excluding the rounding of its raw size to the file alignment.
func peDataSize(s *pe.Section) uint32 {
	if s.VirtualSize == 0 {
		return s.Size
	}
	return min(s.Size, s.VirtualSize)
}

func peSectionWhat(s *pe.Section) string {
	switch {
	case s.Characteristics&pe.IMAGE_SCN_CNT_CODE != 0:
		return "text"
	case strings.HasPrefix(s.Name, ".debug_") || strings.HasPrefix(s.Name, ".zdebug_"):
		return "dwarf"
	}
	return strings.TrimPrefix(s.Name, ".")
}

// blamePEDWARF blames the DWARF sections of a PE file.
func (im *image) blamePEDWARF(f *pe.File) {
	sects := map[string]*dwarfSect{}
	for _, s := range f.Sections {
		off, size := int64(s.Offset), int64(peDataSize(s))
		if off == 0 || size == 0 {
			continue
		}
		if name, ok := strings.CutPrefix(s.Name, ".zdebug_"); ok {
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
		} else if name, ok := strings.CutPrefix(s.Name, ".debug_"); ok {
			sects[name] = &dwarfSect{name: name, data: im.data[off : off+size], fileOff: off, fileSize: size}
		}
	}
	im.blameDWARF(sects)
}

// blamePERelocs blames the base relocation blocks in .reloc, recording
// each relocated pointer as a fixup.
func (im *image) blamePERelocs(f *pe.File, lookup func(uint64) Blame) {
	var imageBase uint64
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		imageBase = oh.ImageBase
	case *pe.OptionalHeader32:
		imageBase = uint64(oh.ImageBase)
	}
	im.blamePEPdata(f, imageBase)
	s := f.Section(".reloc")
	if s == nil || s.Offset == 0 {
		return
	}
	d := im.data[s.Offset : int64(s.Offset)+int64(peDataSize(s))]
	for off := 0; off+8 <= len(d); {
		page := imageBase + uint64(binary.LittleEndian.Uint32(d[off:]))
		n := int(binary.LittleEndian.Uint32(d[off+4:]))
		if n < 8 || off+n > len(d) {
			break
		}
		b := Blame{What: "reloc"}
		first := true
		for i := off + 8; i+2 <= off+n; i += 2 {
			e := binary.LittleEndian.Uint16(d[i:])
			if e>>12 == 0 { // IMAGE_REL_BASED_ABSOLUTE padding
				continue
			}
			a := page + uint64(e&0xfff)
			im.fixups = append(im.fixups, a)
			if first {
				b = lookup(a)
				b.What = "reloc"
				first = false
			}
		}
		im.bm.add(levelStruct, int64(s.Offset)+int64(off), int64(n), b)
		off += n
	}
}

// blamePEPdata blames each RUNTIME_FUNCTION entry in .pdata (the
// exception unwind table) to the func it describes.
func (im *image) blamePEPdata(f *pe.File, imageBase uint64) {
	s := f.Section(".pdata")
	if s == nil || s.Offset == 0 || im.arch != "amd64" {
		return
	}
	n := int64(peDataSize(s)) / 12
	for i := int64(0); i < n; i++ {
		off := int64(s.Offset) + i*12
		pc := imageBase + uint64(binary.LittleEndian.Uint32(im.data[off:]))
		b := Blame{What: "pdata"}
		if fn := im.funcContaining(pc); fn != nil {
			b = fn.blame("pdata")
		} else if sym := im.symAt(pc); sym != nil {
			b = im.symBlame("pdata", sym.name)
		}
		im.bm.add(levelStruct, off, 12, b)
	}
}
