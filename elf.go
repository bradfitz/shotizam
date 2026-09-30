// Copyright 2020 Brad Fitzpatrick. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"debug/elf"
	"fmt"
	"strings"
)

// loadELF fills in im from an ELF file and blames its headers,
// sections, and symbol tables.
func (im *image) loadELF(f *elf.File) error {
	im.order = f.ByteOrder
	switch f.Machine {
	case elf.EM_X86_64:
		im.arch = "amd64"
	case elf.EM_AARCH64:
		im.arch = "arm64"
	}
	im.ptrSize = 4
	ehdrSize, phentSize, shentSize, symSize := int64(52), int64(32), int64(40), int64(16)
	if f.Class == elf.ELFCLASS64 {
		im.ptrSize = 8
		ehdrSize, phentSize, shentSize, symSize = 64, 56, 64, 24
	}

	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD {
			im.addMapping(p.Vaddr, p.Filesz, int64(p.Off))
		}
	}

	bm := im.bm
	bm.add(levelSection, 0, ehdrSize, Blame{What: "elf-header"})
	im.addSection("(elf-header)", 0, 0, ehdrSize)

	// The ELF header tells us where the program and section
	// headers are, but debug/elf doesn't expose those offsets, so
	// read them from the raw header.
	var phoff, shoff int64
	var phnum, shnum int
	d := im.data
	if f.Class == elf.ELFCLASS64 {
		phoff = int64(f.ByteOrder.Uint64(d[32:]))
		shoff = int64(f.ByteOrder.Uint64(d[40:]))
		phnum = int(f.ByteOrder.Uint16(d[56:]))
		shnum = int(f.ByteOrder.Uint16(d[60:]))
	} else {
		phoff = int64(f.ByteOrder.Uint32(d[28:]))
		shoff = int64(f.ByteOrder.Uint32(d[32:]))
		phnum = int(f.ByteOrder.Uint16(d[44:]))
		shnum = int(f.ByteOrder.Uint16(d[48:]))
	}
	for i, p := range f.Progs {
		bm.add(levelSection, phoff+int64(i)*phentSize, phentSize, Blame{What: "elf-phdr", Name: p.Type.String()})
	}
	im.addSection("(elf-phdrs)", 0, phoff, int64(phnum)*phentSize)
	for i := 0; i < shnum && i < len(f.Sections); i++ {
		bm.add(levelSection, shoff+int64(i)*shentSize, shentSize, Blame{What: "elf-shdr", Name: f.Sections[i].Name})
	}
	im.addSection("(elf-shdrs)", 0, shoff, int64(shnum)*shentSize)

	for _, s := range f.Sections {
		if s.Type == elf.SHT_NOBITS || s.Type == elf.SHT_NULL || s.FileSize == 0 {
			continue
		}
		off, size := int64(s.Offset), int64(s.FileSize)
		im.addSection(s.Name, s.Addr, off, size)
		bm.addContainer(levelSection, off, size, Blame{What: elfSectionWhat(s)})
	}

	for _, s := range f.Sections {
		switch s.Type {
		case elf.SHT_SYMTAB, elf.SHT_DYNSYM:
			if err := im.loadELFSymtab(f, s, symSize); err != nil {
				return err
			}
		}
	}
	for _, s := range f.Sections {
		switch s.Name {
		case ".shstrtab":
			im.blameStrtab(int64(s.Offset), int64(s.FileSize), "shstrtab")
		case ".dynstr":
			im.blameStrtab(int64(s.Offset), int64(s.FileSize), "dynstr")
		}
	}
	return nil
}

// elfSectionWhat returns the default What for bytes of section s.
func elfSectionWhat(s *elf.Section) string {
	switch {
	case s.Flags&elf.SHF_EXECINSTR != 0:
		return "text"
	case strings.HasPrefix(s.Name, ".debug_") || strings.HasPrefix(s.Name, ".zdebug_"):
		return "dwarf"
	case s.Type == elf.SHT_RELA || s.Type == elf.SHT_REL:
		return "reloc"
	}
	return strings.TrimPrefix(s.Name, ".")
}

// loadELFSymtab reads the symbol table section s, adding its symbols
// to im and blaming both the symbols' bytes and the symbol table
// entries themselves.
func (im *image) loadELFSymtab(f *elf.File, s *elf.Section, entSize int64) error {
	if int(s.Link) >= len(f.Sections) {
		return fmt.Errorf("bad symtab link %d", s.Link)
	}
	strs := f.Sections[s.Link]
	strOff, strSize := int64(strs.Offset), int64(strs.FileSize)
	d := im.data
	dynamic := s.Type == elf.SHT_DYNSYM
	what, strWhat := "symtab", "strtab"
	if dynamic {
		what, strWhat = "dynsym", "dynstr"
	}

	n := int64(s.FileSize) / entSize
	for i := int64(0); i < n; i++ {
		eoff := int64(s.Offset) + i*entSize
		e := d[eoff : eoff+entSize]
		var nameOff uint32
		var value, size uint64
		var info uint8
		var shndx elf.SectionIndex
		if entSize == 24 {
			nameOff = f.ByteOrder.Uint32(e[0:])
			info = e[4]
			shndx = elf.SectionIndex(f.ByteOrder.Uint16(e[6:]))
			value = f.ByteOrder.Uint64(e[8:])
			size = f.ByteOrder.Uint64(e[16:])
		} else {
			nameOff = f.ByteOrder.Uint32(e[0:])
			value = uint64(f.ByteOrder.Uint32(e[4:]))
			size = uint64(f.ByteOrder.Uint32(e[8:]))
			info = e[12]
			shndx = elf.SectionIndex(f.ByteOrder.Uint16(e[14:]))
		}
		if i == 0 {
			im.bm.add(levelSymbol, eoff, entSize, Blame{What: what, Name: "(null)"})
			continue
		}
		var name string
		if int64(nameOff) < strSize {
			if j := indexNUL(d[strOff+int64(nameOff) : strOff+strSize]); j >= 0 {
				name = string(d[strOff+int64(nameOff) : strOff+int64(nameOff)+int64(j)])
				im.bm.add(levelSymbol, strOff+int64(nameOff), int64(j)+1, im.symBlame(strWhat, name))
			}
		}
		im.bm.add(levelSymbol, eoff, entSize, im.symBlame(what, name))

		if dynamic {
			continue
		}
		typ := elf.SymType(info & 0xf)
		if typ == elf.STT_SECTION || typ == elf.STT_FILE || shndx == elf.SHN_UNDEF || shndx >= elf.SHN_LORESERVE {
			continue
		}
		if int(shndx) >= len(f.Sections) {
			continue
		}
		sect := f.Sections[shndx]
		what := ""
		if sect.Type != elf.SHT_NOBITS && sect.Flags&elf.SHF_ALLOC != 0 {
			what = elfSectionWhat(sect)
		}
		im.addSymbol(name, value, size, sect.Flags&elf.SHF_EXECINSTR != 0, what, sect.Addr+sect.Size)
	}
	return nil
}

// isCarrierSym reports whether name is a linker "carrier" symbol that
// covers many other symbols not present in the symbol table.
func isCarrierSym(name string) bool {
	switch name {
	case "type:*", "go:string.*", "go:funcdesc", "runtime.gcbits.*", "runtime.gcmask.*",
		"runtime.pclntab", "go:func.*", "runtime.itablink", "runtime.typelink":
		return true
	}
	return false
}

// blameStrtab blames each NUL-terminated string in a string table that
// isn't otherwise claimed.
func (im *image) blameStrtab(off, size int64, what string) {
	d := im.data[off : off+size]
	for i := 0; i < len(d); {
		j := indexNUL(d[i:])
		if j < 0 {
			j = len(d) - i - 1
		}
		im.bm.add(levelSymbol-1, off+int64(i), int64(j)+1, Blame{What: what, Name: string(d[i : i+j])})
		i += j + 1
	}
}

func indexNUL(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return -1
}

// blameELFRelocs blames dynamic relocation entries to the symbol
// they relocate. It must run after the Go analysis so that addresses
// can be resolved to names.
func (im *image) blameELFRelocs(f *elf.File, lookup func(addr uint64) Blame) {
	for _, s := range f.Sections {
		var entSize int64
		switch {
		case s.Type == elf.SHT_RELA && f.Class == elf.ELFCLASS64:
			entSize = 24
		case s.Type == elf.SHT_RELA:
			entSize = 12
		case s.Type == elf.SHT_REL && f.Class == elf.ELFCLASS64:
			entSize = 16
		case s.Type == elf.SHT_REL:
			entSize = 8
		default:
			continue
		}
		if s.Flags&elf.SHF_ALLOC == 0 {
			// Relocations for relocatable objects; not handled yet.
			continue
		}
		n := int64(s.FileSize) / entSize
		for i := int64(0); i < n; i++ {
			eoff := int64(s.Offset) + i*entSize
			var addr, info uint64
			if f.Class == elf.ELFCLASS64 {
				addr = f.ByteOrder.Uint64(im.data[eoff:])
				info = f.ByteOrder.Uint64(im.data[eoff+8:])
			} else {
				addr = uint64(f.ByteOrder.Uint32(im.data[eoff:]))
				info = uint64(f.ByteOrder.Uint32(im.data[eoff+4:]))
			}
			if isRelativeReloc(f.Machine, info) {
				im.fixups = append(im.fixups, addr)
			}
			b := lookup(addr)
			b.What = "reloc"
			im.bm.add(levelStruct, eoff, entSize, b)
		}
	}
}

// isRelativeReloc reports whether a dynamic relocation with the given
// r_info adjusts a pointer by the load address, as in PIE binaries.
func isRelativeReloc(m elf.Machine, info uint64) bool {
	switch m {
	case elf.EM_X86_64:
		return elf.R_X86_64(info&0xffffffff) == elf.R_X86_64_RELATIVE
	case elf.EM_AARCH64:
		return elf.R_AARCH64(info&0xffffffff) == elf.R_AARCH64_RELATIVE
	case elf.EM_386:
		return elf.R_386(info&0xff) == elf.R_386_RELATIVE
	case elf.EM_ARM:
		return elf.R_ARM(info&0xff) == elf.R_ARM_RELATIVE
	}
	return false
}
