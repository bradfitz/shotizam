// Copyright 2020 Brad Fitzpatrick. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"sort"
)

// moduleData holds the parts of the runtime's moduledata struct that
// shotizam uses. See runtime/symtab.go.
type moduleData struct {
	addr, size uint64 // of the moduledata struct itself

	pcHeader    uint64
	funcnametab sliceHeader
	cutab       sliceHeader
	filetab     sliceHeader
	pctab       sliceHeader
	pclntable   sliceHeader
	ftab        sliceHeader
	findfunctab uint64
	minpc       uint64
	maxpc       uint64
	text, etext uint64

	noptrdata, enoptrdata uint64
	data, edata           uint64

	types, etypes        uint64
	typedesclen          uint64 // Go 1.27+
	itaboffset, itabsize uint64 // Go 1.27+
	typelinks, itablinks sliceHeader
	rodata, gofunc       uint64
	epclntab             uint64 // Go 1.26+
}

type sliceHeader struct {
	ptr, len uint64
}

// Magic numbers at the start of pcHeader.
const (
	pclnMagic118 = 0xfffffff0
	pclnMagic120 = 0xfffffff1
)

// findModuleData locates and parses the first moduledata.
func (im *image) findModuleData() (*moduleData, error) {
	if s := im.lookup("runtime.firstmoduledata"); s != nil {
		md := im.parseModuleData(s.addr)
		if md == nil {
			return nil, errors.New("runtime.firstmoduledata doesn't look valid")
		}
		md.size = s.size
		return md, nil
	}

	// No symbols. Find the pcHeader and then look for a
	// moduledata pointing to it.
	hdr, ok := im.findPCHeader()
	if !ok {
		return nil, errors.New("no pclntab found")
	}
	ps := uint64(im.ptrSize)
	for _, m := range im.maps {
		b := im.data[m.off : m.off+int64(m.size)]
		for i := 0; i+im.ptrSize <= len(b); i += im.ptrSize {
			var v uint64
			if im.ptrSize == 8 {
				v = im.order.Uint64(b[i:])
			} else {
				v = uint64(im.order.Uint32(b[i:]))
			}
			if v != hdr {
				continue
			}
			if md := im.parseModuleData(m.addr + uint64(i)); md != nil {
				md.size = im.moduleDataSize() * ps
				return md, nil
			}
		}
	}
	return nil, errors.New("no moduledata found")
}

// moduleDataSize returns the approximate size of moduledata in words.
func (im *image) moduleDataSize() uint64 {
	if im.atLeast(27) {
		return 71
	}
	return 69
}

// findPCHeader returns the address of the pcHeader.
func (im *image) findPCHeader() (uint64, bool) {
	for _, name := range []string{"runtime.pcheader", "runtime.pclntab"} {
		if s := im.lookup(name); s != nil && im.validPCHeader(s.addr) {
			return s.addr, true
		}
	}
	for _, s := range im.sects {
		switch s.name {
		case ".gopclntab", ".data.rel.ro.gopclntab", "__TEXT,__gopclntab", "__DATA_CONST,__gopclntab":
			if im.validPCHeader(s.addr) {
				return s.addr, true
			}
		}
	}
	// Scan for the magic number.
	for _, m := range im.maps {
		for a := m.addr; a+16 <= m.addr+m.size; a += 8 {
			if im.validPCHeader(a) {
				return a, true
			}
		}
	}
	return 0, false
}

func (im *image) validPCHeader(addr uint64) bool {
	b := im.bytesAt(addr, 8)
	if b == nil {
		return false
	}
	magic := im.order.Uint32(b)
	if magic != pclnMagic118 && magic != pclnMagic120 {
		return false
	}
	return b[4] == 0 && b[5] == 0 && (b[6] == 1 || b[6] == 2 || b[6] == 4) && int(b[7]) == im.ptrSize
}

func (im *image) parseModuleData(addr uint64) *moduleData {
	ps := uint64(im.ptrSize)
	w := addr
	word := func() uint64 {
		v := im.uptr(w)
		w += ps
		return v
	}
	slice := func() sliceHeader {
		s := sliceHeader{ptr: word(), len: word()}
		word() // cap
		return s
	}
	md := &moduleData{addr: addr}
	md.pcHeader = word()
	if !im.validPCHeader(md.pcHeader) {
		return nil
	}
	md.funcnametab = slice()
	md.cutab = slice()
	md.filetab = slice()
	md.pctab = slice()
	md.pclntable = slice()
	md.ftab = slice()
	md.findfunctab = word()
	md.minpc = word()
	md.maxpc = word()
	md.text = word()
	md.etext = word()
	md.noptrdata = word()
	md.enoptrdata = word()
	md.data = word()
	md.edata = word()
	word() // bss
	word() // ebss
	word() // noptrbss
	word() // enoptrbss
	word() // covctrs
	word() // ecovctrs
	word() // end
	word() // gcdata
	word() // gcbss
	md.types = word()
	if im.atLeast(27) {
		md.typedesclen = word()
		md.etypes = word()
		md.itaboffset = word()
		md.itabsize = word()
		md.rodata = word()
		md.gofunc = word()
		md.epclntab = word()
		slice() // textsectmap
	} else {
		md.etypes = word()
		md.rodata = word()
		md.gofunc = word()
		if im.atLeast(26) {
			md.epclntab = word()
		}
		slice() // textsectmap
		md.typelinks = slice()
		md.itablinks = slice()
	}
	if md.text > md.etext || md.types > md.etypes {
		return nil
	}
	return md
}

// nextAddrAfter returns the smallest of addrs that's greater than a,
// or def if none are.
func nextAddrAfter(a, def uint64, addrs ...uint64) uint64 {
	sort.Slice(addrs, func(i, j int) bool { return addrs[i] < addrs[j] })
	for _, x := range addrs {
		if x > a {
			return x
		}
	}
	return def
}
