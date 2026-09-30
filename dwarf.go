// Copyright 2020 Brad Fitzpatrick. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"compress/zlib"
	"debug/dwarf"
	"debug/elf"
	"io"
	"log"
	"sort"
	"strings"
)

// dwarfSect is a DWARF section, decompressed if needed, along with
// a mapping from offsets in its decompressed data back to the file.
type dwarfSect struct {
	name     string // without prefix, e.g. "info"
	data     []byte // decompressed contents
	fileOff  int64  // file offset of the (possibly compressed) contents
	fileSize int64
	cps      []checkpoint // nil if not compressed
}

// checkpoint records that decompressing the first out bytes of a
// section consumed the first in bytes of its compressed form.
type checkpoint struct {
	out, in int64
}

// fileOffset maps an offset in the decompressed data to a file offset.
// For compressed sections, the mapping is approximate: it interpolates
// between checkpoints.
func (s *dwarfSect) fileOffset(off int64) int64 {
	if s.cps == nil {
		return s.fileOff + min(off, s.fileSize)
	}
	if off >= int64(len(s.data)) {
		return s.fileOff + s.fileSize
	}
	i := sort.Search(len(s.cps), func(i int) bool { return s.cps[i].out > off }) - 1
	if i < 0 {
		return s.fileOff
	}
	a := s.cps[i]
	b := checkpoint{int64(len(s.data)), s.fileSize}
	if i+1 < len(s.cps) {
		b = s.cps[i+1]
	}
	in := a.in
	if b.out > a.out {
		in += (off - a.out) * (b.in - a.in) / (b.out - a.out)
	}
	return s.fileOff + min(in, s.fileSize)
}

// blame claims the file bytes corresponding to decompressed range
// [lo, hi).
func (s *dwarfSect) blame(im *image, level int8, lo, hi int64, b Blame) {
	if hi <= lo {
		return
	}
	flo, fhi := s.fileOffset(lo), s.fileOffset(hi)
	im.bm.add(level, flo, fhi-flo, b)
}

// countingReader counts bytes read. It implements io.ByteReader so
// compress/flate reads from it directly, without buffering ahead.
type countingReader struct {
	r *bytes.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func (c *countingReader) ReadByte() (byte, error) {
	b, err := c.r.ReadByte()
	if err == nil {
		c.n++
	}
	return b, err
}

// newZlibDWARFSect decompresses a zlib stream from the file,
// recording checkpoints for mapping offsets back to the file.
func newZlibDWARFSect(name string, file []byte, off, size, usize int64) (*dwarfSect, error) {
	cr := &countingReader{r: bytes.NewReader(file[off : off+size])}
	zr, err := zlib.NewReader(cr)
	if err != nil {
		return nil, err
	}
	s := &dwarfSect{name: name, fileOff: off, fileSize: size}
	s.data = make([]byte, 0, usize)
	buf := make([]byte, 256)
	for {
		// compress/flate decompresses a window at a time, so only
		// record checkpoints when the input position changes;
		// interpolating between them spreads each window's input
		// over its output.
		if n := len(s.cps); n == 0 || s.cps[n-1].in != cr.n {
			s.cps = append(s.cps, checkpoint{int64(len(s.data)), cr.n})
		}
		n, err := zr.Read(buf)
		s.data = append(s.data, buf[:n]...)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	return s, nil
}

// blameELFDWARF blames the DWARF sections of an ELF file.
func (im *image) blameELFDWARF(f *elf.File) {
	sects := map[string]*dwarfSect{}
	for _, s := range f.Sections {
		name, ok := strings.CutPrefix(s.Name, ".debug_")
		if !ok || s.Type == elf.SHT_NOBITS {
			continue
		}
		off, size := int64(s.Offset), int64(s.FileSize)
		if s.Flags&elf.SHF_COMPRESSED == 0 {
			sects[name] = &dwarfSect{name: name, data: im.data[off : off+size], fileOff: off, fileSize: size}
			continue
		}
		hdrSize := int64(12)
		if f.Class == elf.ELFCLASS64 {
			hdrSize = 24
		}
		im.bm.add(levelStruct, off, hdrSize, Blame{What: "dwarf-chdr", Name: s.Name})
		if elf.CompressionType(f.ByteOrder.Uint32(im.data[off:])) != elf.COMPRESS_ZLIB {
			continue
		}
		ds, err := newZlibDWARFSect(name, im.data, off+hdrSize, size-hdrSize, int64(s.Size))
		if err != nil {
			log.Printf("warning: decompressing %s: %v", s.Name, err)
			continue
		}
		sects[name] = ds
	}
	im.blameDWARF(sects)
}

// blameDWARF blames the bytes of the DWARF sections.
func (im *image) blameDWARF(sects map[string]*dwarfSect) {
	get := func(name string) []byte {
		if s := sects[name]; s != nil {
			return s.data
		}
		return nil
	}
	info := sects["info"]
	if info == nil {
		return
	}
	d, err := dwarf.New(get("abbrev"), get("aranges"), get("frame"), info.data, get("line"), get("pubnames"), get("ranges"), get("str"))
	if err != nil {
		log.Printf("warning: parsing DWARF: %v", err)
		return
	}
	for _, name := range []string{"addr", "line_str", "loclists", "rnglists", "str_offsets"} {
		if b := get(name); b != nil {
			if err := d.AddSection(".debug_"+name, b); err != nil {
				log.Printf("warning: DWARF section %s: %v", name, err)
			}
		}
	}

	type unit struct {
		off, end int64
		name     string
		stmtList int64
		addrBase int64
	}
	var units []*unit
	for off := int64(0); off+4 <= int64(len(info.data)); {
		n := int64(im.order.Uint32(info.data[off:]))
		hdr := int64(4)
		if n == 0xffffffff {
			n = int64(im.order.Uint64(info.data[off+4:]))
			hdr = 12
		}
		end := off + hdr + n
		units = append(units, &unit{off: off, end: end, stmtList: -1, addrBase: -1})
		off = end
	}
	unitAt := func(off int64) *unit {
		i := sort.Search(len(units), func(i int) bool { return units[i].end > off })
		if i < len(units) {
			return units[i]
		}
		return nil
	}

	// Location and range lists referenced by DIEs, keyed by their
	// offset in their section.
	locOwner := map[int64]Blame{}
	rngOwner := map[int64]Blame{}

	r := d.Reader()
	var cu *unit
	var cuBlame Blame
	var top Blame    // blame for the current top-level DIE
	var topOff int64 // offset of the current top-level DIE
	depth := 0
	flushTop := func(end int64) {
		if topOff > 0 && end > topOff {
			info.blame(im, levelStruct, topOff, end, top)
		}
		topOff = 0
	}
	for {
		e, err := r.Next()
		if err != nil {
			log.Printf("warning: reading DWARF: %v", err)
			break
		}
		if e == nil {
			break
		}
		off := int64(e.Offset)
		if e.Tag == dwarf.TagCompileUnit {
			flushTop(off)
			if cu != nil {
				flushTop(cu.end)
			}
			cu = unitAt(off)
			depth = 0
			name, _ := e.Val(dwarf.AttrName).(string)
			cuBlame = Blame{What: "dwarf-info", Name: name, Pkg: name}
			if cu != nil {
				cu.name = name
				if v, ok := e.Val(dwarf.AttrStmtList).(int64); ok {
					cu.stmtList = v
				}
				if v, ok := e.Val(dwarf.AttrAddrBase).(int64); ok {
					cu.addrBase = v
				}
				// The unit header and CU DIE itself.
				info.blame(im, levelStruct, cu.off, off, cuBlame)
			}
			top = cuBlame
			topOff = off
			if e.Children {
				depth = 1
			}
			continue
		}
		if e.Tag == 0 {
			depth--
			continue
		}
		if depth == 1 {
			flushTop(off)
			top = cuBlame
			if name, ok := e.Val(dwarf.AttrName).(string); ok && name != "" {
				top.Name = name
				// Type DIEs are all in one unit, so prefer the
				// package from the name.
				if p := im.pkgOf(name); p != "" {
					top.Pkg = p
				}
			}
			topOff = off
		}
		for _, fld := range e.Field {
			switch fld.Class {
			case dwarf.ClassLocList, dwarf.ClassLocListPtr:
				if v, ok := fld.Val.(int64); ok {
					if _, dup := locOwner[v]; !dup {
						locOwner[v] = top
					}
				}
			case dwarf.ClassRangeListPtr, dwarf.ClassRngList:
				if v, ok := fld.Val.(int64); ok {
					if _, dup := rngOwner[v]; !dup {
						rngOwner[v] = top
					}
				}
			}
		}
		if e.Children {
			depth++
		}
	}
	if cu != nil {
		flushTop(cu.end)
	}

	if s := sects["line"]; s != nil {
		for _, u := range units {
			if u.stmtList < 0 || u.stmtList+4 > int64(len(s.data)) {
				continue
			}
			n := int64(im.order.Uint32(s.data[u.stmtList:]))
			s.blame(im, levelStruct, u.stmtList, u.stmtList+4+n, Blame{What: "dwarf-line", Name: u.name, Pkg: u.name})
		}
	}
	if s := sects["addr"]; s != nil {
		var bases []*unit
		for _, u := range units {
			if u.addrBase >= 0 {
				bases = append(bases, u)
			}
		}
		sort.Slice(bases, func(i, j int) bool { return bases[i].addrBase < bases[j].addrBase })
		for i, u := range bases {
			// The 8-byte header precedes the base.
			lo := u.addrBase - 8
			hi := int64(len(s.data))
			if i+1 < len(bases) {
				hi = bases[i+1].addrBase - 8
			}
			s.blame(im, levelStruct, lo, hi, Blame{What: "dwarf-addr", Name: u.name, Pkg: u.name})
		}
	}
	blameLists := func(s *dwarfSect, owners map[int64]Blame, what string) {
		if s == nil {
			return
		}
		offs := make([]int64, 0, len(owners))
		for off := range owners {
			offs = append(offs, off)
		}
		sort.Slice(offs, func(i, j int) bool { return offs[i] < offs[j] })
		for i, off := range offs {
			hi := int64(len(s.data))
			if i+1 < len(offs) {
				hi = offs[i+1]
			}
			b := owners[off]
			b.What = what
			s.blame(im, levelStruct, off, hi, b)
		}
		// Each unit's list table header precedes its first list.
		if len(offs) > 0 {
			s.blame(im, levelStruct, 0, offs[0], Blame{What: what})
		}
	}
	// DWARF 5 uses loclists and rnglists; DWARF 4 uses loc and ranges.
	blameLists(sects["loclists"], locOwner, "dwarf-loclists")
	blameLists(sects["rnglists"], rngOwner, "dwarf-rnglists")
	blameLists(sects["loc"], locOwner, "dwarf-loc")
	blameLists(sects["ranges"], rngOwner, "dwarf-ranges")

	if s := sects["frame"]; s != nil {
		im.blameDebugFrame(s)
	}
	for name, s := range sects {
		switch name {
		case "info", "line", "addr", "loclists", "rnglists", "loc", "ranges", "frame":
		default:
			s.blame(im, levelStruct-1, 0, int64(len(s.data)), Blame{What: "dwarf-" + name})
		}
	}
}

// blameDebugFrame blames each FDE in .debug_frame to the func whose
// code it describes.
func (im *image) blameDebugFrame(s *dwarfSect) {
	d := s.data
	order := im.order
	ps := int64(im.ptrSize)
	for off := int64(0); off+4 <= int64(len(d)); {
		n := int64(order.Uint32(d[off:]))
		hdr, idSize := int64(4), int64(4)
		if n == 0xffffffff {
			n = int64(order.Uint64(d[off+4:]))
			hdr, idSize = 12, 8
		}
		end := off + hdr + n
		if n == 0 || end > int64(len(d)) {
			break
		}
		var id uint64
		if idSize == 4 {
			id = uint64(order.Uint32(d[off+hdr:]))
		} else {
			id = order.Uint64(d[off+hdr:])
		}
		b := Blame{What: "dwarf-frame"}
		if id != 0xffffffff && id != 0xffffffffffffffff {
			// FDE: CIE pointer, then initial location.
			loc := off + hdr + idSize
			var pc uint64
			if ps == 8 {
				pc = order.Uint64(d[loc:])
			} else {
				pc = uint64(order.Uint32(d[loc:]))
			}
			if f := im.funcContaining(pc); f != nil {
				b.Name, b.Pkg = f.name, f.pkg
			} else if sym := im.symAt(pc); sym != nil {
				b = im.symBlame("dwarf-frame", sym.name)
			}
		} else {
			b.Name = "(CIE)"
		}
		s.blame(im, levelStruct, off, end, b)
		off = end
	}
}
