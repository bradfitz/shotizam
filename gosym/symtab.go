// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package gosym implements access to the Go symbol
// and line number tables embedded in Go binaries generated
// by the gc compilers.
//
// See https://golang.org/s/go12symtab
//
// This is a fork of the Go standard library's debug/gosym package,
// with some stuff added for use by Shotizam.
package gosym

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
)

/*
 * Symbols
 */

// A Sym represents a single symbol table entry.
type Sym struct {
	Value  uint64
	Type   byte
	Name   string
	GoType uint64
	// If this symbol is a function symbol, the corresponding Func
	Func *Func
}

// Static reports whether this symbol is static (not visible outside its file).
func (s *Sym) Static() bool { return s.Type >= 'a' }

// PackageName returns the package part of the symbol name,
// or the empty string if there is none.
func (s *Sym) PackageName() string {
	name := s.Name

	// A prefix of "type." and "go." is a compiler-generated symbol that doesn't belong to any package.
	// See variable reservedimports in cmd/compile/internal/gc/subr.go
	if strings.HasPrefix(name, "go.") || strings.HasPrefix(name, "type.") {
		return ""
	}

	pathend := strings.LastIndex(name, "/")
	if pathend < 0 {
		pathend = 0
	}

	if i := strings.Index(name[pathend:], "."); i != -1 {
		return name[:pathend+i]
	}
	return ""
}

// ReceiverName returns the receiver type name of this symbol,
// or the empty string if there is none.
func (s *Sym) ReceiverName() string {
	pathend := strings.LastIndex(s.Name, "/")
	if pathend < 0 {
		pathend = 0
	}
	l := strings.Index(s.Name[pathend:], ".")
	r := strings.LastIndex(s.Name[pathend:], ".")
	if l == -1 || r == -1 || l == r {
		return ""
	}
	return s.Name[pathend+l+1 : pathend+r]
}

// BaseName returns the symbol name without the package or receiver name.
func (s *Sym) BaseName() string {
	if i := strings.LastIndex(s.Name, "."); i != -1 {
		return s.Name[i+1:]
	}
	return s.Name
}

// A Func collects information about a single function.
type Func struct {
	Entry uint64
	*Sym
	End       uint64
	LineTable *LineTable
	Obj       *Obj

	OffFixedFunc uint64

	ArgSize     int    // in/out args size
	DeferReturn int    // offset of start of a deferreturn call instruction from entry, if any.
	OffPCSP     uint32 // pcsp table (offset from pcvalue table)
	OffPCFile   uint32 // pcfile table (offset from pcvalue table)
	OffPCLn     uint32 // pcln table (offset from pcvalue table)
	NumPCData   int    // number of entries in pcdata list
	NumFuncData int    // number of entries in funcdata list
	FuncID      int    // special runtime func ID (for some runtime funcs)

	funcStructBytes []byte
}

func (f *Func) TableSizePCFile() int { return f.tableSize(f.OffPCFile) }
func (f *Func) TableSizePCSP() int   { return f.tableSize(f.OffPCSP) }
func (f *Func) TableSizePCLn() int   { return f.tableSize(f.OffPCLn) }

// tab is 0-based table number.
func (f *Func) TableSizePCData(tab int) int {
	if tab >= f.NumPCData || tab < 0 {
		log.Fatalf("bogus tab %d; NumPCData=%v", tab, f.NumPCData)
	}
	fs := funcStruct{f.LineTable, f.funcStructBytes}
	var tableOff uint32
	if f.LineTable.version >= ver116 {
		tableOff = fs.field(9 + tab)
	} else {
		tableOff = fs.field(8 + tab)
	}
	if tableOff == 0 {
		return 0
	}
	return f.tableSize(tableOff)
}

func (f *Func) tableSize(off uint32) int {
	sumSize := 0
	f.ForeachTableEntry(off, func(val int64, valBytes int, pc uint64, pcBytes int) {
		sumSize += valBytes + pcBytes
	})
	return sumSize
}

func (f *Func) ForeachTableEntry(off uint32, fn func(val int64, valBytes int, pc uint64, pcBytes int)) {
	if off == 0 {
		return
	}
	data := f.LineTable.funcdata[off:]
	pc := f.Entry
	val := int64(-1)

	for len(data) > 0 && pc < f.End {
		vald, valBytes := binary.Varint(data)
		if valBytes <= 0 {
			panic("bogus")
		}
		val += vald
		data = data[valBytes:]

		pcd, pcBytes := binary.Uvarint(data)
		if pcBytes <= 0 {
			panic("bogus")
		}

		data = data[pcBytes:]
		pcd *= uint64(f.LineTable.quantum)
		pc += pcd

		fn(val, valBytes, pc, pcBytes)
	}
}

// An Obj represents a collection of functions in a symbol table.
//
// The exact method of division of a binary into separate Objs is an internal detail
// of the symbol table format.
//
// In early versions of Go each source file became a different Obj.
//
// In Go 1 and Go 1.1, each package produced one Obj for all Go sources
// and one Obj per C source file.
//
// In Go 1.2, there is a single Obj for the entire program.
type Obj struct {
	// Funcs is a list of functions in the Obj.
	Funcs []Func
}

/*
 * Symbol tables
 */

// Table represents a Go symbol table. It stores all of the
// symbols decoded from the program and provides methods to translate
// between symbols, names, and addresses.
type Table struct {
	Funcs []Func
	Files map[string]*Obj // nil for Go 1.2 and later binaries
	Objs  []Obj           // nil for Go 1.2 and later binaries

	lt *LineTable // Go 1.2 line number table
}

// NewTable returns a new PC/line table
// corresponding to the encoded data.
// Text must be the start address of the
// corresponding text segment.
func NewTable(data []byte, text uint64) (*Table, error) {
	lt := &LineTable{
		Data:      data,
		PC:        text,
		funcNames: make(map[uint32]string),
		strings:   make(map[uint32]string),
	}

	var t Table
	if !lt.isGo12() {
		return nil, errors.New("not a go1.2+ line table")
	}
	t.lt = lt
	t.Funcs = make([]Func, 0)
	t.Files = make(map[string]*Obj)

	// Put all functions into one Obj.
	t.Objs = make([]Obj, 1)
	obj := &t.Objs[0]
	t.lt.go12MapFiles(t.Files, obj)

	t.Funcs = t.lt.go12Funcs()
	obj.Funcs = t.Funcs
	return &t, nil
}

func (t *Table) PtrSize() int { return int(t.lt.ptrsize) }

// PCToFunc returns the function containing the program counter pc,
// or nil if there is no such function.
func (t *Table) PCToFunc(pc uint64) *Func {
	funcs := t.Funcs
	for len(funcs) > 0 {
		m := len(funcs) / 2
		fn := &funcs[m]
		switch {
		case pc < fn.Entry:
			funcs = funcs[0:m]
		case fn.Entry <= pc && pc < fn.End:
			return fn
		default:
			funcs = funcs[m+1:]
		}
	}
	return nil
}

// PCToLine looks up line number information for a program counter.
// If there is no information, it returns fn == nil.
func (t *Table) PCToLine(pc uint64) (file string, line int, fn *Func) {
	if fn = t.PCToFunc(pc); fn == nil {
		return
	}
	file = t.lt.pcToFile(pc)
	line = t.lt.go12PCToLine(pc)
	return
}

// LineToPC looks up the first program counter on the given line in
// the named file. It returns UnknownPathError or UnknownLineError if
// there is an error looking up this line.
func (t *Table) LineToPC(file string, line int) (pc uint64, fn *Func, err error) {
	_, ok := t.Files[file]
	if !ok {
		return 0, nil, UnknownFileError(file)
	}
	pc = t.lt.lineToPC(file, line)
	if pc == 0 {
		return 0, nil, &UnknownLineError{file, line}
	}
	return pc, t.PCToFunc(pc), nil
}

// LookupFunc returns the text, data, or bss symbol with the given name,
// or nil if no such symbol is found.
func (t *Table) LookupFunc(name string) *Func {
	for i := range t.Funcs {
		f := &t.Funcs[i]
		if f.Sym.Name == name {
			return f
		}
	}
	return nil
}

/*
 * Errors
 */

// UnknownFileError represents a failure to find the specific file in
// the symbol table.
type UnknownFileError string

func (e UnknownFileError) Error() string { return "unknown file: " + string(e) }

// UnknownLineError represents a failure to map a line to a program
// counter, either because the line is beyond the bounds of the file
// or because there is no code on the given line.
type UnknownLineError struct {
	File string
	Line int
}

func (e *UnknownLineError) Error() string {
	return "no code at " + e.File + ":" + strconv.Itoa(e.Line)
}

// DecodingError represents an error during the decoding of
// the symbol table.
type DecodingError struct {
	off int
	msg string
	val interface{}
}

func (e *DecodingError) Error() string {
	msg := e.msg
	if e.val != nil {
		msg += fmt.Sprintf(" '%v'", e.val)
	}
	msg += fmt.Sprintf(" at byte %#x", e.off)
	return msg
}
