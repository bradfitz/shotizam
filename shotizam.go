// Copyright 2020 Brad Fitzpatrick. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Shotizam parses a Go binary and breaks down its size into SQL
// output for analysis in SQLite.
//
// Every byte of the file is attributed to some reason: a function's
// code, its pclntab metadata, a type descriptor, a DWARF compile unit,
// a symbol table entry, alignment padding, etc. Bytes that shotizam
// can't explain are reported with What = 'unknown'.
package main

import (
	"bufio"
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/bradfitz/shotizam/ar"
)

var (
	base    = flag.String("base", "", "base file to diff from; must be in json format")
	mode    = flag.String("mode", "sql", "output mode; tsv, json, sql, summary, nameinfo")
	output  = flag.String("o", "", "output filename (default stdout); with --sqlite, the SQLite database to create")
	sqlite  = flag.Bool("sqlite", false, "launch SQLite on data (when true, mode flag is ignored)")
	verbose = flag.Bool("verbose", false, "verbose logging of file parsing")
	noDWARF = flag.Bool("nodwarf", false, "don't break down DWARF sections")
)

// analyze parses the binary in data and returns the blame for every
// byte of it.
func analyze(data []byte) (*image, []Segment, error) {
	if bytes.HasPrefix(data, []byte("!<arch>\n")) {
		sub, err := arGoObject(data)
		if err != nil {
			return nil, nil, err
		}
		return analyze(sub)
	}

	im := newImage(data)
	ra := bytes.NewReader(data)
	var postGo func()
	if f, err := elf.NewFile(ra); err == nil {
		if err := im.loadELF(f); err != nil {
			return nil, nil, err
		}
		postGo = func() {
			if !*noDWARF {
				im.blameELFDWARF(f)
			}
			im.blameELFRelocs(f, im.addrBlamer())
		}
	} else if f, err := macho.NewFile(ra); err == nil {
		if err := im.loadMachO(f); err != nil {
			return nil, nil, err
		}
		postGo = func() {
			if !*noDWARF {
				im.blameMachODWARF(f)
			}
			im.blameMachOFixups(f, im.addrBlamer())
		}
	} else if f, err := pe.NewFile(ra); err == nil {
		if err := im.loadPE(f); err != nil {
			return nil, nil, err
		}
		postGo = func() {
			if !*noDWARF {
				im.blamePEDWARF(f)
			}
			im.blamePERelocs(f, im.addrBlamer())
		}
	} else {
		return nil, nil, errors.New("unsupported binary format")
	}
	im.finishTables()
	im.blameSymbols()

	if err := im.analyzeGo(); err != nil {
		log.Printf("warning: Go analysis: %v", err)
	}
	if postGo != nil {
		postGo()
	}
	segs := im.bm.resolve()

	// Symbol table entries and names were blamed before the pclntab
	// was parsed, so fill in packages for funcs that only the pclntab
	// could provide.
	if im.pcln != nil {
		funcPkg := map[string]string{}
		for _, f := range im.pcln.funcs {
			funcPkg[f.name] = f.pkg
		}
		for i := range segs {
			if s := &segs[i]; s.Pkg == "" && s.Name != "" {
				s.Pkg = funcPkg[s.Name]
			}
		}
	}
	return im, segs, nil
}

// arGoObject returns the contents of the go.o member of an ar archive,
// as produced by -buildmode=c-archive.
func arGoObject(data []byte) ([]byte, error) {
	arr, err := ar.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	for {
		af, err := arr.Next()
		if err != nil {
			return nil, fmt.Errorf("no go.o in archive: %w", err)
		}
		if af.Name == "go.o" {
			return io.ReadAll(af)
		}
	}
}

// analyzeGo attributes bytes described by the Go runtime's own
// metadata: the pclntab, funcdata, type descriptors, and itabs.
func (im *image) analyzeGo() error {
	md, err := im.findModuleData()
	if err != nil {
		// Without moduledata, we can still try the pclntab.
		hdr, ok := im.findPCHeader()
		if !ok {
			return err
		}
		t, err2 := im.parsePclntab(hdr, nil)
		if err2 != nil {
			return err2
		}
		im.pcln = t
		t.blame()
		return fmt.Errorf("%v; analyzed pclntab only", err)
	}
	if md.size > 0 {
		im.blameAddr(levelStruct, md.addr, md.size, Blame{What: "moduledata", Name: "runtime.firstmoduledata", Pkg: "runtime"})
	}
	t, err := im.parsePclntab(md.pcHeader, md)
	if err != nil {
		return err
	}
	im.pcln = t
	t.blame()
	im.refs = im.buildRefIndex(im.arch)
	im.blameFuncDescs(md)
	im.blameTypes(md)
	im.blameUnnamedData(md)
	return nil
}

// blameUnnamedData blames string literals and other data without
// symbols of their own to the code or data referencing them.
func (im *image) blameUnnamedData(md *moduleData) {
	// Static data can point to other static data without symbols,
	// so iterate, blaming each level of pointed-to data.
	for pass := 0; pass < 4; pass++ {
		if pass > 0 && !im.resolvePending(im.refs) {
			break
		}
		if s := im.lookup("go:string.*"); s != nil && s.size > 0 {
			im.blameByRefs(im.refs, s.addr, s.addr+s.size, "string")
		}
		for _, s := range im.sects {
			if s.addr == 0 {
				continue
			}
			switch s.name {
			case ".rodata", ".noptrdata", ".data", "__TEXT,__rodata", "__DATA,__noptrdata", "__DATA,__data", "__DATA_CONST,__rodata":
				what := s.name[strings.LastIndexAny(s.name, ".,_")+1:]
				im.blameByRefs(im.refs, s.addr, s.addr+uint64(s.size), what+"-ref")
			}
		}
	}
}

// blameFuncDescs blames the go:funcdesc (closure-less funcval) symbols,
// which are each a pointer to a func, to the func they point to.
func (im *image) blameFuncDescs(md *moduleData) {
	s := im.lookup("go:funcdesc")
	if s == nil || s.size == 0 {
		return
	}
	ps := uint64(im.ptrSize)
	for a := s.addr; a+ps <= s.addr+s.size; a += ps {
		if f := im.funcAt(im.uptr(a)); f != nil && !strings.HasSuffix(f.name, "·f") {
			im.blameAddr(levelStruct, a, ps, Blame{What: "funcdesc", Name: f.name + "·f", Pkg: f.pkg})
		}
	}
}

// funcAt returns the func whose entry is exactly pc, or nil.
func (im *image) funcAt(pc uint64) *funcInfo {
	t := im.pcln
	if t == nil {
		return nil
	}
	i := sort.Search(len(t.funcs), func(i int) bool { return t.funcs[i].entry >= pc })
	if i < len(t.funcs) && t.funcs[i].entry == pc {
		return t.funcs[i]
	}
	return nil
}

// funcContaining returns the func whose code contains pc, or nil.
func (im *image) funcContaining(pc uint64) *funcInfo {
	t := im.pcln
	if t == nil {
		return nil
	}
	i := sort.Search(len(t.funcs), func(i int) bool { return t.funcs[i].entry > pc })
	if i > 0 && pc < t.funcs[i-1].end {
		return t.funcs[i-1]
	}
	return nil
}

// addrBlamer returns a func that reports the current blame for the
// byte at a virtual address, for attributing relocations and fixups
// to the data they modify.
func (im *image) addrBlamer() func(addr uint64) Blame {
	f := segBlamer(im, im.bm.resolve())
	return func(addr uint64) Blame {
		b, _ := f(addr)
		return b
	}
}

func main() {
	log.SetFlags(0)
	flag.Parse()
	if flag.NArg() != 1 {
		log.Fatalf("Usage: shotizam <go-binary>")
	}
	bin := flag.Arg(0)
	if bin == "SELF" {
		var err error
		bin, err = os.Executable()
		if err != nil {
			log.Fatal(err)
		}
	}
	data, err := os.ReadFile(bin)
	if err != nil {
		log.Fatal(err)
	}
	im, segs, err := analyze(data)
	if err != nil {
		log.Fatal(err)
	}

	if *sqlite {
		*mode = "sql"
	}
	if *base != "" && *mode != "json" {
		log.Fatalf("--base only works with json mode")
	}

	switch *mode {
	case "sql", "json", "tsv", "summary", "nameinfo":
	default:
		log.Fatalf("unknown mode %q", *mode)
	}

	var w io.WriteCloser = os.Stdout
	if !*sqlite && *output != "" && *output != "-" {
		w, err = os.Create(*output)
		if err != nil {
			log.Fatal(err)
		}
	}

	var cmd *exec.Cmd
	if *sqlite {
		sqlBin, err := exec.LookPath("sqlite3")
		if err != nil {
			log.Fatalf("sqlite3 not found")
		}
		dbPath := *output
		if dbPath == "" || dbPath == "-" {
			td, err := os.MkdirTemp("", "shotizam")
			if err != nil {
				log.Fatal(err)
			}
			dbPath = filepath.Join(td, "shotizam.db")
		}
		cmd = exec.Command(sqlBin, dbPath)
		w, err = cmd.StdinPipe()
		if err != nil {
			log.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			log.Fatal(err)
		}
	}

	bw := bufio.NewWriterSize(w, 1<<20)
	switch *mode {
	case "sql":
		writeSQL(bw, im, segs)
	case "tsv":
		for _, s := range segs {
			fmt.Fprintf(bw, "%d\t%d\t%s\t%s\t%s\t%s\n", s.Off, s.Size, im.sectionAt(s.Off), s.What, s.Name, s.Pkg)
		}
	case "summary":
		writeSummary(bw, im, segs)
	case "nameinfo":
		writeNameInfo(bw, im)
	case "json":
		recs := aggregate(im, segs)
		if *base != "" {
			recs = diffMap(recMap(readBaseRecs()), recMap(recs))
		}
		je := json.NewEncoder(bw)
		je.SetIndent("", "\t")
		if err := je.Encode(recs); err != nil {
			log.Fatal(err)
		}
	}
	if err := bw.Flush(); err != nil {
		log.Fatal(err)
	}
	if err := w.Close(); err != nil {
		log.Fatal(err)
	}
	if cmd != nil {
		if err := cmd.Wait(); err != nil {
			log.Fatal(err)
		}
		if err := syscall.Exec(cmd.Path, cmd.Args, cmd.Env); err != nil {
			log.Fatal(err)
		}
	}
}

func writeSQL(w io.Writer, im *image, segs []Segment) {
	fmt.Fprintln(w, "DROP TABLE IF EXISTS Bin;")
	fmt.Fprintln(w, "CREATE TABLE Bin (Off int64, Size int64, Section varchar, What varchar, Name varchar, Pkg varchar);")
	fmt.Fprintln(w, "BEGIN TRANSACTION;")
	const batch = 500
	for i, s := range segs {
		if i%batch == 0 {
			if i > 0 {
				fmt.Fprintln(w, ";")
			}
			fmt.Fprint(w, "INSERT INTO Bin VALUES ")
		} else {
			fmt.Fprint(w, ",")
		}
		fmt.Fprintf(w, "(%d,%d,%s,%s,%s,%s)", s.Off, s.Size,
			sqlString(im.sectionAt(s.Off)), sqlString(s.What), sqlString(s.Name), sqlString(s.Pkg))
	}
	if len(segs) > 0 {
		fmt.Fprintln(w, ";")
	}
	fmt.Fprintln(w, "END TRANSACTION;")

	// Funcs records where each func is declared, for grouping by
	// source file.
	fmt.Fprintln(w, "DROP TABLE IF EXISTS Func;")
	fmt.Fprintln(w, "CREATE TABLE Func (Name varchar, Pkg varchar, File varchar, Line int);")
	fmt.Fprintln(w, "BEGIN TRANSACTION;")
	if t := im.pcln; t != nil {
		for i, f := range t.funcs {
			if i%batch == 0 {
				if i > 0 {
					fmt.Fprintln(w, ";")
				}
				fmt.Fprint(w, "INSERT INTO Func VALUES ")
			} else {
				fmt.Fprint(w, ",")
			}
			fmt.Fprintf(w, "(%s,%s,%s,%d)", sqlString(f.name), sqlString(f.pkg), sqlString(t.file(f)), f.startLine)
		}
		if len(t.funcs) > 0 {
			fmt.Fprintln(w, ";")
		}
	}
	fmt.Fprintln(w, "END TRANSACTION;")

	// Fixups are pointers the dynamic loader adjusts at startup,
	// dirtying the memory pages they're on.
	fmt.Fprintln(w, "DROP TABLE IF EXISTS Fixup;")
	fmt.Fprintln(w, "CREATE TABLE Fixup (Addr int64, Section varchar, What varchar, Name varchar, Pkg varchar);")
	fmt.Fprintln(w, "BEGIN TRANSACTION;")
	blameOf := segBlamer(im, segs)
	for i, a := range im.fixups {
		if i%batch == 0 {
			if i > 0 {
				fmt.Fprintln(w, ";")
			}
			fmt.Fprint(w, "INSERT INTO Fixup VALUES ")
		} else {
			fmt.Fprint(w, ",")
		}
		b, sect := blameOf(a)
		fmt.Fprintf(w, "(%d,%s,%s,%s,%s)", a, sqlString(sect), sqlString(b.What), sqlString(b.Name), sqlString(b.Pkg))
	}
	if len(im.fixups) > 0 {
		fmt.Fprintln(w, ";")
	}
	fmt.Fprintln(w, "END TRANSACTION;")
}

// sortSearchSegs returns the index of the segment containing file
// offset off, or len(segs).
func sortSearchSegs(segs []Segment, off int64) int {
	i := sort.Search(len(segs), func(i int) bool { return segs[i].Off+segs[i].Size > off })
	if i < len(segs) && segs[i].Off > off {
		return len(segs)
	}
	return i
}

// segBlamer returns a func reporting the blame and section of the
// byte at a virtual address.
func segBlamer(im *image, segs []Segment) func(addr uint64) (Blame, string) {
	return func(addr uint64) (Blame, string) {
		if off, ok := im.addrOff(addr); ok {
			i := sortSearchSegs(segs, off)
			if i < len(segs) {
				return segs[i].Blame, im.sectionAt(off)
			}
		}
		if s := im.symAt(addr); s != nil {
			return im.symBlame("bss", s.name), ""
		}
		return Blame{}, ""
	}
}

// writeSummary writes a human-readable breakdown of the file by
// section and by What.
func writeSummary(w io.Writer, im *image, segs []Segment) {
	var total int64
	bySect := map[string]int64{}
	byWhat := map[string]int64{}
	for _, s := range segs {
		total += s.Size
		bySect[im.sectionAt(s.Off)] += s.Size
		byWhat[s.What] += s.Size
	}
	fmt.Fprintf(w, "file size: %d bytes (%s)\n", len(im.data), im.goVersion)
	if total != int64(len(im.data)) {
		fmt.Fprintf(w, "WARNING: segments total %d bytes\n", total)
	}
	printTop := func(title string, m map[string]int64) {
		fmt.Fprintf(w, "\nby %s:\n", title)
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return m[keys[i]] > m[keys[j]] })
		for _, k := range keys {
			fmt.Fprintf(w, "  %10d %6.2f%%  %s\n", m[k], 100*float64(m[k])/float64(total), k)
		}
	}
	printTop("section", bySect)
	printTop("what", byWhat)
}

// writeNameInfo writes statistics about how much of the func name
// data is shared prefixes of other func names.
func writeNameInfo(w io.Writer, im *image) {
	if im.pcln == nil {
		log.Fatal("no pclntab")
	}
	var names []string
	for _, f := range im.pcln.funcs {
		names = append(names, f.name)
	}
	sort.Strings(names)
	var totNames, skip int
	for i, name := range names {
		totNames += len(name)
		if i < len(names)-1 && strings.HasPrefix(names[i+1], name) {
			skip += len(name)
		}
	}
	fmt.Fprintf(w, "                          total length of func names: %d\n", totNames)
	fmt.Fprintf(w, "bytes of func names which are prefixes of other func: %d\n", skip)
}

func sqlString(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == utf8.RuneError {
			return '?'
		}
		return r
	}, s)
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func readBaseRecs() []Rec {
	f, err := os.Open(*base)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	var recs []Rec
	if err := json.NewDecoder(f).Decode(&recs); err != nil {
		log.Fatal(err)
	}
	return recs
}

type RecKey struct {
	Section string `json:"section,omitempty"`
	What    string `json:"what"`
	Name    string `json:"name,omitempty"`
	Package string `json:"package,omitempty"`
}

type Rec struct {
	RecKey
	Size int64 `json:"size"`
}

// aggregate sums segment sizes by everything but their offsets.
func aggregate(im *image, segs []Segment) []Rec {
	m := map[RecKey]int64{}
	for _, s := range segs {
		m[RecKey{im.sectionAt(s.Off), s.What, s.Name, s.Pkg}] += s.Size
	}
	recs := make([]Rec, 0, len(m))
	for k, v := range m {
		recs = append(recs, Rec{k, v})
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].Size > recs[j].Size })
	return recs
}

func recMap(recs []Rec) map[RecKey]int64 {
	m := make(map[RecKey]int64)
	for _, r := range recs {
		m[r.RecKey] += r.Size
	}
	return m
}

func diffMap(a, b map[RecKey]int64) []Rec {
	diff := make(map[RecKey]int64)
	for k, size := range b {
		oldSize, ok := a[k]
		change := size - oldSize
		if change != 0 {
			diff[k] = change
		}
		if ok {
			delete(a, k)
		}
	}
	// Anything not deleted in a is stuff we dropped. Count it as
	// negative size.
	for k, size := range a {
		diff[k] = -size
	}

	recs := make([]Rec, 0, len(diff))
	for k, size := range diff {
		recs = append(recs, Rec{k, size})
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].Size < recs[j].Size })

	return recs
}
