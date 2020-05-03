// Copyright 2020 Brad Fitzpatrick. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Shotizam parses a Go binary and breaks down its size into SQL
// output for analysis in SQLite.
package main

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/bradfitz/shotizam/ar"
	"github.com/bradfitz/shotizam/gosym"
)

var (
	base    = flag.String("base", "", "base file to diff from; must be in json format")
	mode    = flag.String("mode", "sql", "output mode; tsv, json, sql, nameinfo")
	sqlite  = flag.Bool("sqlite", false, "launch SQLite on data (when true, mode flag is ignored)")
	verbose = flag.Bool("verbose", false, "verbose logging of file parsing")
)

type File struct {
	Size       int64
	TextOffset uint64
	Gopclntab  []byte
}

func Open(ra io.ReaderAt, size int64) (*File, error) {
	mo, err := macho.NewFile(ra)
	if err == nil {
		return machoFile(mo, ra, size)
	}
	elf, err := elf.NewFile(ra)
	if err == nil {
		return elfFile(elf, ra, size)
	}
	pf, err := pe.NewFile(ra)
	if err == nil {
		return peFile(pf, ra, size)
	}

	if f, ok := arFile(ra, size); ok {
		return f, nil
	}

	return nil, fmt.Errorf("unsupported binary format")
}

func arFile(ra io.ReaderAt, size int64) (f *File, ok bool) {
	arr, err := ar.NewReader(ra)
	if err != nil {
		return nil, false
	}
	for {
		af, err := arr.Next()
		if err != nil {
			return nil, false
		}
		if af.Name == "go.o" {
			f, err := Open(af, af.Size)
			if err == nil {
				return f, true
			}
		}
	}
}

func elfFile(elf *elf.File, ra io.ReaderAt, size int64) (*File, error) {
	f := &File{Size: size}

	text := elf.Section(".text")
	if text != nil {
		f.TextOffset = text.Offset
	}
	pclntab := elf.Section(".gopclntab")
	if pclntab == nil {
		return nil, errors.New("no __gopclntab section found in ELF file")
	}
	b, err := pclntab.Data()
	if err != nil {
		return nil, err
	}
	f.Gopclntab = b
	return f, nil
}

func machoFile(mo *macho.File, ra io.ReaderAt, size int64) (*File, error) {
	f := &File{Size: size}

	if *verbose {
		log.Printf("Got: %+v", mo.FileHeader)
		log.Printf("%d sections:", len(mo.Sections))
		sort.Slice(mo.Sections, func(i, j int) bool {
			return mo.Sections[i].Size > mo.Sections[j].Size
		})
		for i, s := range mo.Symtab.Syms {
			log.Printf("sym[%d]: %+v", i, s)
		}
	}

	for i, s := range mo.Sections {
		if *verbose {
			log.Printf("sect[%d] = %+v\n", i, s.SectionHeader)
		}
		if s.Name == "__text" {
			f.TextOffset = uint64(s.Offset)
		}
		if s.Name == "__gopclntab" {
			f.Gopclntab = make([]byte, s.Size)
			_, err := ra.ReadAt(f.Gopclntab, int64(s.Offset))
			if err != nil {
				return nil, err
			}
		}
	}
	if f.Gopclntab == nil {
		return nil, errors.New("no __gopclntab section found in macho file")
	}
	return f, nil
}

func peFile(pf *pe.File, ra io.ReaderAt, size int64) (*File, error) {
	f := &File{Size: size}
	for i, s := range pf.Sections {
		if s.Name == ".text" {
			f.TextOffset = uint64(s.Offset)
		}
		if *verbose {
			log.Printf("sect[%d] = %+v", i, s.SectionHeader)
		}
	}

	var start, end int64
	var pclnSect int // 0-based
	for i, s := range pf.Symbols {
		if *verbose {
			log.Printf("sym[%d] = %+v", i, s)
		}
		switch s.Name {
		case "runtime.pclntab":
			start = int64(s.Value)
			if s.SectionNumber == 0 {
				return nil, errors.New("bogus section number 0 for runtime.pclntab")
			}
			// It's 1-based on the file.
			pclnSect = int(s.SectionNumber - 1)
		case "runtime.epclntab":
			end = int64(s.Value)
		}
	}
	if start == 0 {
		return nil, errors.New("didn't find runtime.pclntab symbol")
	}
	if end == 0 {
		return nil, errors.New("didn't find runtime.epclntab symbol")
	}
	pcLnOff := int64(pf.Sections[pclnSect].Offset) + start
	pcLnSize := end - start

	if *verbose {
		log.Printf("got sect %d, start %d, end %d, size %d", pclnSect, start, end, pcLnSize)
		log.Printf("sect off = %d, pcLnOff = %d", int64(pf.Sections[pclnSect].Offset), pcLnOff)
	}

	f.Gopclntab = make([]byte, pcLnSize)
	_, err := ra.ReadAt(f.Gopclntab, pcLnOff)
	if err != nil {
		return nil, err
	}

	return f, nil
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

	of, err := os.Open(bin)
	if err != nil {
		log.Fatal(err)
	}
	fi, err := of.Stat()
	if err != nil {
		log.Fatal(err)
	}
	binSize := fi.Size()
	f, err := Open(of, binSize)
	of.Close()
	if err != nil {
		log.Fatal(err)
	}

	t, err := gosym.NewTable(f.Gopclntab, f.TextOffset)
	if err != nil {
		log.Fatal(err)
	}
	// TODO: data

	if *sqlite {
		*mode = "sql"
	}

	if *base != "" && *mode != "json" {
		log.Fatalf("--base only works with json mode")
	}

	var w io.WriteCloser = os.Stdout
	switch *mode {
	case "sql":
	case "json":
	case "tsv":
	case "nameinfo":
		w = nopWriteCloser()
	default:
		log.Fatalf("unknown mode %q", *mode)
	}

	var cmd *exec.Cmd
	var dbPath string
	if *sqlite {
		sqlBin, err := exec.LookPath("sqlite3")
		if err != nil {
			log.Fatalf("sqlite3 not found")
		}
		td, err := ioutil.TempDir("", "shotizam")
		if err != nil {
			log.Fatal(err)
		}
		dbPath = filepath.Join(td, "shotizam.db")
		cmd = exec.Command(sqlBin, dbPath)
		w, err = cmd.StdinPipe()
		if err != nil {
			log.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			log.Fatal(err)
		}
	}

	switch *mode {
	case "sql":
		fmt.Fprintln(w, "DROP TABLE IF EXISTS Bin;")
		fmt.Fprintln(w, "CREATE TABLE Bin (Func varchar, Pkg varchar, What varchar, Size int64);")
		fmt.Fprintln(w, "BEGIN TRANSACTION;")
	}
	unaccountedSize := binSize

	var names []string
	var recs []Rec

	for i := range t.Funcs {
		f := &t.Funcs[i]
		names = append(names, f.Name)
		emit := func(what string, size int64) {
			unaccountedSize -= int64(size)
			if size == 0 {
				return
			}
			switch *mode {
			case "sql":
				// TODO: include truncated name, stopping at first ".func" closure.
				// Likewise, add field for func truncated just past type too. ("Type"?)
				fmt.Fprintf(w, "INSERT INTO Bin VALUES (%s, %s, %q, %v);\n",
					sqlString(f.Name),
					sqlString(f.PackageName()),
					what,
					size)
			case "tsv":
				fmt.Fprintf(w, "%s\t%s\t%s\t%v\n", f.Name, f.PackageName(), what, size)
			case "json":
				recs = append(recs, Rec{RecKey{f.Name, f.PackageName(), what}, size})
			}
		}
		emit("fixedheader", int64(t.PtrSize()+8*4))        // uintptr + 8 x int32s in _func
		emit("funcdata", int64(t.PtrSize()*f.NumFuncData)) // TODO: add optional 4 byte alignment padding before first funcdata
		emit("pcsp", int64(f.TableSizePCSP()))
		emit("pcfile", int64(f.TableSizePCFile()))
		emit("pcln", int64(f.TableSizePCLn()))
		for tab := 0; tab < f.NumPCData; tab++ {
			emit(fmt.Sprintf("pcdata%d%s", tab, pcdataSuffix(tab)), int64(4 /* offset pointer */ +f.TableSizePCData(tab)))
		}
		// TODO: the other funcdata and pcdata tables
		emit("text", int64(f.End-f.Entry))
		emit("funcname", int64(len(f.Name)+len("\x00")))
	}

	switch *mode {
	case "sql":
		fmt.Fprintf(w, "INSERT INTO Bin (What, Size) VALUES ('TODO', %v);\n", unaccountedSize)
		fmt.Fprintln(w, "END TRANSACTION;")
	case "json":
		if *base != "" {
			old := readBaseRecs()
			oldm := recMap(old)
			newm := recMap(recs)
			recs = diffMap(oldm, newm)
		}
		je := json.NewEncoder(w)
		je.SetIndent("", "\t")
		if err := je.Encode(recs); err != nil {
			log.Fatal(err)
		}
	case "nameinfo":
		sort.Strings(names)
		var totNames, skip int
		for i, name := range names {
			totNames += len(name)
			var next string
			if i < len(names)-1 {
				next = names[i+1]
			}
			if strings.HasPrefix(next, name) {
				skip += len(name)
			}
		}
		log.Printf("                          total length of func names: %d", totNames)
		log.Printf("bytes of func names which are prefixes of other func: %d", skip)
		return
	}

	w.Close()
	if cmd != nil {
		if err := cmd.Wait(); err != nil {
			log.Fatal(err)
		}
		if err := syscall.Exec(cmd.Path, cmd.Args, cmd.Env); err != nil {
			log.Fatal(err)
		}
	}
}

func pcdataSuffix(n int) string {
	switch n {
	case 0:
		return "-regmap"
	case 1:
		return "-stackmap"
	case 2:
		return "-inltree"
	}
	return ""
}

func sqlString(s string) string {
	var sb strings.Builder
	sb.WriteByte('\'')
	for _, r := range s {
		if r == '\'' {
			sb.WriteString("''")
		} else {
			sb.WriteRune(r)
		}
	}
	sb.WriteByte('\'')
	return sb.String()
}

func nopWriteCloser() io.WriteCloser {
	return struct {
		io.Writer
		io.Closer
	}{
		ioutil.Discard,
		ioutil.NopCloser(nil),
	}
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
	Name    string `json:"name,omitempty"`
	Package string `json:"package,omitempty"`
	What    string `json:"what"`
}

type Rec struct {
	RecKey
	Size int64 `json:"size"`
}

func recMap(recs []Rec) map[RecKey]int64 {
	m := make(map[RecKey]int64)
	for _, r := range recs {
		m[r.RecKey] = r.Size
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
