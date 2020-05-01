// Copyright 2020 Brad Fitzpatrick. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Shotizam parses a Go binary and breaks down its size into SQL
// output for analysis in SQLite.
package main

import (
	"debug/elf"
	"debug/macho"
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

	"github.com/bradfitz/shotizam/gosym"
)

var (
	sqlite   = flag.Bool("sqlite", false, "launch SQLite on data")
	nameInfo = flag.Bool("nameinfo", false, "show analysis of func names")
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
	return nil, fmt.Errorf("unsupported binary format")
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

	/*
		log.Printf("Got: %+v", mo.FileHeader)
		log.Printf("%d sections:", len(mo.Sections))
		sort.Slice(mo.Sections, func(i, j int) bool {
			return mo.Sections[i].Size > mo.Sections[j].Size
		})
	*/
	for _, s := range mo.Sections {
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
		log.Printf("Using binary %v", bin)
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

	var w io.WriteCloser = os.Stdout
	if *nameInfo {
		w = struct {
			io.Writer
			io.Closer
		}{
			ioutil.Discard,
			ioutil.NopCloser(nil),
		}
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

	fmt.Fprintln(w, "DROP TABLE IF EXISTS Bin;")
	fmt.Fprintln(w, "CREATE TABLE Bin (Func varchar, Pkg varchar, What varchar, Size int64);")
	fmt.Fprintln(w, "BEGIN TRANSACTION;")

	unaccountedSize := binSize

	var names []string
	for i := range t.Funcs {
		f := &t.Funcs[i]
		names = append(names, f.Name)
		emit := func(what string, size int) {
			unaccountedSize -= int64(size)
			if size == 0 {
				return
			}
			// TODO: include truncated name, stopping at first ".func" closure.
			// Likewise, add field for func truncated just past type too. ("Type"?)
			fmt.Fprintf(w, "INSERT INTO Bin VALUES (%s, %s, %q, %v);\n",
				sqlString(f.Name),
				sqlString(f.PackageName()),
				what,
				size)
		}
		emit("fixedheader", t.PtrSize()+8*4)        // uintptr + 8 x int32s in _func
		emit("funcdata", t.PtrSize()*f.NumFuncData) // TODO: add optional 4 byte alignment padding before first funcdata
		emit("pcsp", f.TableSizePCSP())
		emit("pcfile", f.TableSizePCFile())
		emit("pcln", f.TableSizePCLn())
		for tab := 0; tab < f.NumPCData; tab++ {
			emit(fmt.Sprintf("pcdata%d%s", tab, pcdataSuffix(tab)), 4 /* offset pointer */ +f.TableSizePCData(tab))
		}
		// TODO: the other funcdata and pcdata tables
		emit("text", int(f.End-f.Entry))
		emit("funcname", len(f.Name)+len("\x00"))
	}

	fmt.Fprintf(w, "INSERT INTO Bin (What, Size) VALUES ('TODO', %v);\n", unaccountedSize)

	fmt.Fprintln(w, "END TRANSACTION;")

	if *nameInfo {
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
