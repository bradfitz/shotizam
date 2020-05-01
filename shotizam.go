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
	"syscall"

	"github.com/bradfitz/shotizam/gosym"
)

var (
	sqlite = flag.Bool("sqlite", false, "launch SQLite on data")
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
	f, err := Open(of, fi.Size())
	of.Close()
	if err != nil {
		log.Fatal(err)
	}

	lt := gosym.NewLineTable(f.Gopclntab, f.TextOffset)
	t, err := gosym.NewTable(lt)
	if err != nil {
		log.Fatal(err)
	}
	// TODO: data

	var w io.WriteCloser = os.Stdout
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

	for i := range t.Funcs {
		f := &t.Funcs[i]
		emit := func(what string, size int) {
			// TODO: include truncated name, stopping at first ".func" closure.
			// Likewise, add field for func truncated just past type too. ("Type"?)
			fmt.Fprintf(w, "INSERT INTO Bin VALUES (%q, %q, %q, %v);\n",
				f.Name, f.PackageName(), what, size)
		}
		emit("pcsp", f.TableSizePCSP())
		emit("pcfile", f.TableSizePCFile())
		emit("pcln", f.TableSizePCLn())
		// TODO: the other funcdata and pcdata tables
		emit("textSize", int(f.End-f.Entry))
		emit("funcname", len(f.Name)+len("\x00"))
	}
	fmt.Fprintln(w, "END TRANSACTION;")

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
