// Package ar contains a minimal ar archive reader, including only what
// shotizam needs.
package ar

import (
	"errors"
	"fmt"
	"io"
	"net/textproto"
	"strconv"
	"strings"
)

type Reader struct {
	ra        io.ReaderAt
	off       int64
	headerBuf []byte
}

const (
	magic        = "!<arch>\n"
	fileOff      = 0
	fileLen      = 16
	mtimeOff     = fileOff + fileLen
	mtimeLen     = 12
	uidOff       = mtimeOff + mtimeLen
	uidLen       = 6 // decimal
	gidOff       = uidOff + uidLen
	gidLen       = 6 // decimal
	modeOff      = gidOff + gidLen
	modeLen      = 8 // octal
	sizeOff      = modeOff + modeLen
	sizeLen      = 10 // decimal
	endOff       = sizeOff + sizeLen
	endHeader    = "\x60\x0a"
	endHeaderLen = 2
	headerLen    = fileLen + mtimeLen + uidLen + gidLen + modeLen + sizeLen + endHeaderLen
)

func NewReader(ra io.ReaderAt) (*Reader, error) {
	buf := make([]byte, len(magic))
	if _, err := ra.ReadAt(buf, 0); err != nil {
		return nil, err
	}
	if string(buf) != magic {
		return nil, errors.New("invalid magic")
	}
	r := &Reader{
		ra:        ra,
		off:       int64(len(magic)),
		headerBuf: make([]byte, headerLen),
	}
	return r, nil
}

type File struct {
	*io.SectionReader
	Name string
	Size int64
}

// Next returns the next file or an error.
//
// On EOF, the error is (nil, io.EOF).
func (r *Reader) Next() (*File, error) {
	buf := r.headerBuf
	n, err := r.ra.ReadAt(buf, r.off)
	if err != nil {
		return nil, err
	}
	if n != headerLen {
		return nil, fmt.Errorf("read header of %d bytes; want %d", n, headerLen)
	}
	if string(buf[endOff:endOff+endHeaderLen]) != endHeader {
		return nil, fmt.Errorf("bogus header record: %q", buf)
	}
	f := &File{}
	f.Name = textproto.TrimString(string(buf[:fileLen]))
	sizeStr := string(buf[sizeOff : sizeOff+sizeLen])
	f.Size, err = strconv.ParseInt(textproto.TrimString(sizeStr), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("unexpected parsing int from %q: %v", sizeStr, err)
	}
	r.off += headerLen

	// macOS extended filename; see ar(5) on macOS.
	if strings.HasPrefix(f.Name, "#1/") {
		n, err := strconv.Atoi(f.Name[3:])
		if err != nil {
			return nil, fmt.Errorf("unexpected macOS ar filename %q: %v", f.Name, err)
		}
		nameBuf := make([]byte, n)
		if _, err := r.ra.ReadAt(nameBuf, r.off); err != nil {
			return nil, err
		}
		f.Name = strings.TrimRight(string(nameBuf), "\x00") // why are there nuls at the end?
		r.off += int64(n)
		f.Size -= int64(n)
	}

	f.SectionReader = io.NewSectionReader(r.ra, r.off, f.Size)
	r.off += f.Size
	if r.off&1 != 0 {
		r.off++
	}
	return f, nil
}
