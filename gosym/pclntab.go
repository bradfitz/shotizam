package gosym

import (
	"fmt"
	"bytes"
	"encoding/binary"
	"sync"
)

// A LineTable is a data structure mapping program counters to line numbers.
//
// In Go 1.1 and earlier, each function (represented by a Func) had its own LineTable,
// and the line number corresponded to a numbering of all source lines in the
// program, across all files. That absolute line number would then have to be
// converted separately to a file name and line number within the file.
//
// In Go 1.2, the format of the data changed so that there is a single LineTable
// for the entire program, shared by all Funcs, and there are no absolute line
// numbers, just line numbers within specific files.
//
// For the most part, LineTable's methods should be treated as an internal
// detail of the package; callers should use the methods on Table instead.
type LineTable struct {
	Data []byte
	PC   uint64

	// Go 1.2 state
	go12     int // is this in Go 1.2 format? -1 no, 0 unknown, 1 yes
	binary   binary.ByteOrder
	quantum  uint32
	ptrsize  uint32
	functab  []byte
	nfunctab uint32
	filetab  []byte
	nfiletab uint32

	mu        sync.Mutex
	fileMap   map[string]uint32
	strings   map[uint32]string // interned substrings of Data, keyed by offset
	stringLen int64             // cumulate len(values(strings))
}

func (t *LineTable) String() string {
	return fmt.Sprintf("LineTable: %d bytes, nfunc=%v (%v bytes), nfile=%d (%v bytes), filemap=%v, strings=%v",
		len(t.Data),
		t.nfunctab,
		len(t.functab),
		t.nfiletab,
		len(t.filetab),
		len(t.fileMap),
		len(t.strings),
	)
}

// PCToLine returns the line number for the given program counter.
//
// Deprecated: Use Table's PCToLine method instead.
func (t *LineTable) PCToLine(pc uint64) int {
	return t.go12PCToLine(pc)
}

// isGo12 reports whether this is a Go 1.2 (or later) symbol table.
func (t *LineTable) isGo12() bool {
	t.go12Init()
	return t.go12 == 1
}

const go12magic = 0xfffffffb

// uintptr returns the pointer-sized value encoded at b.
// The pointer size is dictated by the table being read.
func (t *LineTable) uintptr(b []byte) uint64 {
	if t.ptrsize == 4 {
		return uint64(t.binary.Uint32(b))
	}
	return t.binary.Uint64(b)
}

// go12init initializes the Go 1.2 metadata if t is a Go 1.2 symbol table.
func (t *LineTable) go12Init() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.go12 != 0 {
		return
	}

	defer func() {
		// If we panic parsing, assume it's not a Go 1.2 symbol table.
		recover()
	}()

	// Check header: 4-byte magic, two zeros, pc quantum, pointer size.
	t.go12 = -1 // not Go 1.2 until proven otherwise
	if len(t.Data) < 16 || t.Data[4] != 0 || t.Data[5] != 0 ||
		(t.Data[6] != 1 && t.Data[6] != 2 && t.Data[6] != 4) || // pc quantum
		(t.Data[7] != 4 && t.Data[7] != 8) { // pointer size
		return
	}

	switch uint32(go12magic) {
	case binary.LittleEndian.Uint32(t.Data):
		t.binary = binary.LittleEndian
	case binary.BigEndian.Uint32(t.Data):
		t.binary = binary.BigEndian
	default:
		return
	}

	t.quantum = uint32(t.Data[6])
	t.ptrsize = uint32(t.Data[7])

	rest := t.Data[8:]

	t.nfunctab, rest = uint32(t.uintptr(rest)), rest[t.ptrsize:]
	functabsize := t.nfunctab*2*t.ptrsize + t.ptrsize
	t.functab = rest[:functabsize]
	fileoff := t.binary.Uint32(rest[functabsize:])
	t.filetab = t.Data[fileoff:]
	t.nfiletab = t.binary.Uint32(t.filetab)
	t.filetab = t.filetab[:t.nfiletab*4]

	t.go12 = 1 // so far so good
}

/*
From doc linked above:

        struct        Func
        {
                uintptr        entry;  // start pc
                int32 name;         // name (offset to C string)
                int32 args;         // size of arguments passed to function
                int32 frame;        // size of function frame, including saved caller PC
                int32        pcsp;                // pcsp table (offset to pcvalue table)
                int32        pcfile;          // pcfile table (offset to pcvalue table)
                int32        pcln;                  // pcln table (offset to pcvalue table)
                int32        nfuncdata;          // number of entries in funcdata list
                int32        npcdata;          // number of entries in pcdata list
        };
*/
type funcStruct struct {
	lt  *LineTable
	enc []byte
}

func (s funcStruct) entry() uint64 {
	return s.lt.uintptr(s.enc)
}

func (s funcStruct) field(n int) uint32 {
	return s.lt.binary.Uint32(s.enc[int(s.lt.ptrsize)+n*4:])
}

func (s funcStruct) OffName() uint32   { return s.field(0) }
func (s funcStruct) ArgSize() int      { return int(s.field(1)) }
func (s funcStruct) DeferReturn() int  { return int(s.field(2)) }
func (s funcStruct) OffPCSP() uint32   { return s.field(3) }
func (s funcStruct) OffPCFile() uint32 { return s.field(4) }
func (s funcStruct) OffPCLn() uint32   { return s.field(5) }
func (s funcStruct) NumPCData() int    { return int(s.field(6)) }
func (s funcStruct) FuncID() int       { return int(s.field(7) >> 24) }
func (s funcStruct) NumFuncData() int  { return int(s.field(7) & 255) }

// go12Funcs returns a slice of Funcs derived from the Go 1.2 pcln table.
func (t *LineTable) go12Funcs() []Func {
	// Assume it is malformed and return nil on error.
	defer func() {
		recover()
	}()

	n := len(t.functab) / int(t.ptrsize) / 2
	funcs := make([]Func, n)
	for i := range funcs {
		f := &funcs[i]
		f.Entry = t.uintptr(t.functab[2*i*int(t.ptrsize):])
		f.End = t.uintptr(t.functab[(2*i+2)*int(t.ptrsize):])

		fsOff := t.uintptr(t.functab[(2*i+1)*int(t.ptrsize):])
		f.OffFixedFunc = fsOff
		f.funcStructBytes = t.Data[fsOff:]

		fs := funcStruct{t, f.funcStructBytes}

		f.LineTable = t
		f.ArgSize = fs.ArgSize()
		f.NumPCData = fs.NumPCData()
		f.NumFuncData = fs.NumFuncData()
		f.OffPCSP = fs.OffPCSP()
		f.OffPCFile = fs.OffPCFile()
		f.OffPCLn = fs.OffPCLn()
		f.FuncID = fs.FuncID()
		f.Sym = &Sym{
			Value:  f.Entry,
			Type:   'T',
			Name:   t.string(fs.OffName()),
			GoType: 0,
			Func:   f,
		}
	}
	return funcs
}

// findFunc returns the func corresponding to the given program counter.
func (t *LineTable) findFunc(pc uint64) []byte {
	if pc < t.uintptr(t.functab) || pc >= t.uintptr(t.functab[len(t.functab)-int(t.ptrsize):]) {
		return nil
	}

	// The function table is a list of 2*nfunctab+1 uintptrs,
	// alternating program counters and offsets to func structures.
	f := t.functab
	nf := t.nfunctab
	for nf > 0 {
		m := nf / 2
		fm := f[2*t.ptrsize*m:]
		if t.uintptr(fm) <= pc && pc < t.uintptr(fm[2*t.ptrsize:]) {
			return t.Data[t.uintptr(fm[t.ptrsize:]):]
		} else if pc < t.uintptr(fm) {
			nf = m
		} else {
			f = f[(m+1)*2*t.ptrsize:]
			nf -= m + 1
		}
	}
	return nil
}

// readvarint reads, removes, and returns a varint from *pp.
func (t *LineTable) readvarint(pp *[]byte) uint32 {
	var v, shift uint32
	p := *pp
	for shift = 0; ; shift += 7 {
		b := p[0]
		p = p[1:]
		v |= (uint32(b) & 0x7F) << shift
		if b&0x80 == 0 {
			break
		}
	}
	*pp = p
	return v
}

// string returns a Go string found at off.
func (t *LineTable) string(off uint32) string {
	if s, ok := t.strings[off]; ok {
		return s
	}
	i := bytes.IndexByte(t.Data[off:], 0)
	s := string(t.Data[off : off+uint32(i)])
	t.strings[off] = s
	t.stringLen += int64(len(s))
	//log.Printf("string@%d = %q, sum %v", off, s, t.stringLen)
	return s
}

func (t *LineTable) StringAtOffset(off uint32) string { return t.string(off) }

func (t *LineTable) Uint32AtOffset(off uint32) uint32 {
	return t.binary.Uint32(t.Data[off:])
}

// step advances to the next pc, value pair in the encoded table.
func (t *LineTable) step(p *[]byte, pc *uint64, val *int32, first bool) bool {
	uvdelta := t.readvarint(p)
	if uvdelta == 0 && !first {
		return false
	}
	if uvdelta&1 != 0 {
		uvdelta = ^(uvdelta >> 1)
	} else {
		uvdelta >>= 1
	}
	vdelta := int32(uvdelta)
	pcdelta := t.readvarint(p) * t.quantum
	*pc += uint64(pcdelta)
	*val += vdelta
	return true
}

// pcvalue reports the value associated with the target pc.
// off is the offset to the beginning of the pc-value table,
// and entry is the start PC for the corresponding function.
func (t *LineTable) pcvalue(off uint32, entry, targetpc uint64) int32 {
	p := t.Data[off:]

	val := int32(-1)
	pc := entry
	for t.step(&p, &pc, &val, pc == entry) {
		if targetpc < pc {
			return val
		}
	}
	return -1
}

// findFileLine scans one function in the binary looking for a
// program counter in the given file on the given line.
// It does so by running the pc-value tables mapping program counter
// to file number. Since most functions come from a single file, these
// are usually short and quick to scan. If a file match is found, then the
// code goes to the expense of looking for a simultaneous line number match.
func (t *LineTable) findFileLine(entry uint64, filetab, linetab uint32, filenum, line int32) uint64 {
	if filetab == 0 || linetab == 0 {
		return 0
	}

	fp := t.Data[filetab:]
	fl := t.Data[linetab:]
	fileVal := int32(-1)
	filePC := entry
	lineVal := int32(-1)
	linePC := entry
	fileStartPC := filePC
	for t.step(&fp, &filePC, &fileVal, filePC == entry) {
		if fileVal == filenum && fileStartPC < filePC {
			// fileVal is in effect starting at fileStartPC up to
			// but not including filePC, and it's the file we want.
			// Run the PC table looking for a matching line number
			// or until we reach filePC.
			lineStartPC := linePC
			for linePC < filePC && t.step(&fl, &linePC, &lineVal, linePC == entry) {
				// lineVal is in effect until linePC, and lineStartPC < filePC.
				if lineVal == line {
					if fileStartPC <= lineStartPC {
						return lineStartPC
					}
					if fileStartPC < linePC {
						return fileStartPC
					}
				}
				lineStartPC = linePC
			}
		}
		fileStartPC = filePC
	}
	return 0
}

// go12PCToLine maps program counter to line number for the Go 1.2 pcln table.
func (t *LineTable) go12PCToLine(pc uint64) (line int) {
	defer func() {
		if recover() != nil {
			line = -1
		}
	}()

	f := t.findFunc(pc)
	if f == nil {
		return -1
	}
	entry := t.uintptr(f)
	linetab := t.binary.Uint32(f[t.ptrsize+5*4:])
	return int(t.pcvalue(linetab, entry, pc))
}

// pcToFile maps program counter to file name.
func (t *LineTable) pcToFile(pc uint64) (file string) {
	f := t.findFunc(pc)
	if f == nil {
		return ""
	}
	entry := t.uintptr(f)
	filetab := t.binary.Uint32(f[t.ptrsize+4*4:])
	fno := t.pcvalue(filetab, entry, pc)
	if fno <= 0 {
		return ""
	}
	return t.string(t.binary.Uint32(t.filetab[4*fno:]))
}

// File returns filename at index n in the file table.
func (t *LineTable) File(n int) string {
	return t.string(t.binary.Uint32(t.filetab[4*n:]))
}

// lineToPC maps a (file, line) pair to a program counter for the Go 1.2 pcln table.
func (t *LineTable) lineToPC(file string, line int) (pc uint64) {
	defer func() {
		if recover() != nil {
			pc = 0
		}
	}()

	t.initFileMap()
	filenum := t.fileMap[file]
	if filenum == 0 {
		return 0
	}

	// Scan all functions.
	// If this turns out to be a bottleneck, we could build a map[int32][]int32
	// mapping file number to a list of functions with code from that file.
	for i := uint32(0); i < t.nfunctab; i++ {
		f := t.Data[t.uintptr(t.functab[2*t.ptrsize*i+t.ptrsize:]):]
		entry := t.uintptr(f)
		filetab := t.binary.Uint32(f[t.ptrsize+4*4:])
		linetab := t.binary.Uint32(f[t.ptrsize+5*4:])
		pc := t.findFileLine(entry, filetab, linetab, int32(filenum), int32(line))
		if pc != 0 {
			return pc
		}
	}
	return 0
}

// initFileMap initializes the map from file name to file number.
func (t *LineTable) initFileMap() {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.fileMap != nil {
		return
	}
	m := make(map[string]uint32)

	for i := uint32(1); i < t.nfiletab; i++ {
		s := t.string(t.binary.Uint32(t.filetab[4*i:]))
		m[s] = i
	}
	t.fileMap = m
}

// go12MapFiles adds to m a key for every file in the Go 1.2 LineTable.
// Every key maps to obj. That's not a very interesting map, but it provides
// a way for callers to obtain the list of files in the program.
func (t *LineTable) go12MapFiles(m map[string]*Obj, obj *Obj) {
	t.initFileMap()
	for file := range t.fileMap {
		m[file] = obj
	}
}
