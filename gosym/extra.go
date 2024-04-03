package gosym

import (
	"encoding/binary"
	"log"
)

func (t *Table) PtrSize() int { return int(t.lt.ptrsize) }

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
	data := f.LineTable.pctab[off:]
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
