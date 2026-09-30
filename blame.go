// Copyright 2020 Brad Fitzpatrick. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"container/heap"
	"sort"
)

// Blame describes why a range of bytes in a file exists.
type Blame struct {
	What string // kind of data: "text", "pcsp", "type", "symtab", "padding", etc.
	Name string // symbol, func, type or file name, if any
	Pkg  string // Go package path, if known
}

// Priority levels for spans. When spans overlap, the span with the
// higher level wins. Within a level, the smaller span wins.
const (
	levelFile    = iota // whole-file fallbacks
	levelSection        // sections, segments, and headers
	levelSymbol         // symbols from a symbol table
	levelStruct         // parsed runtime structures
	levelDetail         // finer breakdowns of parsed runtime structures
)

// span is a claim on a range of file bytes.
type span struct {
	off, size int64
	level     int8
	container bool // if true, unclaimed bytes are examined for padding
	blame     int32
	seq       int32 // insertion order, for tie breaking
}

// Segment is a resolved, non-overlapping range of the file.
type Segment struct {
	Off, Size int64
	Blame
}

// blameMap accumulates claims on file byte ranges and resolves them
// into a list of non-overlapping segments covering the whole file.
type blameMap struct {
	data   []byte // the whole file
	spans  []span
	blames []Blame
	idx    map[Blame]int32
	breaks map[int64]bool // offsets at which segments must not be merged
}

func newBlameMap(data []byte) *blameMap {
	return &blameMap{data: data, idx: make(map[Blame]int32), breaks: make(map[int64]bool)}
}

func (m *blameMap) intern(b Blame) int32 {
	if i, ok := m.idx[b]; ok {
		return i
	}
	i := int32(len(m.blames))
	m.blames = append(m.blames, b)
	m.idx[b] = i
	return i
}

// addBreak marks off as a boundary (such as the start or end of a
// section) across which resolved segments are never merged.
func (m *blameMap) addBreak(off int64) {
	m.breaks[off] = true
}

// add claims [off, off+size) at the given level.
// Ranges that extend beyond the file are clipped.
func (m *blameMap) add(level int8, off, size int64, b Blame) {
	m.addSpan(level, off, size, b, false)
}

// addContainer is like add, but marks the span as a container of
// other spans. Bytes of a container not claimed by any higher
// priority span are reported as padding if they're all the same
// filler byte.
func (m *blameMap) addContainer(level int8, off, size int64, b Blame) {
	m.addSpan(level, off, size, b, true)
}

func (m *blameMap) addSpan(level int8, off, size int64, b Blame, container bool) {
	if off < 0 {
		size += off
		off = 0
	}
	if end := int64(len(m.data)); off+size > end {
		size = end - off
	}
	if size <= 0 {
		return
	}
	m.spans = append(m.spans, span{
		off:       off,
		size:      size,
		level:     level,
		container: container,
		blame:     m.intern(b),
		seq:       int32(len(m.spans)),
	})
}

// beats reports whether a has priority over b.
func (a *span) beats(b *span) bool {
	if a.level != b.level {
		return a.level > b.level
	}
	if a.size != b.size {
		return a.size < b.size
	}
	return a.seq > b.seq
}

type spanHeap []*span

func (h spanHeap) Len() int           { return len(h) }
func (h spanHeap) Less(i, j int) bool { return h[i].beats(h[j]) }
func (h spanHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *spanHeap) Push(x any)        { *h = append(*h, x.(*span)) }
func (h *spanHeap) Pop() any {
	old := *h
	x := old[len(old)-1]
	*h = old[:len(old)-1]
	return x
}

// resolve returns non-overlapping segments covering every byte of the
// file, in file order.
func (m *blameMap) resolve() []Segment {
	fileSize := int64(len(m.data))
	spans := make([]*span, len(m.spans))
	for i := range m.spans {
		spans[i] = &m.spans[i]
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].off < spans[j].off })

	// Collect the boundary points: every span start and end.
	points := make([]int64, 0, 2*len(spans)+2)
	points = append(points, 0, fileSize)
	for _, s := range spans {
		points = append(points, s.off, s.off+s.size)
	}
	for off := range m.breaks {
		if off >= 0 && off <= fileSize {
			points = append(points, off)
		}
	}
	sort.Slice(points, func(i, j int) bool { return points[i] < points[j] })

	var segs []Segment
	emit := func(off, size int64, s *span) {
		var b Blame
		switch {
		case s == nil:
			b = Blame{What: "unknown"}
			if isFill(m.data[off : off+size]) {
				b.What = "padding"
			}
		case s.container:
			b = m.blames[s.blame]
			if isFill(m.data[off : off+size]) {
				b = Blame{What: "padding"}
			}
		default:
			b = m.blames[s.blame]
		}
		if n := len(segs); n > 0 && segs[n-1].Blame == b && segs[n-1].Off+segs[n-1].Size == off && !m.breaks[off] {
			segs[n-1].Size += size
			return
		}
		segs = append(segs, Segment{Off: off, Size: size, Blame: b})
	}

	var h spanHeap
	next := 0 // index into spans of next span to activate
	for pi := 0; pi < len(points)-1; pi++ {
		p, q := points[pi], points[pi+1]
		if p == q {
			continue
		}
		for next < len(spans) && spans[next].off <= p {
			heap.Push(&h, spans[next])
			next++
		}
		for len(h) > 0 && h[0].off+h[0].size <= p {
			heap.Pop(&h)
		}
		var top *span
		if len(h) > 0 {
			top = h[0]
		}
		// The winner can only change at a boundary point, but a
		// container's padding detection needs to look at the
		// actual bytes, so emit per boundary interval and let emit
		// merge adjacent identical segments.
		emit(p, q-p, top)
	}
	return segs
}

// isFill reports whether b consists of a single repeated padding byte
// (0x00 or the x86 INT3 0xCC).
func isFill(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	c := b[0]
	if c != 0 && c != 0xcc {
		return false
	}
	for _, x := range b {
		if x != c {
			return false
		}
	}
	return true
}
