# Shotizam

Shotizam analyzes the size of Go binaries and outputs SQL with size
info for analysis in SQLite3.

It tries to blame every byte of the file on something: a function's
code, its pclntab metadata (name, line tables, stack maps, inline
trees, ...), a type descriptor or its names, an itab, a string
literal, a symbol table entry, a DWARF entry, a relocation, alignment
padding, and so on. Bytes it can't explain are reported with
`What = 'unknown'`, and the rows always sum to the file size.

It supports ELF, Mach-O, and PE binaries built by Go 1.18+ (with the
most detail for recent versions), and the `go.o` in
`-buildmode=c-archive` archives (currently with less detail; see
below).

```
$ shotizam --sqlite ./tailscaled
SQLite version 3.45.1 2024-01-30 16:01:20
sqlite> .mode column
sqlite> .header on
sqlite> select Pkg, sum(Size) as Size from Bin group by 1 order by 2 desc limit 10;
Pkg                                        Size
-----------------------------------------  -------
runtime                                    1943968
tailscale.com/ipn/ipnlocal                 1507000
slices                                     1038671
crypto/tls                                 905922
net/http                                   872956
gvisor.dev/gvisor/pkg/tcpip/stack          844967
tailscale.com/wgengine/magicsock           805350
                                           669393
net/http/internal/http2                    664623
gvisor.dev/gvisor/pkg/tcpip/transport/tcp  619046

sqlite> select What, sum(Size) as Size from Bin group by 1 order by 2 desc limit 20;
What              Size
----------------  --------
text              13273450
dwarf-info        4335715
type              2700976
dwarf-line        2645530
dwarf-loclists    2259217
funcname          2170056
strtab            2037299
pcln              1487536
_func             1350360
funcdata-inltree  1283040
symtab            937680
dwarf-rnglists    858863
_func-funcdata    813424
type-name         806690
string            693544
padding           587424
dwarf-frame       503456
_func-pcdata      464612
pcdata-inltree    449397
pcsp              447611

sqlite> select What, sum(Size) as Size from Bin where Pkg = 'tailscale.com/wgengine/magicsock' group by 1 order by 2 desc limit 5;
What              Size
----------------  ------
text              286206
dwarf-info        66018
dwarf-line        48231
strtab            44852
type              42920

sqlite> select Section, What, Name, Size from Bin where Off <= 20000000 and Off+Size > 20000000;
Section     What  Name                                                      Size
----------  ----  --------------------------------------------------------  ----
.gopclntab  pcln  tailscale.com/ipn/ipnlocal.(*LocalBackend).ReadRouteInfo  29
```

Use `-mode=summary` for a quick breakdown by section and by What
without SQLite.

## Schema

```sql
CREATE TABLE Bin (Off int64, Size int64, Section varchar, What varchar, Name varchar, Pkg varchar);
CREATE TABLE Fixup (Addr int64, Section varchar, What varchar, Name varchar, Pkg varchar);
```

Each `Bin` row is a contiguous range of the file:

* `Off`, `Size`: the file offset and size of the range.
* `Section`: the section containing it, like `.text` or
  `__TEXT,__gopclntab`, or a pseudo-section like `(elf-header)` or
  `__LINKEDIT,rebase`.
* `What`: what kind of bytes they are. See below.
* `Name`: the function, symbol, type, file, or DWARF entry the bytes
  are for, if any.
* `Pkg`: the Go package to blame, if known.

Each `Fixup` row is a pointer that the dynamic loader adjusts at
startup (ELF `R_*_RELATIVE` relocations, Mach-O rebases, PE base
relocations), blamed on whatever owns the pointer. On iOS, where
the memory limit for network extensions was once 15 MB, these pages
become dirty and count against you. See
https://tailscale.com/blog/go-linker.

```
sqlite> select count(*) as Fixups, count(*)*8 as Bytes from Fixup;
Fixups  Bytes
------  -------
126518  1012144
sqlite> select What, count(*) as N from Fixup group by 1 order by 2 desc limit 3;
What       N
---------  -----
type       89573
rodata     19887
data       7283
```

## What

The main values of `What`:

* `text`: machine code of the func or symbol `Name`.
* `padding`: alignment padding (runs of 0x00 or 0xCC not covered by
  anything else).
* pclntab: `pcheader`, `funcname`, `cutab`, `filename`, `functab`,
  `_func` (the fixed part of the runtime's `_func` struct),
  `_func-pcdata` and `_func-funcdata` (its table offsets), the pcvalue
  tables `pcsp`, `pcfile`, `pcln`, and `pcdata-*`, the funcdata
  (`funcdata-*`, such as stack maps and inline trees), and
  `findfunctab`.
* Types: `type` (type descriptors, including their method, field,
  and parameter tables), `type-name` (names of types, fields, and
  methods), `type-pkgpath`, `gcbits`, and `itab`.
* `string`: string literal data, blamed on the first function (or
  data symbol) that references it.
* `rodata-ref`, `data-ref`, `noptrdata-ref`: data without a symbol of
  its own (compiler-generated statics, `//go:embed` data, etc.),
  blamed on the first function or data that references it.
* `funcdesc`: the `·f` func values for top-level functions.
* `rodata`, `data`, `noptrdata`, ...: data symbols, named after
  their section.
* `symtab`, `strtab`, `dynsym`, `dynstr`, `reloc`, `rebase`, `bind`,
  `code_signature`, `pdata`, ...: symbol tables, relocations, and
  other linker and loader metadata, blamed on the symbol or code they
  describe where possible.
* `dwarf-info`, `dwarf-line`, `dwarf-loclists`, `dwarf-rnglists`,
  `dwarf-loc`, `dwarf-ranges`, `dwarf-frame`, `dwarf-addr`, ...: DWARF,
  per top-level DIE (func, type, or variable), per compile unit, or
  per function. Use `-nodwarf` to skip breaking these down.
* `elf-header`, `elf-phdr`, `elf-shdr`, `macho-header`,
  `macho-loadcmd`, `pe-header`, ...: file format headers.
* `moduledata`, `buildinfo`, and so on for other runtime structures.

## Caveats

* The linker deduplicates identical pcvalue tables, funcdata, and
  names. Shared data is blamed on the first function or type that
  uses it.
* DWARF sections are usually compressed. Their compressed bytes are
  mapped back to DWARF entries by tracking how much input the
  decompressor consumes, so the per-entry sizes are approximate
  (though they always sum correctly).
* `string` and `*-ref` attribution comes from scanning machine code
  (amd64 and arm64) for references to data, and scanning data for
  pointers. It's a heuristic.
* For relocatable objects (the `go.o` in a c-archive), only the
  file structure, sections, and symbols are broken down so far, as
  the Go runtime structures' pointers aren't relocated yet.

## JSON diffs

`-mode=json` writes the sizes aggregated by (Section, What, Name,
Pkg). Use `-base=old.json` to write the difference from a previous
run instead:

```
$ shotizam -mode=json old-binary > old.json
$ shotizam -mode=json -base=old.json new-binary
```

For fun bugs to make Go smaller, see https://github.com/golang/go/labels/binary-size
