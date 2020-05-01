# Shotizam

Shotizam analyzes the size of Go binaries and outputs SQL with size
info for analyis in SQLite3.

```
$ shotizam --sqlite /some/go.binary
SQLite version 3.28.0 2019-04-15 14:49:49
Enter ".help" for usage hints.
sqlite> .width 40
sqlite> .mode column

sqlite> select func, sum(size) from bin where func <> '' group by 1 order by 2 desc limit 20;
unicode.init                              21528
debug/dwarf.init                          13764
fmt.(*pp).printValue                      11941
debug/macho.NewFile                       10017
time.Time.AppendFormat                    9949
runtime.gentraceback                      8278
debug/elf.NewFile                         7631
runtime.selectgo                          6722
encoding/binary.Read                      6555
main.main                                 6476
internal/fmtsort.compare                  6373
time.LoadLocationFromTZData               5795
fmt.(*pp).doPrintf                        5520
runtime.findrunnable                      5287
runtime.typesEqual                        4843
time.nextStdChunk                         4736
time.ParseDuration                        4440
time.loadTzinfoFromZip                    4234
runtime.(*pageAlloc).find                 4109
runtime.heapBitsSetType                   3938

sqlite> select what, sum(size) from bin group by 1;
TODO                                      1370985
fixedheader                               101800
funcdata                                  99656
funcname                                  63062
pcdata0-regmap                            54361
pcdata1-stackmap                          47977
pcdata2-inltree                           40024
pcfile                                    38544
pcln                                      141103
pcsp                                      36478
text                                      896722

sqlite> select pkg, sum(size) from bin where pkg <> '' group by 1 order by 2 desc limit 20;
runtime               621236
reflect               187926
fmt                   61727
time                  58786
strconv               55817
syscall               39481
debug/elf             37070
os                    36707
compress/flate        31462
debug/macho           27117
encoding/binary       26637
os/exec               26599
internal/reflectlite  23687
unicode               22316
sync                  21322
flag                  20871
debug/dwarf           17692
internal/poll         17092
strings               15511
sort                  14992

sqlite> select func, length(func) from bin order by 2 desc limit 5;
type..eq.[67]struct { runtime.size uint3  89
type..eq.[67]struct { runtime.size uint3  89
type..eq.[67]struct { runtime.size uint3  89
type..eq.[67]struct { runtime.size uint3  89
type..eq.[67]struct { runtime.size uint3  89

sqlite> select func, sum(size) from bin where what = 'pcfile' and func <> '' group by 1 order by 2 desc limit 20;
internal/fmtsort.compare                  268
fmt.(*pp).printValue                      227
encoding/binary.Read                      195
os.Getwd                                  174
runtime.sighandler                        172
runtime.(*pageAlloc).scavengeOne          153
runtime.findrunnable                      148
debug/macho.NewFile                       131
runtime.selectgo                          130
syscall.forkAndExecInChild                129
main.main                                 123
runtime.(*mspan).sweep                    123
internal/fmtsort.nilCompare               119
runtime.growslice                         119
debug/elf.NewFile                         112
fmt.intFromArg                            107
runtime.greyobject                        105
runtime.evacuate_fast64                   103
runtime.mapaccess2_faststr                101
runtime.evacuate                          99

sqlite> select func, sum(size) from bin where what = 'pcln' and func <> '' group by 1 order by 2 desc limit 20;
time.Time.AppendFormat                    1347
runtime.gentraceback                      1132
runtime.selectgo                          1102
fmt.(*pp).printValue                      1027
runtime.findrunnable                      830
runtime.heapBitsSetType                   794
internal/fmtsort.compare                  720
runtime.memmove                           720
debug/macho.NewFile                       692
fmt.(*pp).doPrintf                        638
encoding/binary.Read                      616
runtime.runGCProg                         613
syscall.forkAndExecInChild                552
debug/elf.NewFile                         539
runtime.mallocgc                          532
time.LoadLocationFromTZData               530
runtime.duffcopy                          528
aeshashbody                               518
runtime.(*mspan).sweep                    502
runtime.sighandler                        478

sqlite> select * from bin limit 30;
go.buildid                                            fixedheader  40
go.buildid                                            text         112
go.buildid                                            funcname     11
internal/cpu.Initialize                   internal/c  fixedheader  40
internal/cpu.Initialize                   internal/c  pcsp         13
internal/cpu.Initialize                   internal/c  pcfile       5
internal/cpu.Initialize                   internal/c  pcln         21
internal/cpu.Initialize                   internal/c  pcdata0-reg  22
internal/cpu.Initialize                   internal/c  pcdata1-sta  21
internal/cpu.Initialize                   internal/c  text         80
internal/cpu.Initialize                   internal/c  funcname     24
internal/cpu.processOptions               internal/c  fixedheader  40
internal/cpu.processOptions               internal/c  pcsp         24
internal/cpu.processOptions               internal/c  pcfile       6
internal/cpu.processOptions               internal/c  pcln         167
internal/cpu.processOptions               internal/c  pcdata0-reg  30
internal/cpu.processOptions               internal/c  pcdata1-sta  60
internal/cpu.processOptions               internal/c  text         1792
internal/cpu.processOptions               internal/c  funcname     28
internal/cpu.indexByte                    internal/c  fixedheader  40
internal/cpu.indexByte                    internal/c  pcsp         9
internal/cpu.indexByte                    internal/c  pcfile       5
internal/cpu.indexByte                    internal/c  pcln         21
internal/cpu.indexByte                    internal/c  pcdata0-reg  22
internal/cpu.indexByte                    internal/c  text         64
internal/cpu.indexByte                    internal/c  funcname     23
internal/cpu.doinit                       internal/c  fixedheader  40
internal/cpu.doinit                       internal/c  pcsp         22
internal/cpu.doinit                       internal/c  pcfile       5
internal/cpu.doinit                       internal/c  pcln         159
```

etc

For fun bugs to make Go smaller, see https://github.com/golang/go/labels/binary-size
