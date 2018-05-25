#!/usr/bin/env bash

llvm-link -o tools/lkl/tests/boot.bc tools/lkl/tests/boot-in.o tools/lkl/lib/liblkl-in.o tools/lkl/lib/lkl.o
llvm-dis -o tools/lkl/tests/boot.ll tools/lkl/tests/boot.bc
cat tools/lkl/tests/boot.ll | sed s/\"wchar_size\",\ i32\ 2/\"wchar_size\",\ i32\ 4/g > tools/lkl/tests/boot-mod.ll
mkdir -p js
cp ~/.emscripten_cache/asmjs/dlmalloc.bc js/dlmalloc.bc
cp ~/.emscripten_cache/asmjs/libc.bc js/libc.bc
llvm-dis -o js/dlmalloc.ll js/dlmalloc.bc
llvm-dis -o js/libc.ll js/libc.bc
python rename_symbols.py tools/lkl/tests/boot-mod.ll tools/lkl/tests/boot-mod2.ll
EMCC_DEBUG=1 emcc -o tools/lkl/tests/boot.js tools/lkl/tests/boot.bc -v
