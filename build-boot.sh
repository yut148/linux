#!/usr/bin/env bash

echo "LINK boot.bc"
llvm-link -o tools/lkl/tests/boot.bc tools/lkl/tests/boot-in.o tools/lkl/lib/liblkl-in.o tools/lkl/lib/lkl.o
echo "DIS boot.bc"
llvm-dis -o tools/lkl/tests/boot.ll tools/lkl/tests/boot.bc
echo "SED wchar_size"
cat tools/lkl/tests/boot.ll | sed s/\"wchar_size\",\ i32\ 2/\"wchar_size\",\ i32\ 4/g > tools/lkl/tests/boot-mod.ll
mkdir -p js
cp ~/.emscripten_cache/asmjs/dlmalloc.bc js/dlmalloc.bc
cp ~/.emscripten_cache/asmjs/libc.bc js/libc.bc
echo "DIS dlmalloc.bc"
llvm-dis -o js/dlmalloc.ll js/dlmalloc.bc
echo "DIS libc.bc"
llvm-dis -o js/libc.ll js/libc.bc
echo "PY rename_symbols.py"
python rename_symbols.py tools/lkl/tests/boot-mod.ll tools/lkl/tests/boot-mod2.ll
echo "EMCC boot.js"
EMCC_DEBUG=1 emcc -o tools/lkl/tests/boot.js tools/lkl/tests/boot-mod2.ll -s EMULATE_FUNCTION_POINTER_CASTS=1 -s PTHREAD_POOL_SIZE=2 -s USE_PTHREADS=1 -v
