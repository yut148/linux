#!/usr/bin/env bash

make -C tools/lkl CC="emcc -m32 -s EMULATE_FUNCTION_POINTER_CASTS=1 -I./arch/lkl/include -DMAX_NR_ZONES=2 -DNR_PAGEFLAGS=20 -DSPINLOCK_SIZE=0 -DF_GETLK64=12 -DF_SETLK64=13 -DF_SETLKW64=14 -fshort-wchar" AR="python ar.py" V=1
