#!/usr/bin/bash

make -C tools/lkl CC="clang -emit-llvm -DNR_PAGEFLAGS=20 -DMAX_NR_ZONES=2" AR="./pseudo-ar.py" V=1
