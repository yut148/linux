#ifndef _ASM_UAPI_LKL_BITSPERLONG_H
#define _ASM_UAPI_LKL_BITSPERLONG_H

/*
#ifdef CONFIG_64BIT
#define __BITS_PER_LONG 64
#else
#define __BITS_PER_LONG 32
#endif
*/

/* for emscripten */
#define __BITS_PER_LONG 32

#define BITS_PER_LONG __BITS_PER_LONG

#define __ARCH_WANT_STAT64

#endif /* _ASM_UAPI_LKL_BITSPERLONG_H */
