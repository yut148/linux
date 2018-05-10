#include <asm/types.h>
#include <asm/unistd.h>

/* *at */
#define __IGNORE_open		/* openat */
#define __IGNORE_link		/* linkat */
#define __IGNORE_unlink		/* unlinkat */
#define __IGNORE_mknod		/* mknodat */
#define __IGNORE_chmod		/* fchmodat */
#define __IGNORE_chown		/* fchownat */
#define __IGNORE_mkdir		/* mkdirat */
#define __IGNORE_rmdir		/* unlinkat */
#define __IGNORE_lchown		/* fchownat */
#define __IGNORE_access		/* faccessat */
#define __IGNORE_rename		/* renameat2 */
#define __IGNORE_readlink	/* readlinkat */
#define __IGNORE_symlink	/* symlinkat */
#define __IGNORE_utimes		/* futimesat */
#if BITS_PER_LONG == 64
#define __IGNORE_stat		/* fstatat */
#define __IGNORE_lstat		/* fstatat */
#else
#define __IGNORE_stat64		/* fstatat64 */
#define __IGNORE_lstat64	/* fstatat64 */
#endif

/* Missing flags argument */
#define __IGNORE_renameat	/* renameat2 */

/* CLOEXEC flag */
#define __IGNORE_pipe		/* pipe2 */
#define __IGNORE_dup2		/* dup3 */
#define __IGNORE_epoll_create	/* epoll_create1 */
#define __IGNORE_inotify_init	/* inotify_init1 */
#define __IGNORE_eventfd	/* eventfd2 */
#define __IGNORE_signalfd	/* signalfd4 */

/* MMU */
#ifndef CONFIG_MMU
#define __IGNORE_madvise
#define __IGNORE_mbind
#define __IGNORE_mincore
#define __IGNORE_mlock
#define __IGNORE_mlockall
#define __IGNORE_munlock
#define __IGNORE_munlockall
#define __IGNORE_mprotect
#define __IGNORE_msync
#define __IGNORE_migrate_pages
#define __IGNORE_move_pages
#define __IGNORE_remap_file_pages
#define __IGNORE_get_mempolicy
#define __IGNORE_set_mempolicy
#define __IGNORE_swapoff
#define __IGNORE_swapon
#endif

/* System calls for 32-bit kernels only */
#if BITS_PER_LONG == 64
#define __IGNORE_sendfile64
#define __IGNORE_ftruncate64
#define __IGNORE_truncate64
#define __IGNORE_stat64
#define __IGNORE_lstat64
#define __IGNORE_fstat64
#define __IGNORE_fcntl64
#define __IGNORE_fadvise64_64
#define __IGNORE_fstatat64
#define __IGNORE_fstatfs64
#define __IGNORE_statfs64
#define __IGNORE_llseek
#define __IGNORE_mmap2
#else
#define __IGNORE_sendfile
#define __IGNORE_ftruncate
#define __IGNORE_truncate
#define __IGNORE_stat
#define __IGNORE_lstat
#define __IGNORE_fstat
#define __IGNORE_fcntl
#define __IGNORE_fadvise64
#define __IGNORE_newfstatat
#define __IGNORE_fstatfs
#define __IGNORE_statfs
#define __IGNORE_lseek
#define __IGNORE_mmap
#endif

/* i386-specific or historical system calls */
#define __IGNORE_break
#define __IGNORE_stty
#define __IGNORE_gtty
#define __IGNORE_ftime
#define __IGNORE_prof
#define __IGNORE_lock
#define __IGNORE_mpx
#define __IGNORE_ulimit
#define __IGNORE_profil
#define __IGNORE_ioperm
#define __IGNORE_iopl
#define __IGNORE_idle
#define __IGNORE_modify_ldt
#define __IGNORE_ugetrlimit
#define __IGNORE_vm86
#define __IGNORE_vm86old
#define __IGNORE_set_thread_area
#define __IGNORE_get_thread_area
#define __IGNORE_madvise1
#define __IGNORE_oldstat
#define __IGNORE_oldfstat
#define __IGNORE_oldlstat
#define __IGNORE_oldolduname
#define __IGNORE_olduname
#define __IGNORE_umount
#define __IGNORE_waitpid
#define __IGNORE_stime
#define __IGNORE_nice
#define __IGNORE_signal
#define __IGNORE_sigaction
#define __IGNORE_sgetmask
#define __IGNORE_sigsuspend
#define __IGNORE_sigpending
#define __IGNORE_ssetmask
#define __IGNORE_readdir
#define __IGNORE_socketcall
#define __IGNORE_ipc
#define __IGNORE_sigreturn
#define __IGNORE_sigprocmask
#define __IGNORE_bdflush
#define __IGNORE__llseek
#define __IGNORE__newselect
#define __IGNORE_create_module
#define __IGNORE_query_module
#define __IGNORE_get_kernel_syms
#define __IGNORE_sysfs
#define __IGNORE_uselib
#define __IGNORE__sysctl
#define __IGNORE_arch_prctl

/* ... including the "new" 32-bit uid syscalls */
#define __IGNORE_lchown32
#define __IGNORE_getuid32
#define __IGNORE_getgid32
#define __IGNORE_geteuid32
#define __IGNORE_getegid32
#define __IGNORE_setreuid32
#define __IGNORE_setregid32
#define __IGNORE_getgroups32
#define __IGNORE_setgroups32
#define __IGNORE_fchown32
#define __IGNORE_setresuid32
#define __IGNORE_getresuid32
#define __IGNORE_setresgid32
#define __IGNORE_getresgid32
#define __IGNORE_chown32
#define __IGNORE_setuid32
#define __IGNORE_setgid32
#define __IGNORE_setfsuid32
#define __IGNORE_setfsgid32

/* these can be expressed using other calls */
#define __IGNORE_alarm		/* setitimer */
#define __IGNORE_creat		/* open */
#define __IGNORE_fork		/* clone */
#define __IGNORE_futimesat	/* utimensat */
#define __IGNORE_getpgrp	/* getpgid */
#define __IGNORE_getdents	/* getdents64 */
#define __IGNORE_pause		/* sigsuspend */
#define __IGNORE_poll		/* ppoll */
#define __IGNORE_select		/* pselect6 */
#define __IGNORE_epoll_wait	/* epoll_pwait */
#define __IGNORE_time		/* gettimeofday */
#define __IGNORE_uname		/* newuname */
#define __IGNORE_ustat		/* statfs */
#define __IGNORE_utime		/* utimes */
#define __IGNORE_vfork		/* clone */

/* sync_file_range had a stupid ABI. Allow sync_file_range2 instead */
#ifdef __NR_sync_file_range2
#define __IGNORE_sync_file_range
#endif

/* Unmerged syscalls for AFS, STREAMS, etc. */
#define __IGNORE_afs_syscall
#define __IGNORE_getpmsg
#define __IGNORE_putpmsg
#define __IGNORE_vserver
#if !defined(__NR_restart_syscall) && !defined(__IGNORE_restart_syscall)
#warning syscall restart_syscall not implemented
#endif
#if !defined(__NR_exit) && !defined(__IGNORE_exit)
#warning syscall exit not implemented
#endif
#if !defined(__NR_fork) && !defined(__IGNORE_fork)
#warning syscall fork not implemented
#endif
#if !defined(__NR_read) && !defined(__IGNORE_read)
#warning syscall read not implemented
#endif
#if !defined(__NR_write) && !defined(__IGNORE_write)
#warning syscall write not implemented
#endif
#if !defined(__NR_open) && !defined(__IGNORE_open)
#warning syscall open not implemented
#endif
#if !defined(__NR_close) && !defined(__IGNORE_close)
#warning syscall close not implemented
#endif
#if !defined(__NR_waitpid) && !defined(__IGNORE_waitpid)
#warning syscall waitpid not implemented
#endif
#if !defined(__NR_creat) && !defined(__IGNORE_creat)
#warning syscall creat not implemented
#endif
#if !defined(__NR_link) && !defined(__IGNORE_link)
#warning syscall link not implemented
#endif
#if !defined(__NR_unlink) && !defined(__IGNORE_unlink)
#warning syscall unlink not implemented
#endif
#if !defined(__NR_execve) && !defined(__IGNORE_execve)
#warning syscall execve not implemented
#endif
#if !defined(__NR_chdir) && !defined(__IGNORE_chdir)
#warning syscall chdir not implemented
#endif
#if !defined(__NR_time) && !defined(__IGNORE_time)
#warning syscall time not implemented
#endif
#if !defined(__NR_mknod) && !defined(__IGNORE_mknod)
#warning syscall mknod not implemented
#endif
#if !defined(__NR_chmod) && !defined(__IGNORE_chmod)
#warning syscall chmod not implemented
#endif
#if !defined(__NR_lchown) && !defined(__IGNORE_lchown)
#warning syscall lchown not implemented
#endif
#if !defined(__NR_break) && !defined(__IGNORE_break)
#warning syscall break not implemented
#endif
#if !defined(__NR_oldstat) && !defined(__IGNORE_oldstat)
#warning syscall oldstat not implemented
#endif
#if !defined(__NR_lseek) && !defined(__IGNORE_lseek)
#warning syscall lseek not implemented
#endif
#if !defined(__NR_getpid) && !defined(__IGNORE_getpid)
#warning syscall getpid not implemented
#endif
#if !defined(__NR_mount) && !defined(__IGNORE_mount)
#warning syscall mount not implemented
#endif
#if !defined(__NR_umount) && !defined(__IGNORE_umount)
#warning syscall umount not implemented
#endif
#if !defined(__NR_setuid) && !defined(__IGNORE_setuid)
#warning syscall setuid not implemented
#endif
#if !defined(__NR_getuid) && !defined(__IGNORE_getuid)
#warning syscall getuid not implemented
#endif
#if !defined(__NR_stime) && !defined(__IGNORE_stime)
#warning syscall stime not implemented
#endif
#if !defined(__NR_ptrace) && !defined(__IGNORE_ptrace)
#warning syscall ptrace not implemented
#endif
#if !defined(__NR_alarm) && !defined(__IGNORE_alarm)
#warning syscall alarm not implemented
#endif
#if !defined(__NR_oldfstat) && !defined(__IGNORE_oldfstat)
#warning syscall oldfstat not implemented
#endif
#if !defined(__NR_pause) && !defined(__IGNORE_pause)
#warning syscall pause not implemented
#endif
#if !defined(__NR_utime) && !defined(__IGNORE_utime)
#warning syscall utime not implemented
#endif
#if !defined(__NR_stty) && !defined(__IGNORE_stty)
#warning syscall stty not implemented
#endif
#if !defined(__NR_gtty) && !defined(__IGNORE_gtty)
#warning syscall gtty not implemented
#endif
#if !defined(__NR_access) && !defined(__IGNORE_access)
#warning syscall access not implemented
#endif
#if !defined(__NR_nice) && !defined(__IGNORE_nice)
#warning syscall nice not implemented
#endif
#if !defined(__NR_ftime) && !defined(__IGNORE_ftime)
#warning syscall ftime not implemented
#endif
#if !defined(__NR_sync) && !defined(__IGNORE_sync)
#warning syscall sync not implemented
#endif
#if !defined(__NR_kill) && !defined(__IGNORE_kill)
#warning syscall kill not implemented
#endif
#if !defined(__NR_rename) && !defined(__IGNORE_rename)
#warning syscall rename not implemented
#endif
#if !defined(__NR_mkdir) && !defined(__IGNORE_mkdir)
#warning syscall mkdir not implemented
#endif
#if !defined(__NR_rmdir) && !defined(__IGNORE_rmdir)
#warning syscall rmdir not implemented
#endif
#if !defined(__NR_dup) && !defined(__IGNORE_dup)
#warning syscall dup not implemented
#endif
#if !defined(__NR_pipe) && !defined(__IGNORE_pipe)
#warning syscall pipe not implemented
#endif
#if !defined(__NR_times) && !defined(__IGNORE_times)
#warning syscall times not implemented
#endif
#if !defined(__NR_prof) && !defined(__IGNORE_prof)
#warning syscall prof not implemented
#endif
#if !defined(__NR_brk) && !defined(__IGNORE_brk)
#warning syscall brk not implemented
#endif
#if !defined(__NR_setgid) && !defined(__IGNORE_setgid)
#warning syscall setgid not implemented
#endif
#if !defined(__NR_getgid) && !defined(__IGNORE_getgid)
#warning syscall getgid not implemented
#endif
#if !defined(__NR_signal) && !defined(__IGNORE_signal)
#warning syscall signal not implemented
#endif
#if !defined(__NR_geteuid) && !defined(__IGNORE_geteuid)
#warning syscall geteuid not implemented
#endif
#if !defined(__NR_getegid) && !defined(__IGNORE_getegid)
#warning syscall getegid not implemented
#endif
#if !defined(__NR_acct) && !defined(__IGNORE_acct)
#warning syscall acct not implemented
#endif
#if !defined(__NR_umount2) && !defined(__IGNORE_umount2)
#warning syscall umount2 not implemented
#endif
#if !defined(__NR_lock) && !defined(__IGNORE_lock)
#warning syscall lock not implemented
#endif
#if !defined(__NR_ioctl) && !defined(__IGNORE_ioctl)
#warning syscall ioctl not implemented
#endif
#if !defined(__NR_fcntl) && !defined(__IGNORE_fcntl)
#warning syscall fcntl not implemented
#endif
#if !defined(__NR_mpx) && !defined(__IGNORE_mpx)
#warning syscall mpx not implemented
#endif
#if !defined(__NR_setpgid) && !defined(__IGNORE_setpgid)
#warning syscall setpgid not implemented
#endif
#if !defined(__NR_ulimit) && !defined(__IGNORE_ulimit)
#warning syscall ulimit not implemented
#endif
#if !defined(__NR_oldolduname) && !defined(__IGNORE_oldolduname)
#warning syscall oldolduname not implemented
#endif
#if !defined(__NR_umask) && !defined(__IGNORE_umask)
#warning syscall umask not implemented
#endif
#if !defined(__NR_chroot) && !defined(__IGNORE_chroot)
#warning syscall chroot not implemented
#endif
#if !defined(__NR_ustat) && !defined(__IGNORE_ustat)
#warning syscall ustat not implemented
#endif
#if !defined(__NR_dup2) && !defined(__IGNORE_dup2)
#warning syscall dup2 not implemented
#endif
#if !defined(__NR_getppid) && !defined(__IGNORE_getppid)
#warning syscall getppid not implemented
#endif
#if !defined(__NR_getpgrp) && !defined(__IGNORE_getpgrp)
#warning syscall getpgrp not implemented
#endif
#if !defined(__NR_setsid) && !defined(__IGNORE_setsid)
#warning syscall setsid not implemented
#endif
#if !defined(__NR_sigaction) && !defined(__IGNORE_sigaction)
#warning syscall sigaction not implemented
#endif
#if !defined(__NR_sgetmask) && !defined(__IGNORE_sgetmask)
#warning syscall sgetmask not implemented
#endif
#if !defined(__NR_ssetmask) && !defined(__IGNORE_ssetmask)
#warning syscall ssetmask not implemented
#endif
#if !defined(__NR_setreuid) && !defined(__IGNORE_setreuid)
#warning syscall setreuid not implemented
#endif
#if !defined(__NR_setregid) && !defined(__IGNORE_setregid)
#warning syscall setregid not implemented
#endif
#if !defined(__NR_sigsuspend) && !defined(__IGNORE_sigsuspend)
#warning syscall sigsuspend not implemented
#endif
#if !defined(__NR_sigpending) && !defined(__IGNORE_sigpending)
#warning syscall sigpending not implemented
#endif
#if !defined(__NR_sethostname) && !defined(__IGNORE_sethostname)
#warning syscall sethostname not implemented
#endif
#if !defined(__NR_setrlimit) && !defined(__IGNORE_setrlimit)
#warning syscall setrlimit not implemented
#endif
#if !defined(__NR_getrlimit) && !defined(__IGNORE_getrlimit)
#warning syscall getrlimit not implemented
#endif
#if !defined(__NR_getrusage) && !defined(__IGNORE_getrusage)
#warning syscall getrusage not implemented
#endif
#if !defined(__NR_gettimeofday) && !defined(__IGNORE_gettimeofday)
#warning syscall gettimeofday not implemented
#endif
#if !defined(__NR_settimeofday) && !defined(__IGNORE_settimeofday)
#warning syscall settimeofday not implemented
#endif
#if !defined(__NR_getgroups) && !defined(__IGNORE_getgroups)
#warning syscall getgroups not implemented
#endif
#if !defined(__NR_setgroups) && !defined(__IGNORE_setgroups)
#warning syscall setgroups not implemented
#endif
#if !defined(__NR_select) && !defined(__IGNORE_select)
#warning syscall select not implemented
#endif
#if !defined(__NR_symlink) && !defined(__IGNORE_symlink)
#warning syscall symlink not implemented
#endif
#if !defined(__NR_oldlstat) && !defined(__IGNORE_oldlstat)
#warning syscall oldlstat not implemented
#endif
#if !defined(__NR_readlink) && !defined(__IGNORE_readlink)
#warning syscall readlink not implemented
#endif
#if !defined(__NR_uselib) && !defined(__IGNORE_uselib)
#warning syscall uselib not implemented
#endif
#if !defined(__NR_swapon) && !defined(__IGNORE_swapon)
#warning syscall swapon not implemented
#endif
#if !defined(__NR_reboot) && !defined(__IGNORE_reboot)
#warning syscall reboot not implemented
#endif
#if !defined(__NR_readdir) && !defined(__IGNORE_readdir)
#warning syscall readdir not implemented
#endif
#if !defined(__NR_mmap) && !defined(__IGNORE_mmap)
#warning syscall mmap not implemented
#endif
#if !defined(__NR_munmap) && !defined(__IGNORE_munmap)
#warning syscall munmap not implemented
#endif
#if !defined(__NR_truncate) && !defined(__IGNORE_truncate)
#warning syscall truncate not implemented
#endif
#if !defined(__NR_ftruncate) && !defined(__IGNORE_ftruncate)
#warning syscall ftruncate not implemented
#endif
#if !defined(__NR_fchmod) && !defined(__IGNORE_fchmod)
#warning syscall fchmod not implemented
#endif
#if !defined(__NR_fchown) && !defined(__IGNORE_fchown)
#warning syscall fchown not implemented
#endif
#if !defined(__NR_getpriority) && !defined(__IGNORE_getpriority)
#warning syscall getpriority not implemented
#endif
#if !defined(__NR_setpriority) && !defined(__IGNORE_setpriority)
#warning syscall setpriority not implemented
#endif
#if !defined(__NR_profil) && !defined(__IGNORE_profil)
#warning syscall profil not implemented
#endif
#if !defined(__NR_statfs) && !defined(__IGNORE_statfs)
#warning syscall statfs not implemented
#endif
#if !defined(__NR_fstatfs) && !defined(__IGNORE_fstatfs)
#warning syscall fstatfs not implemented
#endif
#if !defined(__NR_ioperm) && !defined(__IGNORE_ioperm)
#warning syscall ioperm not implemented
#endif
#if !defined(__NR_socketcall) && !defined(__IGNORE_socketcall)
#warning syscall socketcall not implemented
#endif
#if !defined(__NR_syslog) && !defined(__IGNORE_syslog)
#warning syscall syslog not implemented
#endif
#if !defined(__NR_setitimer) && !defined(__IGNORE_setitimer)
#warning syscall setitimer not implemented
#endif
#if !defined(__NR_getitimer) && !defined(__IGNORE_getitimer)
#warning syscall getitimer not implemented
#endif
#if !defined(__NR_stat) && !defined(__IGNORE_stat)
#warning syscall stat not implemented
#endif
#if !defined(__NR_lstat) && !defined(__IGNORE_lstat)
#warning syscall lstat not implemented
#endif
#if !defined(__NR_fstat) && !defined(__IGNORE_fstat)
#warning syscall fstat not implemented
#endif
#if !defined(__NR_olduname) && !defined(__IGNORE_olduname)
#warning syscall olduname not implemented
#endif
#if !defined(__NR_iopl) && !defined(__IGNORE_iopl)
#warning syscall iopl not implemented
#endif
#if !defined(__NR_vhangup) && !defined(__IGNORE_vhangup)
#warning syscall vhangup not implemented
#endif
#if !defined(__NR_idle) && !defined(__IGNORE_idle)
#warning syscall idle not implemented
#endif
#if !defined(__NR_vm86old) && !defined(__IGNORE_vm86old)
#warning syscall vm86old not implemented
#endif
#if !defined(__NR_wait4) && !defined(__IGNORE_wait4)
#warning syscall wait4 not implemented
#endif
#if !defined(__NR_swapoff) && !defined(__IGNORE_swapoff)
#warning syscall swapoff not implemented
#endif
#if !defined(__NR_sysinfo) && !defined(__IGNORE_sysinfo)
#warning syscall sysinfo not implemented
#endif
#if !defined(__NR_ipc) && !defined(__IGNORE_ipc)
#warning syscall ipc not implemented
#endif
#if !defined(__NR_fsync) && !defined(__IGNORE_fsync)
#warning syscall fsync not implemented
#endif
#if !defined(__NR_sigreturn) && !defined(__IGNORE_sigreturn)
#warning syscall sigreturn not implemented
#endif
#if !defined(__NR_clone) && !defined(__IGNORE_clone)
#warning syscall clone not implemented
#endif
#if !defined(__NR_setdomainname) && !defined(__IGNORE_setdomainname)
#warning syscall setdomainname not implemented
#endif
#if !defined(__NR_uname) && !defined(__IGNORE_uname)
#warning syscall uname not implemented
#endif
#if !defined(__NR_modify_ldt) && !defined(__IGNORE_modify_ldt)
#warning syscall modify_ldt not implemented
#endif
#if !defined(__NR_adjtimex) && !defined(__IGNORE_adjtimex)
#warning syscall adjtimex not implemented
#endif
#if !defined(__NR_mprotect) && !defined(__IGNORE_mprotect)
#warning syscall mprotect not implemented
#endif
#if !defined(__NR_sigprocmask) && !defined(__IGNORE_sigprocmask)
#warning syscall sigprocmask not implemented
#endif
#if !defined(__NR_create_module) && !defined(__IGNORE_create_module)
#warning syscall create_module not implemented
#endif
#if !defined(__NR_init_module) && !defined(__IGNORE_init_module)
#warning syscall init_module not implemented
#endif
#if !defined(__NR_delete_module) && !defined(__IGNORE_delete_module)
#warning syscall delete_module not implemented
#endif
#if !defined(__NR_get_kernel_syms) && !defined(__IGNORE_get_kernel_syms)
#warning syscall get_kernel_syms not implemented
#endif
#if !defined(__NR_quotactl) && !defined(__IGNORE_quotactl)
#warning syscall quotactl not implemented
#endif
#if !defined(__NR_getpgid) && !defined(__IGNORE_getpgid)
#warning syscall getpgid not implemented
#endif
#if !defined(__NR_fchdir) && !defined(__IGNORE_fchdir)
#warning syscall fchdir not implemented
#endif
#if !defined(__NR_bdflush) && !defined(__IGNORE_bdflush)
#warning syscall bdflush not implemented
#endif
#if !defined(__NR_sysfs) && !defined(__IGNORE_sysfs)
#warning syscall sysfs not implemented
#endif
#if !defined(__NR_personality) && !defined(__IGNORE_personality)
#warning syscall personality not implemented
#endif
#if !defined(__NR_afs_syscall) && !defined(__IGNORE_afs_syscall)
#warning syscall afs_syscall not implemented
#endif
#if !defined(__NR_setfsuid) && !defined(__IGNORE_setfsuid)
#warning syscall setfsuid not implemented
#endif
#if !defined(__NR_setfsgid) && !defined(__IGNORE_setfsgid)
#warning syscall setfsgid not implemented
#endif
#if !defined(__NR__llseek) && !defined(__IGNORE__llseek)
#warning syscall _llseek not implemented
#endif
#if !defined(__NR_getdents) && !defined(__IGNORE_getdents)
#warning syscall getdents not implemented
#endif
#if !defined(__NR__newselect) && !defined(__IGNORE__newselect)
#warning syscall _newselect not implemented
#endif
#if !defined(__NR_flock) && !defined(__IGNORE_flock)
#warning syscall flock not implemented
#endif
#if !defined(__NR_msync) && !defined(__IGNORE_msync)
#warning syscall msync not implemented
#endif
#if !defined(__NR_readv) && !defined(__IGNORE_readv)
#warning syscall readv not implemented
#endif
#if !defined(__NR_writev) && !defined(__IGNORE_writev)
#warning syscall writev not implemented
#endif
#if !defined(__NR_getsid) && !defined(__IGNORE_getsid)
#warning syscall getsid not implemented
#endif
#if !defined(__NR_fdatasync) && !defined(__IGNORE_fdatasync)
#warning syscall fdatasync not implemented
#endif
#if !defined(__NR__sysctl) && !defined(__IGNORE__sysctl)
#warning syscall _sysctl not implemented
#endif
#if !defined(__NR_mlock) && !defined(__IGNORE_mlock)
#warning syscall mlock not implemented
#endif
#if !defined(__NR_munlock) && !defined(__IGNORE_munlock)
#warning syscall munlock not implemented
#endif
#if !defined(__NR_mlockall) && !defined(__IGNORE_mlockall)
#warning syscall mlockall not implemented
#endif
#if !defined(__NR_munlockall) && !defined(__IGNORE_munlockall)
#warning syscall munlockall not implemented
#endif
#if !defined(__NR_sched_setparam) && !defined(__IGNORE_sched_setparam)
#warning syscall sched_setparam not implemented
#endif
#if !defined(__NR_sched_getparam) && !defined(__IGNORE_sched_getparam)
#warning syscall sched_getparam not implemented
#endif
#if !defined(__NR_sched_setscheduler) && !defined(__IGNORE_sched_setscheduler)
#warning syscall sched_setscheduler not implemented
#endif
#if !defined(__NR_sched_getscheduler) && !defined(__IGNORE_sched_getscheduler)
#warning syscall sched_getscheduler not implemented
#endif
#if !defined(__NR_sched_yield) && !defined(__IGNORE_sched_yield)
#warning syscall sched_yield not implemented
#endif
#if !defined(__NR_sched_get_priority_max) && !defined(__IGNORE_sched_get_priority_max)
#warning syscall sched_get_priority_max not implemented
#endif
#if !defined(__NR_sched_get_priority_min) && !defined(__IGNORE_sched_get_priority_min)
#warning syscall sched_get_priority_min not implemented
#endif
#if !defined(__NR_sched_rr_get_interval) && !defined(__IGNORE_sched_rr_get_interval)
#warning syscall sched_rr_get_interval not implemented
#endif
#if !defined(__NR_nanosleep) && !defined(__IGNORE_nanosleep)
#warning syscall nanosleep not implemented
#endif
#if !defined(__NR_mremap) && !defined(__IGNORE_mremap)
#warning syscall mremap not implemented
#endif
#if !defined(__NR_setresuid) && !defined(__IGNORE_setresuid)
#warning syscall setresuid not implemented
#endif
#if !defined(__NR_getresuid) && !defined(__IGNORE_getresuid)
#warning syscall getresuid not implemented
#endif
#if !defined(__NR_vm86) && !defined(__IGNORE_vm86)
#warning syscall vm86 not implemented
#endif
#if !defined(__NR_query_module) && !defined(__IGNORE_query_module)
#warning syscall query_module not implemented
#endif
#if !defined(__NR_poll) && !defined(__IGNORE_poll)
#warning syscall poll not implemented
#endif
#if !defined(__NR_nfsservctl) && !defined(__IGNORE_nfsservctl)
#warning syscall nfsservctl not implemented
#endif
#if !defined(__NR_setresgid) && !defined(__IGNORE_setresgid)
#warning syscall setresgid not implemented
#endif
#if !defined(__NR_getresgid) && !defined(__IGNORE_getresgid)
#warning syscall getresgid not implemented
#endif
#if !defined(__NR_prctl) && !defined(__IGNORE_prctl)
#warning syscall prctl not implemented
#endif
#if !defined(__NR_rt_sigreturn) && !defined(__IGNORE_rt_sigreturn)
#warning syscall rt_sigreturn not implemented
#endif
#if !defined(__NR_rt_sigaction) && !defined(__IGNORE_rt_sigaction)
#warning syscall rt_sigaction not implemented
#endif
#if !defined(__NR_rt_sigprocmask) && !defined(__IGNORE_rt_sigprocmask)
#warning syscall rt_sigprocmask not implemented
#endif
#if !defined(__NR_rt_sigpending) && !defined(__IGNORE_rt_sigpending)
#warning syscall rt_sigpending not implemented
#endif
#if !defined(__NR_rt_sigtimedwait) && !defined(__IGNORE_rt_sigtimedwait)
#warning syscall rt_sigtimedwait not implemented
#endif
#if !defined(__NR_rt_sigqueueinfo) && !defined(__IGNORE_rt_sigqueueinfo)
#warning syscall rt_sigqueueinfo not implemented
#endif
#if !defined(__NR_rt_sigsuspend) && !defined(__IGNORE_rt_sigsuspend)
#warning syscall rt_sigsuspend not implemented
#endif
#if !defined(__NR_pread64) && !defined(__IGNORE_pread64)
#warning syscall pread64 not implemented
#endif
#if !defined(__NR_pwrite64) && !defined(__IGNORE_pwrite64)
#warning syscall pwrite64 not implemented
#endif
#if !defined(__NR_chown) && !defined(__IGNORE_chown)
#warning syscall chown not implemented
#endif
#if !defined(__NR_getcwd) && !defined(__IGNORE_getcwd)
#warning syscall getcwd not implemented
#endif
#if !defined(__NR_capget) && !defined(__IGNORE_capget)
#warning syscall capget not implemented
#endif
#if !defined(__NR_capset) && !defined(__IGNORE_capset)
#warning syscall capset not implemented
#endif
#if !defined(__NR_sigaltstack) && !defined(__IGNORE_sigaltstack)
#warning syscall sigaltstack not implemented
#endif
#if !defined(__NR_sendfile) && !defined(__IGNORE_sendfile)
#warning syscall sendfile not implemented
#endif
#if !defined(__NR_getpmsg) && !defined(__IGNORE_getpmsg)
#warning syscall getpmsg not implemented
#endif
#if !defined(__NR_putpmsg) && !defined(__IGNORE_putpmsg)
#warning syscall putpmsg not implemented
#endif
#if !defined(__NR_vfork) && !defined(__IGNORE_vfork)
#warning syscall vfork not implemented
#endif
#if !defined(__NR_ugetrlimit) && !defined(__IGNORE_ugetrlimit)
#warning syscall ugetrlimit not implemented
#endif
#if !defined(__NR_mmap2) && !defined(__IGNORE_mmap2)
#warning syscall mmap2 not implemented
#endif
#if !defined(__NR_truncate64) && !defined(__IGNORE_truncate64)
#warning syscall truncate64 not implemented
#endif
#if !defined(__NR_ftruncate64) && !defined(__IGNORE_ftruncate64)
#warning syscall ftruncate64 not implemented
#endif
#if !defined(__NR_stat64) && !defined(__IGNORE_stat64)
#warning syscall stat64 not implemented
#endif
#if !defined(__NR_lstat64) && !defined(__IGNORE_lstat64)
#warning syscall lstat64 not implemented
#endif
#if !defined(__NR_fstat64) && !defined(__IGNORE_fstat64)
#warning syscall fstat64 not implemented
#endif
#if !defined(__NR_lchown32) && !defined(__IGNORE_lchown32)
#warning syscall lchown32 not implemented
#endif
#if !defined(__NR_getuid32) && !defined(__IGNORE_getuid32)
#warning syscall getuid32 not implemented
#endif
#if !defined(__NR_getgid32) && !defined(__IGNORE_getgid32)
#warning syscall getgid32 not implemented
#endif
#if !defined(__NR_geteuid32) && !defined(__IGNORE_geteuid32)
#warning syscall geteuid32 not implemented
#endif
#if !defined(__NR_getegid32) && !defined(__IGNORE_getegid32)
#warning syscall getegid32 not implemented
#endif
#if !defined(__NR_setreuid32) && !defined(__IGNORE_setreuid32)
#warning syscall setreuid32 not implemented
#endif
#if !defined(__NR_setregid32) && !defined(__IGNORE_setregid32)
#warning syscall setregid32 not implemented
#endif
#if !defined(__NR_getgroups32) && !defined(__IGNORE_getgroups32)
#warning syscall getgroups32 not implemented
#endif
#if !defined(__NR_setgroups32) && !defined(__IGNORE_setgroups32)
#warning syscall setgroups32 not implemented
#endif
#if !defined(__NR_fchown32) && !defined(__IGNORE_fchown32)
#warning syscall fchown32 not implemented
#endif
#if !defined(__NR_setresuid32) && !defined(__IGNORE_setresuid32)
#warning syscall setresuid32 not implemented
#endif
#if !defined(__NR_getresuid32) && !defined(__IGNORE_getresuid32)
#warning syscall getresuid32 not implemented
#endif
#if !defined(__NR_setresgid32) && !defined(__IGNORE_setresgid32)
#warning syscall setresgid32 not implemented
#endif
#if !defined(__NR_getresgid32) && !defined(__IGNORE_getresgid32)
#warning syscall getresgid32 not implemented
#endif
#if !defined(__NR_chown32) && !defined(__IGNORE_chown32)
#warning syscall chown32 not implemented
#endif
#if !defined(__NR_setuid32) && !defined(__IGNORE_setuid32)
#warning syscall setuid32 not implemented
#endif
#if !defined(__NR_setgid32) && !defined(__IGNORE_setgid32)
#warning syscall setgid32 not implemented
#endif
#if !defined(__NR_setfsuid32) && !defined(__IGNORE_setfsuid32)
#warning syscall setfsuid32 not implemented
#endif
#if !defined(__NR_setfsgid32) && !defined(__IGNORE_setfsgid32)
#warning syscall setfsgid32 not implemented
#endif
#if !defined(__NR_pivot_root) && !defined(__IGNORE_pivot_root)
#warning syscall pivot_root not implemented
#endif
#if !defined(__NR_mincore) && !defined(__IGNORE_mincore)
#warning syscall mincore not implemented
#endif
#if !defined(__NR_madvise) && !defined(__IGNORE_madvise)
#warning syscall madvise not implemented
#endif
#if !defined(__NR_getdents64) && !defined(__IGNORE_getdents64)
#warning syscall getdents64 not implemented
#endif
#if !defined(__NR_fcntl64) && !defined(__IGNORE_fcntl64)
#warning syscall fcntl64 not implemented
#endif
#if !defined(__NR_gettid) && !defined(__IGNORE_gettid)
#warning syscall gettid not implemented
#endif
#if !defined(__NR_readahead) && !defined(__IGNORE_readahead)
#warning syscall readahead not implemented
#endif
#if !defined(__NR_setxattr) && !defined(__IGNORE_setxattr)
#warning syscall setxattr not implemented
#endif
#if !defined(__NR_lsetxattr) && !defined(__IGNORE_lsetxattr)
#warning syscall lsetxattr not implemented
#endif
#if !defined(__NR_fsetxattr) && !defined(__IGNORE_fsetxattr)
#warning syscall fsetxattr not implemented
#endif
#if !defined(__NR_getxattr) && !defined(__IGNORE_getxattr)
#warning syscall getxattr not implemented
#endif
#if !defined(__NR_lgetxattr) && !defined(__IGNORE_lgetxattr)
#warning syscall lgetxattr not implemented
#endif
#if !defined(__NR_fgetxattr) && !defined(__IGNORE_fgetxattr)
#warning syscall fgetxattr not implemented
#endif
#if !defined(__NR_listxattr) && !defined(__IGNORE_listxattr)
#warning syscall listxattr not implemented
#endif
#if !defined(__NR_llistxattr) && !defined(__IGNORE_llistxattr)
#warning syscall llistxattr not implemented
#endif
#if !defined(__NR_flistxattr) && !defined(__IGNORE_flistxattr)
#warning syscall flistxattr not implemented
#endif
#if !defined(__NR_removexattr) && !defined(__IGNORE_removexattr)
#warning syscall removexattr not implemented
#endif
#if !defined(__NR_lremovexattr) && !defined(__IGNORE_lremovexattr)
#warning syscall lremovexattr not implemented
#endif
#if !defined(__NR_fremovexattr) && !defined(__IGNORE_fremovexattr)
#warning syscall fremovexattr not implemented
#endif
#if !defined(__NR_tkill) && !defined(__IGNORE_tkill)
#warning syscall tkill not implemented
#endif
#if !defined(__NR_sendfile64) && !defined(__IGNORE_sendfile64)
#warning syscall sendfile64 not implemented
#endif
#if !defined(__NR_futex) && !defined(__IGNORE_futex)
#warning syscall futex not implemented
#endif
#if !defined(__NR_sched_setaffinity) && !defined(__IGNORE_sched_setaffinity)
#warning syscall sched_setaffinity not implemented
#endif
#if !defined(__NR_sched_getaffinity) && !defined(__IGNORE_sched_getaffinity)
#warning syscall sched_getaffinity not implemented
#endif
#if !defined(__NR_set_thread_area) && !defined(__IGNORE_set_thread_area)
#warning syscall set_thread_area not implemented
#endif
#if !defined(__NR_get_thread_area) && !defined(__IGNORE_get_thread_area)
#warning syscall get_thread_area not implemented
#endif
#if !defined(__NR_io_setup) && !defined(__IGNORE_io_setup)
#warning syscall io_setup not implemented
#endif
#if !defined(__NR_io_destroy) && !defined(__IGNORE_io_destroy)
#warning syscall io_destroy not implemented
#endif
#if !defined(__NR_io_getevents) && !defined(__IGNORE_io_getevents)
#warning syscall io_getevents not implemented
#endif
#if !defined(__NR_io_submit) && !defined(__IGNORE_io_submit)
#warning syscall io_submit not implemented
#endif
#if !defined(__NR_io_cancel) && !defined(__IGNORE_io_cancel)
#warning syscall io_cancel not implemented
#endif
#if !defined(__NR_fadvise64) && !defined(__IGNORE_fadvise64)
#warning syscall fadvise64 not implemented
#endif
#if !defined(__NR_exit_group) && !defined(__IGNORE_exit_group)
#warning syscall exit_group not implemented
#endif
#if !defined(__NR_lookup_dcookie) && !defined(__IGNORE_lookup_dcookie)
#warning syscall lookup_dcookie not implemented
#endif
#if !defined(__NR_epoll_create) && !defined(__IGNORE_epoll_create)
#warning syscall epoll_create not implemented
#endif
#if !defined(__NR_epoll_ctl) && !defined(__IGNORE_epoll_ctl)
#warning syscall epoll_ctl not implemented
#endif
#if !defined(__NR_epoll_wait) && !defined(__IGNORE_epoll_wait)
#warning syscall epoll_wait not implemented
#endif
#if !defined(__NR_remap_file_pages) && !defined(__IGNORE_remap_file_pages)
#warning syscall remap_file_pages not implemented
#endif
#if !defined(__NR_set_tid_address) && !defined(__IGNORE_set_tid_address)
#warning syscall set_tid_address not implemented
#endif
#if !defined(__NR_timer_create) && !defined(__IGNORE_timer_create)
#warning syscall timer_create not implemented
#endif
#if !defined(__NR_timer_settime) && !defined(__IGNORE_timer_settime)
#warning syscall timer_settime not implemented
#endif
#if !defined(__NR_timer_gettime) && !defined(__IGNORE_timer_gettime)
#warning syscall timer_gettime not implemented
#endif
#if !defined(__NR_timer_getoverrun) && !defined(__IGNORE_timer_getoverrun)
#warning syscall timer_getoverrun not implemented
#endif
#if !defined(__NR_timer_delete) && !defined(__IGNORE_timer_delete)
#warning syscall timer_delete not implemented
#endif
#if !defined(__NR_clock_settime) && !defined(__IGNORE_clock_settime)
#warning syscall clock_settime not implemented
#endif
#if !defined(__NR_clock_gettime) && !defined(__IGNORE_clock_gettime)
#warning syscall clock_gettime not implemented
#endif
#if !defined(__NR_clock_getres) && !defined(__IGNORE_clock_getres)
#warning syscall clock_getres not implemented
#endif
#if !defined(__NR_clock_nanosleep) && !defined(__IGNORE_clock_nanosleep)
#warning syscall clock_nanosleep not implemented
#endif
#if !defined(__NR_statfs64) && !defined(__IGNORE_statfs64)
#warning syscall statfs64 not implemented
#endif
#if !defined(__NR_fstatfs64) && !defined(__IGNORE_fstatfs64)
#warning syscall fstatfs64 not implemented
#endif
#if !defined(__NR_tgkill) && !defined(__IGNORE_tgkill)
#warning syscall tgkill not implemented
#endif
#if !defined(__NR_utimes) && !defined(__IGNORE_utimes)
#warning syscall utimes not implemented
#endif
#if !defined(__NR_fadvise64_64) && !defined(__IGNORE_fadvise64_64)
#warning syscall fadvise64_64 not implemented
#endif
#if !defined(__NR_vserver) && !defined(__IGNORE_vserver)
#warning syscall vserver not implemented
#endif
#if !defined(__NR_mbind) && !defined(__IGNORE_mbind)
#warning syscall mbind not implemented
#endif
#if !defined(__NR_get_mempolicy) && !defined(__IGNORE_get_mempolicy)
#warning syscall get_mempolicy not implemented
#endif
#if !defined(__NR_set_mempolicy) && !defined(__IGNORE_set_mempolicy)
#warning syscall set_mempolicy not implemented
#endif
#if !defined(__NR_mq_open) && !defined(__IGNORE_mq_open)
#warning syscall mq_open not implemented
#endif
#if !defined(__NR_mq_unlink) && !defined(__IGNORE_mq_unlink)
#warning syscall mq_unlink not implemented
#endif
#if !defined(__NR_mq_timedsend) && !defined(__IGNORE_mq_timedsend)
#warning syscall mq_timedsend not implemented
#endif
#if !defined(__NR_mq_timedreceive) && !defined(__IGNORE_mq_timedreceive)
#warning syscall mq_timedreceive not implemented
#endif
#if !defined(__NR_mq_notify) && !defined(__IGNORE_mq_notify)
#warning syscall mq_notify not implemented
#endif
#if !defined(__NR_mq_getsetattr) && !defined(__IGNORE_mq_getsetattr)
#warning syscall mq_getsetattr not implemented
#endif
#if !defined(__NR_kexec_load) && !defined(__IGNORE_kexec_load)
#warning syscall kexec_load not implemented
#endif
#if !defined(__NR_waitid) && !defined(__IGNORE_waitid)
#warning syscall waitid not implemented
#endif
#if !defined(__NR_add_key) && !defined(__IGNORE_add_key)
#warning syscall add_key not implemented
#endif
#if !defined(__NR_request_key) && !defined(__IGNORE_request_key)
#warning syscall request_key not implemented
#endif
#if !defined(__NR_keyctl) && !defined(__IGNORE_keyctl)
#warning syscall keyctl not implemented
#endif
#if !defined(__NR_ioprio_set) && !defined(__IGNORE_ioprio_set)
#warning syscall ioprio_set not implemented
#endif
#if !defined(__NR_ioprio_get) && !defined(__IGNORE_ioprio_get)
#warning syscall ioprio_get not implemented
#endif
#if !defined(__NR_inotify_init) && !defined(__IGNORE_inotify_init)
#warning syscall inotify_init not implemented
#endif
#if !defined(__NR_inotify_add_watch) && !defined(__IGNORE_inotify_add_watch)
#warning syscall inotify_add_watch not implemented
#endif
#if !defined(__NR_inotify_rm_watch) && !defined(__IGNORE_inotify_rm_watch)
#warning syscall inotify_rm_watch not implemented
#endif
#if !defined(__NR_migrate_pages) && !defined(__IGNORE_migrate_pages)
#warning syscall migrate_pages not implemented
#endif
#if !defined(__NR_openat) && !defined(__IGNORE_openat)
#warning syscall openat not implemented
#endif
#if !defined(__NR_mkdirat) && !defined(__IGNORE_mkdirat)
#warning syscall mkdirat not implemented
#endif
#if !defined(__NR_mknodat) && !defined(__IGNORE_mknodat)
#warning syscall mknodat not implemented
#endif
#if !defined(__NR_fchownat) && !defined(__IGNORE_fchownat)
#warning syscall fchownat not implemented
#endif
#if !defined(__NR_futimesat) && !defined(__IGNORE_futimesat)
#warning syscall futimesat not implemented
#endif
#if !defined(__NR_fstatat64) && !defined(__IGNORE_fstatat64)
#warning syscall fstatat64 not implemented
#endif
#if !defined(__NR_unlinkat) && !defined(__IGNORE_unlinkat)
#warning syscall unlinkat not implemented
#endif
#if !defined(__NR_renameat) && !defined(__IGNORE_renameat)
#warning syscall renameat not implemented
#endif
#if !defined(__NR_linkat) && !defined(__IGNORE_linkat)
#warning syscall linkat not implemented
#endif
#if !defined(__NR_symlinkat) && !defined(__IGNORE_symlinkat)
#warning syscall symlinkat not implemented
#endif
#if !defined(__NR_readlinkat) && !defined(__IGNORE_readlinkat)
#warning syscall readlinkat not implemented
#endif
#if !defined(__NR_fchmodat) && !defined(__IGNORE_fchmodat)
#warning syscall fchmodat not implemented
#endif
#if !defined(__NR_faccessat) && !defined(__IGNORE_faccessat)
#warning syscall faccessat not implemented
#endif
#if !defined(__NR_pselect6) && !defined(__IGNORE_pselect6)
#warning syscall pselect6 not implemented
#endif
#if !defined(__NR_ppoll) && !defined(__IGNORE_ppoll)
#warning syscall ppoll not implemented
#endif
#if !defined(__NR_unshare) && !defined(__IGNORE_unshare)
#warning syscall unshare not implemented
#endif
#if !defined(__NR_set_robust_list) && !defined(__IGNORE_set_robust_list)
#warning syscall set_robust_list not implemented
#endif
#if !defined(__NR_get_robust_list) && !defined(__IGNORE_get_robust_list)
#warning syscall get_robust_list not implemented
#endif
#if !defined(__NR_splice) && !defined(__IGNORE_splice)
#warning syscall splice not implemented
#endif
#if !defined(__NR_sync_file_range) && !defined(__IGNORE_sync_file_range)
#warning syscall sync_file_range not implemented
#endif
#if !defined(__NR_tee) && !defined(__IGNORE_tee)
#warning syscall tee not implemented
#endif
#if !defined(__NR_vmsplice) && !defined(__IGNORE_vmsplice)
#warning syscall vmsplice not implemented
#endif
#if !defined(__NR_move_pages) && !defined(__IGNORE_move_pages)
#warning syscall move_pages not implemented
#endif
#if !defined(__NR_getcpu) && !defined(__IGNORE_getcpu)
#warning syscall getcpu not implemented
#endif
#if !defined(__NR_epoll_pwait) && !defined(__IGNORE_epoll_pwait)
#warning syscall epoll_pwait not implemented
#endif
#if !defined(__NR_utimensat) && !defined(__IGNORE_utimensat)
#warning syscall utimensat not implemented
#endif
#if !defined(__NR_signalfd) && !defined(__IGNORE_signalfd)
#warning syscall signalfd not implemented
#endif
#if !defined(__NR_timerfd_create) && !defined(__IGNORE_timerfd_create)
#warning syscall timerfd_create not implemented
#endif
#if !defined(__NR_eventfd) && !defined(__IGNORE_eventfd)
#warning syscall eventfd not implemented
#endif
#if !defined(__NR_fallocate) && !defined(__IGNORE_fallocate)
#warning syscall fallocate not implemented
#endif
#if !defined(__NR_timerfd_settime) && !defined(__IGNORE_timerfd_settime)
#warning syscall timerfd_settime not implemented
#endif
#if !defined(__NR_timerfd_gettime) && !defined(__IGNORE_timerfd_gettime)
#warning syscall timerfd_gettime not implemented
#endif
#if !defined(__NR_signalfd4) && !defined(__IGNORE_signalfd4)
#warning syscall signalfd4 not implemented
#endif
#if !defined(__NR_eventfd2) && !defined(__IGNORE_eventfd2)
#warning syscall eventfd2 not implemented
#endif
#if !defined(__NR_epoll_create1) && !defined(__IGNORE_epoll_create1)
#warning syscall epoll_create1 not implemented
#endif
#if !defined(__NR_dup3) && !defined(__IGNORE_dup3)
#warning syscall dup3 not implemented
#endif
#if !defined(__NR_pipe2) && !defined(__IGNORE_pipe2)
#warning syscall pipe2 not implemented
#endif
#if !defined(__NR_inotify_init1) && !defined(__IGNORE_inotify_init1)
#warning syscall inotify_init1 not implemented
#endif
#if !defined(__NR_preadv) && !defined(__IGNORE_preadv)
#warning syscall preadv not implemented
#endif
#if !defined(__NR_pwritev) && !defined(__IGNORE_pwritev)
#warning syscall pwritev not implemented
#endif
#if !defined(__NR_rt_tgsigqueueinfo) && !defined(__IGNORE_rt_tgsigqueueinfo)
#warning syscall rt_tgsigqueueinfo not implemented
#endif
#if !defined(__NR_perf_event_open) && !defined(__IGNORE_perf_event_open)
#warning syscall perf_event_open not implemented
#endif
#if !defined(__NR_recvmmsg) && !defined(__IGNORE_recvmmsg)
#warning syscall recvmmsg not implemented
#endif
#if !defined(__NR_fanotify_init) && !defined(__IGNORE_fanotify_init)
#warning syscall fanotify_init not implemented
#endif
#if !defined(__NR_fanotify_mark) && !defined(__IGNORE_fanotify_mark)
#warning syscall fanotify_mark not implemented
#endif
#if !defined(__NR_prlimit64) && !defined(__IGNORE_prlimit64)
#warning syscall prlimit64 not implemented
#endif
#if !defined(__NR_name_to_handle_at) && !defined(__IGNORE_name_to_handle_at)
#warning syscall name_to_handle_at not implemented
#endif
#if !defined(__NR_open_by_handle_at) && !defined(__IGNORE_open_by_handle_at)
#warning syscall open_by_handle_at not implemented
#endif
#if !defined(__NR_clock_adjtime) && !defined(__IGNORE_clock_adjtime)
#warning syscall clock_adjtime not implemented
#endif
#if !defined(__NR_syncfs) && !defined(__IGNORE_syncfs)
#warning syscall syncfs not implemented
#endif
#if !defined(__NR_sendmmsg) && !defined(__IGNORE_sendmmsg)
#warning syscall sendmmsg not implemented
#endif
#if !defined(__NR_setns) && !defined(__IGNORE_setns)
#warning syscall setns not implemented
#endif
#if !defined(__NR_process_vm_readv) && !defined(__IGNORE_process_vm_readv)
#warning syscall process_vm_readv not implemented
#endif
#if !defined(__NR_process_vm_writev) && !defined(__IGNORE_process_vm_writev)
#warning syscall process_vm_writev not implemented
#endif
#if !defined(__NR_kcmp) && !defined(__IGNORE_kcmp)
#warning syscall kcmp not implemented
#endif
#if !defined(__NR_finit_module) && !defined(__IGNORE_finit_module)
#warning syscall finit_module not implemented
#endif
#if !defined(__NR_sched_setattr) && !defined(__IGNORE_sched_setattr)
#warning syscall sched_setattr not implemented
#endif
#if !defined(__NR_sched_getattr) && !defined(__IGNORE_sched_getattr)
#warning syscall sched_getattr not implemented
#endif
#if !defined(__NR_renameat2) && !defined(__IGNORE_renameat2)
#warning syscall renameat2 not implemented
#endif
#if !defined(__NR_seccomp) && !defined(__IGNORE_seccomp)
#warning syscall seccomp not implemented
#endif
#if !defined(__NR_getrandom) && !defined(__IGNORE_getrandom)
#warning syscall getrandom not implemented
#endif
#if !defined(__NR_memfd_create) && !defined(__IGNORE_memfd_create)
#warning syscall memfd_create not implemented
#endif
#if !defined(__NR_bpf) && !defined(__IGNORE_bpf)
#warning syscall bpf not implemented
#endif
#if !defined(__NR_execveat) && !defined(__IGNORE_execveat)
#warning syscall execveat not implemented
#endif
#if !defined(__NR_socket) && !defined(__IGNORE_socket)
#warning syscall socket not implemented
#endif
#if !defined(__NR_socketpair) && !defined(__IGNORE_socketpair)
#warning syscall socketpair not implemented
#endif
#if !defined(__NR_bind) && !defined(__IGNORE_bind)
#warning syscall bind not implemented
#endif
#if !defined(__NR_connect) && !defined(__IGNORE_connect)
#warning syscall connect not implemented
#endif
#if !defined(__NR_listen) && !defined(__IGNORE_listen)
#warning syscall listen not implemented
#endif
#if !defined(__NR_accept4) && !defined(__IGNORE_accept4)
#warning syscall accept4 not implemented
#endif
#if !defined(__NR_getsockopt) && !defined(__IGNORE_getsockopt)
#warning syscall getsockopt not implemented
#endif
#if !defined(__NR_setsockopt) && !defined(__IGNORE_setsockopt)
#warning syscall setsockopt not implemented
#endif
#if !defined(__NR_getsockname) && !defined(__IGNORE_getsockname)
#warning syscall getsockname not implemented
#endif
#if !defined(__NR_getpeername) && !defined(__IGNORE_getpeername)
#warning syscall getpeername not implemented
#endif
#if !defined(__NR_sendto) && !defined(__IGNORE_sendto)
#warning syscall sendto not implemented
#endif
#if !defined(__NR_sendmsg) && !defined(__IGNORE_sendmsg)
#warning syscall sendmsg not implemented
#endif
#if !defined(__NR_recvfrom) && !defined(__IGNORE_recvfrom)
#warning syscall recvfrom not implemented
#endif
#if !defined(__NR_recvmsg) && !defined(__IGNORE_recvmsg)
#warning syscall recvmsg not implemented
#endif
#if !defined(__NR_shutdown) && !defined(__IGNORE_shutdown)
#warning syscall shutdown not implemented
#endif
#if !defined(__NR_userfaultfd) && !defined(__IGNORE_userfaultfd)
#warning syscall userfaultfd not implemented
#endif
#if !defined(__NR_membarrier) && !defined(__IGNORE_membarrier)
#warning syscall membarrier not implemented
#endif
#if !defined(__NR_mlock2) && !defined(__IGNORE_mlock2)
#warning syscall mlock2 not implemented
#endif
#if !defined(__NR_copy_file_range) && !defined(__IGNORE_copy_file_range)
#warning syscall copy_file_range not implemented
#endif
#if !defined(__NR_preadv2) && !defined(__IGNORE_preadv2)
#warning syscall preadv2 not implemented
#endif
#if !defined(__NR_pwritev2) && !defined(__IGNORE_pwritev2)
#warning syscall pwritev2 not implemented
#endif
#if !defined(__NR_pkey_mprotect) && !defined(__IGNORE_pkey_mprotect)
#warning syscall pkey_mprotect not implemented
#endif
#if !defined(__NR_pkey_alloc) && !defined(__IGNORE_pkey_alloc)
#warning syscall pkey_alloc not implemented
#endif
#if !defined(__NR_pkey_free) && !defined(__IGNORE_pkey_free)
#warning syscall pkey_free not implemented
#endif
#if !defined(__NR_statx) && !defined(__IGNORE_statx)
#warning syscall statx not implemented
#endif
#if !defined(__NR_arch_prctl) && !defined(__IGNORE_arch_prctl)
#warning syscall arch_prctl not implemented
#endif
