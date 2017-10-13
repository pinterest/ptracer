# Automatically generated from system headers.
# DO NOT EDIT.

import ctypes

from .syscalldef import CType, SysCallSig, SysCallParamSig


PTRACE_TRACEME = 0
PTRACE_PEEKTEXT = 1
PTRACE_PEEKDATA = 2
PTRACE_PEEKUSER = 3
PTRACE_POKETEXT = 4
PTRACE_POKEDATA = 5
PTRACE_POKEUSER = 6
PTRACE_CONT = 7
PTRACE_KILL = 8
PTRACE_SINGLESTEP = 9
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_GETFPREGS = 14
PTRACE_SETFPREGS = 15
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
PTRACE_GETFPXREGS = 18
PTRACE_SETFPXREGS = 19
PTRACE_SYSCALL = 24
PTRACE_SETOPTIONS = 0x4200
PTRACE_GETEVENTMSG = 0x4201
PTRACE_GETSIGINFO = 0x4202
PTRACE_SETSIGINFO = 0x4203
PTRACE_GETREGSET = 0x4204
PTRACE_SETREGSET = 0x4205
PTRACE_SEIZE = 0x4206
PTRACE_INTERRUPT = 0x4207
PTRACE_LISTEN = 0x4208
PTRACE_PEEKSIGINFO = 0x4209
PTRACE_GETSIGMASK = 0x420a
PTRACE_SETSIGMASK = 0x420b
PTRACE_SECCOMP_GET_FILTER = 0x420c
PTRACE_SEIZE_DEVEL = 0x80000000
PTRACE_O_TRACESYSGOOD = 0x00000001
PTRACE_O_TRACEFORK = 0x00000002
PTRACE_O_TRACEVFORK = 0x00000004
PTRACE_O_TRACECLONE = 0x00000008
PTRACE_O_TRACEEXEC = 0x00000010
PTRACE_O_TRACEVFORKDONE = 0x00000020
PTRACE_O_TRACEEXIT = 0x00000040
PTRACE_O_TRACESECCOMP = 0x00000080
PTRACE_O_EXITKILL = 0x00100000
PTRACE_O_SUSPEND_SECCOMP = 0x00200000
PTRACE_O_MASK = 0x003000ff
PTRACE_EVENT_FORK = 1
PTRACE_EVENT_VFORK = 2
PTRACE_EVENT_CLONE = 3
PTRACE_EVENT_EXEC = 4
PTRACE_EVENT_VFORK_DONE = 5
PTRACE_EVENT_EXIT = 6
PTRACE_EVENT_SECCOMP = 7
PTRACE_PEEKSIGINFO_SHARED = 1 << 0


class __ptrace_peeksiginfo_args(ctypes.Structure):
    _fields_ = (
        ('off', ctypes.c_ulong),
        ('flags', ctypes.c_uint),
        ('nr', ctypes.c_int),
    )


class user_fpregs_struct(ctypes.Structure):
    _fields_ = (
        ('cwd', ctypes.c_ushort),
        ('swd', ctypes.c_ushort),
        ('ftw', ctypes.c_ushort),
        ('fop', ctypes.c_ushort),
        ('rip', ctypes.c_ulonglong),
        ('rdp', ctypes.c_ulonglong),
        ('mxcsr', ctypes.c_uint),
        ('mxcr_mask', ctypes.c_uint),
        ('st_space', ctypes.c_uint * 32),
        ('xmm_space', ctypes.c_uint * 64),
        ('padding', ctypes.c_uint * 24),
    )


class user_regs_struct(ctypes.Structure):
    _fields_ = (
        ('r15', ctypes.c_ulonglong),
        ('r14', ctypes.c_ulonglong),
        ('r13', ctypes.c_ulonglong),
        ('r12', ctypes.c_ulonglong),
        ('rbp', ctypes.c_ulonglong),
        ('rbx', ctypes.c_ulonglong),
        ('r11', ctypes.c_ulonglong),
        ('r10', ctypes.c_ulonglong),
        ('r9', ctypes.c_ulonglong),
        ('r8', ctypes.c_ulonglong),
        ('rax', ctypes.c_ulonglong),
        ('rcx', ctypes.c_ulonglong),
        ('rdx', ctypes.c_ulonglong),
        ('rsi', ctypes.c_ulonglong),
        ('rdi', ctypes.c_ulonglong),
        ('orig_rax', ctypes.c_ulonglong),
        ('rip', ctypes.c_ulonglong),
        ('cs', ctypes.c_ulonglong),
        ('eflags', ctypes.c_ulonglong),
        ('rsp', ctypes.c_ulonglong),
        ('ss', ctypes.c_ulonglong),
        ('fs_base', ctypes.c_ulonglong),
        ('gs_base', ctypes.c_ulonglong),
        ('ds', ctypes.c_ulonglong),
        ('es', ctypes.c_ulonglong),
        ('fs', ctypes.c_ulonglong),
        ('gs', ctypes.c_ulonglong),
    )


class _anon_2(ctypes.Structure):
    _fields_ = (
        ('si_pid', ctypes.c_int),
        ('si_uid', ctypes.c_uint),
    )


class _anon_3(ctypes.Structure):
    _fields_ = (
        ('si_tid', ctypes.c_int),
        ('si_overrun', ctypes.c_int),
        ('si_sigval', ctypes.c_void_p),
    )


class _anon_4(ctypes.Structure):
    _fields_ = (
        ('si_pid', ctypes.c_int),
        ('si_uid', ctypes.c_uint),
        ('si_sigval', ctypes.c_void_p),
    )


class _anon_5(ctypes.Structure):
    _fields_ = (
        ('si_pid', ctypes.c_int),
        ('si_uid', ctypes.c_uint),
        ('si_status', ctypes.c_int),
        ('si_utime', ctypes.c_long),
        ('si_stime', ctypes.c_long),
    )


class _anon_7(ctypes.Structure):
    _fields_ = (
        ('_lower', ctypes.c_void_p),
        ('_upper', ctypes.c_void_p),
    )


class _anon_6(ctypes.Structure):
    _fields_ = (
        ('si_addr', ctypes.c_void_p),
        ('si_addr_lsb', ctypes.c_short),
        ('si_addr_bnd', _anon_7),
    )


class _anon_8(ctypes.Structure):
    _fields_ = (
        ('si_band', ctypes.c_long),
        ('si_fd', ctypes.c_int),
    )


class _anon_9(ctypes.Structure):
    _fields_ = (
        ('_call_addr', ctypes.c_void_p),
        ('_syscall', ctypes.c_int),
        ('_arch', ctypes.c_uint),
    )


class _anon_1(ctypes.Union):
    _fields_ = (
        ('_pad', ctypes.c_int * 28),
        ('_kill', _anon_2),
        ('_timer', _anon_3),
        ('_rt', _anon_4),
        ('_sigchld', _anon_5),
        ('_sigfault', _anon_6),
        ('_sigpoll', _anon_8),
        ('_sigsys', _anon_9),
    )


class siginfo_t(ctypes.Structure):
    _fields_ = (
        ('si_signo', ctypes.c_int),
        ('si_errno', ctypes.c_int),
        ('si_code', ctypes.c_int),
        ('_sifields', _anon_1),
    )


SYSCALLS = {
    'time': SysCallSig(
        'time',
        params=[
            SysCallParamSig(
                'tloc',
                CType(
                    ['time_t', '*'],
                    ctypes.c_long,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'stime': SysCallSig(
        'stime',
        params=[
            SysCallParamSig(
                'tptr',
                CType(
                    ['time_t', '*'],
                    ctypes.c_long,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'gettimeofday': SysCallSig(
        'gettimeofday',
        params=[
            SysCallParamSig(
                'tv',
                CType(
                    ['struct', 'timeval', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'tz',
                CType(
                    ['struct', 'timezone', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'settimeofday': SysCallSig(
        'settimeofday',
        params=[
            SysCallParamSig(
                'tv',
                CType(
                    ['struct', 'timeval', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'tz',
                CType(
                    ['struct', 'timezone', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'adjtimex': SysCallSig(
        'adjtimex',
        params=[
            SysCallParamSig(
                'txc_p',
                CType(
                    ['struct', 'timex', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'times': SysCallSig(
        'times',
        params=[
            SysCallParamSig(
                'tbuf',
                CType(
                    ['struct', 'tms', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'gettid': SysCallSig(
        'gettid',
        params=[
            SysCallParamSig(
                None,
                CType(
                    ['void'],
                    ctypes.c_long,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'nanosleep': SysCallSig(
        'nanosleep',
        params=[
            SysCallParamSig(
                'rqtp',
                CType(
                    ['struct', 'timespec', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'rmtp',
                CType(
                    ['struct', 'timespec', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'alarm': SysCallSig(
        'alarm',
        params=[
            SysCallParamSig(
                'seconds',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'getpid': SysCallSig(
        'getpid',
        params=[
            SysCallParamSig(
                None,
                CType(
                    ['void'],
                    ctypes.c_long,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'getppid': SysCallSig(
        'getppid',
        params=[
            SysCallParamSig(
                None,
                CType(
                    ['void'],
                    ctypes.c_long,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'getuid': SysCallSig(
        'getuid',
        params=[
            SysCallParamSig(
                None,
                CType(
                    ['void'],
                    ctypes.c_long,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'geteuid': SysCallSig(
        'geteuid',
        params=[
            SysCallParamSig(
                None,
                CType(
                    ['void'],
                    ctypes.c_long,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'getgid': SysCallSig(
        'getgid',
        params=[
            SysCallParamSig(
                None,
                CType(
                    ['void'],
                    ctypes.c_long,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'getegid': SysCallSig(
        'getegid',
        params=[
            SysCallParamSig(
                None,
                CType(
                    ['void'],
                    ctypes.c_long,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'getresuid': SysCallSig(
        'getresuid',
        params=[
            SysCallParamSig(
                'ruid',
                CType(
                    ['uid_t', '*'],
                    ctypes.c_uint,
                    1
                )
            ),
            SysCallParamSig(
                'euid',
                CType(
                    ['uid_t', '*'],
                    ctypes.c_uint,
                    1
                )
            ),
            SysCallParamSig(
                'suid',
                CType(
                    ['uid_t', '*'],
                    ctypes.c_uint,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'getresgid': SysCallSig(
        'getresgid',
        params=[
            SysCallParamSig(
                'rgid',
                CType(
                    ['gid_t', '*'],
                    ctypes.c_uint,
                    1
                )
            ),
            SysCallParamSig(
                'egid',
                CType(
                    ['gid_t', '*'],
                    ctypes.c_uint,
                    1
                )
            ),
            SysCallParamSig(
                'sgid',
                CType(
                    ['gid_t', '*'],
                    ctypes.c_uint,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'getpgid': SysCallSig(
        'getpgid',
        params=[
            SysCallParamSig(
                'pid',
                CType(
                    ['pid_t'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'getpgrp': SysCallSig(
        'getpgrp',
        params=[
            SysCallParamSig(
                None,
                CType(
                    ['void'],
                    ctypes.c_long,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'getsid': SysCallSig(
        'getsid',
        params=[
            SysCallParamSig(
                'pid',
                CType(
                    ['pid_t'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'getgroups': SysCallSig(
        'getgroups',
        params=[
            SysCallParamSig(
                'gidsetsize',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'grouplist',
                CType(
                    ['gid_t', '*'],
                    ctypes.c_uint,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'setregid': SysCallSig(
        'setregid',
        params=[
            SysCallParamSig(
                'rgid',
                CType(
                    ['gid_t'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'egid',
                CType(
                    ['gid_t'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'setgid': SysCallSig(
        'setgid',
        params=[
            SysCallParamSig(
                'gid',
                CType(
                    ['gid_t'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'setreuid': SysCallSig(
        'setreuid',
        params=[
            SysCallParamSig(
                'ruid',
                CType(
                    ['uid_t'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'euid',
                CType(
                    ['uid_t'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'setuid': SysCallSig(
        'setuid',
        params=[
            SysCallParamSig(
                'uid',
                CType(
                    ['uid_t'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'setresuid': SysCallSig(
        'setresuid',
        params=[
            SysCallParamSig(
                'ruid',
                CType(
                    ['uid_t'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'euid',
                CType(
                    ['uid_t'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'suid',
                CType(
                    ['uid_t'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'setresgid': SysCallSig(
        'setresgid',
        params=[
            SysCallParamSig(
                'rgid',
                CType(
                    ['gid_t'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'egid',
                CType(
                    ['gid_t'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'sgid',
                CType(
                    ['gid_t'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'setfsuid': SysCallSig(
        'setfsuid',
        params=[
            SysCallParamSig(
                'uid',
                CType(
                    ['uid_t'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'setfsgid': SysCallSig(
        'setfsgid',
        params=[
            SysCallParamSig(
                'gid',
                CType(
                    ['gid_t'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'setpgid': SysCallSig(
        'setpgid',
        params=[
            SysCallParamSig(
                'pid',
                CType(
                    ['pid_t'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'pgid',
                CType(
                    ['pid_t'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'setsid': SysCallSig(
        'setsid',
        params=[
            SysCallParamSig(
                None,
                CType(
                    ['void'],
                    ctypes.c_long,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'setgroups': SysCallSig(
        'setgroups',
        params=[
            SysCallParamSig(
                'gidsetsize',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'grouplist',
                CType(
                    ['gid_t', '*'],
                    ctypes.c_uint,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'acct': SysCallSig(
        'acct',
        params=[
            SysCallParamSig(
                'name',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'capget': SysCallSig(
        'capget',
        params=[
            SysCallParamSig(
                'header',
                CType(
                    ['cap_user_header_t'],
                    ctypes.c_long,
                    1
                )
            ),
            SysCallParamSig(
                'dataptr',
                CType(
                    ['cap_user_data_t'],
                    ctypes.c_long,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'capset': SysCallSig(
        'capset',
        params=[
            SysCallParamSig(
                'header',
                CType(
                    ['cap_user_header_t'],
                    ctypes.c_long,
                    1
                )
            ),
            SysCallParamSig(
                'data',
                CType(
                    ['const', 'cap_user_data_t'],
                    ctypes.c_long,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'personality': SysCallSig(
        'personality',
        params=[
            SysCallParamSig(
                'personality',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'sigpending': SysCallSig(
        'sigpending',
        params=[
            SysCallParamSig(
                'set',
                CType(
                    ['old_sigset_t', '*'],
                    ctypes.c_ulong,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'sigprocmask': SysCallSig(
        'sigprocmask',
        params=[
            SysCallParamSig(
                'how',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'set',
                CType(
                    ['old_sigset_t', '*'],
                    ctypes.c_ulong,
                    1
                )
            ),
            SysCallParamSig(
                'oset',
                CType(
                    ['old_sigset_t', '*'],
                    ctypes.c_ulong,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'sigaltstack': SysCallSig(
        'sigaltstack',
        params=[
            SysCallParamSig(
                'uss',
                CType(
                    ['const', 'struct', 'sigaltstack', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'uoss',
                CType(
                    ['struct', 'sigaltstack', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'getitimer': SysCallSig(
        'getitimer',
        params=[
            SysCallParamSig(
                'which',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'value',
                CType(
                    ['struct', 'itimerval', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'setitimer': SysCallSig(
        'setitimer',
        params=[
            SysCallParamSig(
                'which',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'value',
                CType(
                    ['struct', 'itimerval', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'ovalue',
                CType(
                    ['struct', 'itimerval', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'timer_create': SysCallSig(
        'timer_create',
        params=[
            SysCallParamSig(
                'which_clock',
                CType(
                    ['clockid_t'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'timer_event_spec',
                CType(
                    ['struct', 'sigevent', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'created_timer_id',
                CType(
                    ['timer_t', '*'],
                    ctypes.c_int,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'timer_gettime': SysCallSig(
        'timer_gettime',
        params=[
            SysCallParamSig(
                'timer_id',
                CType(
                    ['timer_t'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'setting',
                CType(
                    ['struct', 'itimerspec', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'timer_getoverrun': SysCallSig(
        'timer_getoverrun',
        params=[
            SysCallParamSig(
                'timer_id',
                CType(
                    ['timer_t'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'timer_settime': SysCallSig(
        'timer_settime',
        params=[
            SysCallParamSig(
                'timer_id',
                CType(
                    ['timer_t'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'new_setting',
                CType(
                    ['const', 'struct', 'itimerspec', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'old_setting',
                CType(
                    ['struct', 'itimerspec', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'timer_delete': SysCallSig(
        'timer_delete',
        params=[
            SysCallParamSig(
                'timer_id',
                CType(
                    ['timer_t'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'clock_settime': SysCallSig(
        'clock_settime',
        params=[
            SysCallParamSig(
                'which_clock',
                CType(
                    ['clockid_t'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'tp',
                CType(
                    ['const', 'struct', 'timespec', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'clock_gettime': SysCallSig(
        'clock_gettime',
        params=[
            SysCallParamSig(
                'which_clock',
                CType(
                    ['clockid_t'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'tp',
                CType(
                    ['struct', 'timespec', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'clock_adjtime': SysCallSig(
        'clock_adjtime',
        params=[
            SysCallParamSig(
                'which_clock',
                CType(
                    ['clockid_t'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'tx',
                CType(
                    ['struct', 'timex', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'clock_getres': SysCallSig(
        'clock_getres',
        params=[
            SysCallParamSig(
                'which_clock',
                CType(
                    ['clockid_t'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'tp',
                CType(
                    ['struct', 'timespec', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'clock_nanosleep': SysCallSig(
        'clock_nanosleep',
        params=[
            SysCallParamSig(
                'which_clock',
                CType(
                    ['clockid_t'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'rqtp',
                CType(
                    ['const', 'struct', 'timespec', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'rmtp',
                CType(
                    ['struct', 'timespec', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'nice': SysCallSig(
        'nice',
        params=[
            SysCallParamSig(
                'increment',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'sched_setscheduler': SysCallSig(
        'sched_setscheduler',
        params=[
            SysCallParamSig(
                'pid',
                CType(
                    ['pid_t'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'policy',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'param',
                CType(
                    ['struct', 'sched_param', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'sched_setparam': SysCallSig(
        'sched_setparam',
        params=[
            SysCallParamSig(
                'pid',
                CType(
                    ['pid_t'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'param',
                CType(
                    ['struct', 'sched_param', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'sched_setattr': SysCallSig(
        'sched_setattr',
        params=[
            SysCallParamSig(
                'pid',
                CType(
                    ['pid_t'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'attr',
                CType(
                    ['struct', 'sched_attr', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'sched_getscheduler': SysCallSig(
        'sched_getscheduler',
        params=[
            SysCallParamSig(
                'pid',
                CType(
                    ['pid_t'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'sched_getparam': SysCallSig(
        'sched_getparam',
        params=[
            SysCallParamSig(
                'pid',
                CType(
                    ['pid_t'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'param',
                CType(
                    ['struct', 'sched_param', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'sched_getattr': SysCallSig(
        'sched_getattr',
        params=[
            SysCallParamSig(
                'pid',
                CType(
                    ['pid_t'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'attr',
                CType(
                    ['struct', 'sched_attr', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'size',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'sched_setaffinity': SysCallSig(
        'sched_setaffinity',
        params=[
            SysCallParamSig(
                'pid',
                CType(
                    ['pid_t'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'len',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'user_mask_ptr',
                CType(
                    ['unsigned', 'long', '*'],
                    ctypes.c_ulong,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'sched_getaffinity': SysCallSig(
        'sched_getaffinity',
        params=[
            SysCallParamSig(
                'pid',
                CType(
                    ['pid_t'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'len',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'user_mask_ptr',
                CType(
                    ['unsigned', 'long', '*'],
                    ctypes.c_ulong,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'sched_yield': SysCallSig(
        'sched_yield',
        params=[
            SysCallParamSig(
                None,
                CType(
                    ['void'],
                    ctypes.c_long,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'sched_get_priority_max': SysCallSig(
        'sched_get_priority_max',
        params=[
            SysCallParamSig(
                'policy',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'sched_get_priority_min': SysCallSig(
        'sched_get_priority_min',
        params=[
            SysCallParamSig(
                'policy',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'sched_rr_get_interval': SysCallSig(
        'sched_rr_get_interval',
        params=[
            SysCallParamSig(
                'pid',
                CType(
                    ['pid_t'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'interval',
                CType(
                    ['struct', 'timespec', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'setpriority': SysCallSig(
        'setpriority',
        params=[
            SysCallParamSig(
                'which',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'who',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'niceval',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'getpriority': SysCallSig(
        'getpriority',
        params=[
            SysCallParamSig(
                'which',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'who',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'shutdown': SysCallSig(
        'shutdown',
        params=[
            SysCallParamSig(
                None,
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'reboot': SysCallSig(
        'reboot',
        params=[
            SysCallParamSig(
                'magic1',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'magic2',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'cmd',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'arg',
                CType(
                    ['void', '*'],
                    ctypes.c_long,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'restart_syscall': SysCallSig(
        'restart_syscall',
        params=[
            SysCallParamSig(
                None,
                CType(
                    ['void'],
                    ctypes.c_long,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'kexec_load': SysCallSig(
        'kexec_load',
        params=[
            SysCallParamSig(
                'entry',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'nr_segments',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'segments',
                CType(
                    ['struct', 'kexec_segment', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'kexec_file_load': SysCallSig(
        'kexec_file_load',
        params=[
            SysCallParamSig(
                'kernel_fd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'initrd_fd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'cmdline_len',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'cmdline_ptr',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'exit': SysCallSig(
        'exit',
        params=[
            SysCallParamSig(
                'error_code',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'exit_group': SysCallSig(
        'exit_group',
        params=[
            SysCallParamSig(
                'error_code',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'wait4': SysCallSig(
        'wait4',
        params=[
            SysCallParamSig(
                'pid',
                CType(
                    ['pid_t'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'stat_addr',
                CType(
                    ['int', '*'],
                    ctypes.c_int,
                    1
                )
            ),
            SysCallParamSig(
                'options',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'ru',
                CType(
                    ['struct', 'rusage', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'waitid': SysCallSig(
        'waitid',
        params=[
            SysCallParamSig(
                'which',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'pid',
                CType(
                    ['pid_t'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'infop',
                CType(
                    ['struct', 'siginfo', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'options',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'ru',
                CType(
                    ['struct', 'rusage', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'waitpid': SysCallSig(
        'waitpid',
        params=[
            SysCallParamSig(
                'pid',
                CType(
                    ['pid_t'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'stat_addr',
                CType(
                    ['int', '*'],
                    ctypes.c_int,
                    1
                )
            ),
            SysCallParamSig(
                'options',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'set_tid_address': SysCallSig(
        'set_tid_address',
        params=[
            SysCallParamSig(
                'tidptr',
                CType(
                    ['int', '*'],
                    ctypes.c_int,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'futex': SysCallSig(
        'futex',
        params=[
            SysCallParamSig(
                'uaddr',
                CType(
                    ['u32', '*'],
                    ctypes.c_uint,
                    1
                )
            ),
            SysCallParamSig(
                'op',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'val',
                CType(
                    ['u32'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'utime',
                CType(
                    ['struct', 'timespec', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'uaddr2',
                CType(
                    ['u32', '*'],
                    ctypes.c_uint,
                    1
                )
            ),
            SysCallParamSig(
                'val3',
                CType(
                    ['u32'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'init_module': SysCallSig(
        'init_module',
        params=[
            SysCallParamSig(
                'umod',
                CType(
                    ['void', '*'],
                    ctypes.c_long,
                    1
                )
            ),
            SysCallParamSig(
                'len',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'uargs',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'delete_module': SysCallSig(
        'delete_module',
        params=[
            SysCallParamSig(
                'name_user',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'rt_sigsuspend': SysCallSig(
        'rt_sigsuspend',
        params=[
            SysCallParamSig(
                'unewset',
                CType(
                    ['sigset_t', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'sigsetsize',
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'rt_sigaction': SysCallSig(
        'rt_sigaction',
        params=[
            SysCallParamSig(
                None,
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['const', 'struct', 'sigaction', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['struct', 'sigaction', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'rt_sigprocmask': SysCallSig(
        'rt_sigprocmask',
        params=[
            SysCallParamSig(
                'how',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'set',
                CType(
                    ['sigset_t', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'oset',
                CType(
                    ['sigset_t', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'sigsetsize',
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'rt_sigpending': SysCallSig(
        'rt_sigpending',
        params=[
            SysCallParamSig(
                'set',
                CType(
                    ['sigset_t', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'sigsetsize',
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'rt_sigtimedwait': SysCallSig(
        'rt_sigtimedwait',
        params=[
            SysCallParamSig(
                'uthese',
                CType(
                    ['const', 'sigset_t', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'uinfo',
                CType(
                    ['siginfo_t', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'uts',
                CType(
                    ['const', 'struct', 'timespec', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'sigsetsize',
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'rt_tgsigqueueinfo': SysCallSig(
        'rt_tgsigqueueinfo',
        params=[
            SysCallParamSig(
                'tgid',
                CType(
                    ['pid_t'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'pid',
                CType(
                    ['pid_t'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'sig',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'uinfo',
                CType(
                    ['siginfo_t', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'kill': SysCallSig(
        'kill',
        params=[
            SysCallParamSig(
                'pid',
                CType(
                    ['pid_t'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'sig',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'tgkill': SysCallSig(
        'tgkill',
        params=[
            SysCallParamSig(
                'tgid',
                CType(
                    ['pid_t'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'pid',
                CType(
                    ['pid_t'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'sig',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'tkill': SysCallSig(
        'tkill',
        params=[
            SysCallParamSig(
                'pid',
                CType(
                    ['pid_t'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'sig',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'rt_sigqueueinfo': SysCallSig(
        'rt_sigqueueinfo',
        params=[
            SysCallParamSig(
                'pid',
                CType(
                    ['pid_t'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'sig',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'uinfo',
                CType(
                    ['siginfo_t', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'sgetmask': SysCallSig(
        'sgetmask',
        params=[
            SysCallParamSig(
                None,
                CType(
                    ['void'],
                    ctypes.c_long,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'ssetmask': SysCallSig(
        'ssetmask',
        params=[
            SysCallParamSig(
                'newmask',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'signal': SysCallSig(
        'signal',
        params=[
            SysCallParamSig(
                'sig',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'handler',
                CType(
                    ['__sighandler_t'],
                    ctypes.c_long,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'pause': SysCallSig(
        'pause',
        params=[
            SysCallParamSig(
                None,
                CType(
                    ['void'],
                    ctypes.c_long,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'sync': SysCallSig(
        'sync',
        params=[
            SysCallParamSig(
                None,
                CType(
                    ['void'],
                    ctypes.c_long,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'fsync': SysCallSig(
        'fsync',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'fdatasync': SysCallSig(
        'fdatasync',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'bdflush': SysCallSig(
        'bdflush',
        params=[
            SysCallParamSig(
                'func',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'data',
                CType(
                    ['long'],
                    ctypes.c_long,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'mount': SysCallSig(
        'mount',
        params=[
            SysCallParamSig(
                'dev_name',
                CType(
                    ['char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'dir_name',
                CType(
                    ['char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'type',
                CType(
                    ['char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'data',
                CType(
                    ['void', '*'],
                    ctypes.c_long,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'umount': SysCallSig(
        'umount',
        params=[
            SysCallParamSig(
                'name',
                CType(
                    ['char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'oldumount': SysCallSig(
        'oldumount',
        params=[
            SysCallParamSig(
                'name',
                CType(
                    ['char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'truncate': SysCallSig(
        'truncate',
        params=[
            SysCallParamSig(
                'path',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'length',
                CType(
                    ['long'],
                    ctypes.c_long,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'ftruncate': SysCallSig(
        'ftruncate',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'length',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'stat': SysCallSig(
        'stat',
        params=[
            SysCallParamSig(
                'filename',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'statbuf',
                CType(
                    ['struct', '__old_kernel_stat', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'statfs': SysCallSig(
        'statfs',
        params=[
            SysCallParamSig(
                'path',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'buf',
                CType(
                    ['struct', 'statfs', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'statfs64': SysCallSig(
        'statfs64',
        params=[
            SysCallParamSig(
                'path',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'sz',
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'buf',
                CType(
                    ['struct', 'statfs64', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'fstatfs': SysCallSig(
        'fstatfs',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'buf',
                CType(
                    ['struct', 'statfs', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'fstatfs64': SysCallSig(
        'fstatfs64',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'sz',
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'buf',
                CType(
                    ['struct', 'statfs64', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'lstat': SysCallSig(
        'lstat',
        params=[
            SysCallParamSig(
                'filename',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'statbuf',
                CType(
                    ['struct', '__old_kernel_stat', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'fstat': SysCallSig(
        'fstat',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'statbuf',
                CType(
                    ['struct', '__old_kernel_stat', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'newstat': SysCallSig(
        'newstat',
        params=[
            SysCallParamSig(
                'filename',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'statbuf',
                CType(
                    ['struct', 'stat', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'newlstat': SysCallSig(
        'newlstat',
        params=[
            SysCallParamSig(
                'filename',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'statbuf',
                CType(
                    ['struct', 'stat', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'newfstat': SysCallSig(
        'newfstat',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'statbuf',
                CType(
                    ['struct', 'stat', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'ustat': SysCallSig(
        'ustat',
        params=[
            SysCallParamSig(
                'dev',
                CType(
                    ['unsigned'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'ubuf',
                CType(
                    ['struct', 'ustat', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'setxattr': SysCallSig(
        'setxattr',
        params=[
            SysCallParamSig(
                'path',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'name',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'value',
                CType(
                    ['const', 'void', '*'],
                    ctypes.c_long,
                    1
                )
            ),
            SysCallParamSig(
                'size',
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'lsetxattr': SysCallSig(
        'lsetxattr',
        params=[
            SysCallParamSig(
                'path',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'name',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'value',
                CType(
                    ['const', 'void', '*'],
                    ctypes.c_long,
                    1
                )
            ),
            SysCallParamSig(
                'size',
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'fsetxattr': SysCallSig(
        'fsetxattr',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'name',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'value',
                CType(
                    ['const', 'void', '*'],
                    ctypes.c_long,
                    1
                )
            ),
            SysCallParamSig(
                'size',
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'getxattr': SysCallSig(
        'getxattr',
        params=[
            SysCallParamSig(
                'path',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'name',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'value',
                CType(
                    ['void', '*'],
                    ctypes.c_long,
                    1
                )
            ),
            SysCallParamSig(
                'size',
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'lgetxattr': SysCallSig(
        'lgetxattr',
        params=[
            SysCallParamSig(
                'path',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'name',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'value',
                CType(
                    ['void', '*'],
                    ctypes.c_long,
                    1
                )
            ),
            SysCallParamSig(
                'size',
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'fgetxattr': SysCallSig(
        'fgetxattr',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'name',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'value',
                CType(
                    ['void', '*'],
                    ctypes.c_long,
                    1
                )
            ),
            SysCallParamSig(
                'size',
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'listxattr': SysCallSig(
        'listxattr',
        params=[
            SysCallParamSig(
                'path',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'list',
                CType(
                    ['char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'size',
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'llistxattr': SysCallSig(
        'llistxattr',
        params=[
            SysCallParamSig(
                'path',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'list',
                CType(
                    ['char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'size',
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'flistxattr': SysCallSig(
        'flistxattr',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'list',
                CType(
                    ['char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'size',
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'removexattr': SysCallSig(
        'removexattr',
        params=[
            SysCallParamSig(
                'path',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'name',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'lremovexattr': SysCallSig(
        'lremovexattr',
        params=[
            SysCallParamSig(
                'path',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'name',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'fremovexattr': SysCallSig(
        'fremovexattr',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'name',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'brk': SysCallSig(
        'brk',
        params=[
            SysCallParamSig(
                'brk',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'mprotect': SysCallSig(
        'mprotect',
        params=[
            SysCallParamSig(
                'start',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'len',
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'prot',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'mremap': SysCallSig(
        'mremap',
        params=[
            SysCallParamSig(
                'addr',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'old_len',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'new_len',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'new_addr',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'remap_file_pages': SysCallSig(
        'remap_file_pages',
        params=[
            SysCallParamSig(
                'start',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'size',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'prot',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'pgoff',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'msync': SysCallSig(
        'msync',
        params=[
            SysCallParamSig(
                'start',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'len',
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'fadvise64': SysCallSig(
        'fadvise64',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'offset',
                CType(
                    ['loff_t'],
                    ctypes.c_longlong,
                    0
                )
            ),
            SysCallParamSig(
                'len',
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'advice',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'fadvise64_64': SysCallSig(
        'fadvise64_64',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'offset',
                CType(
                    ['loff_t'],
                    ctypes.c_longlong,
                    0
                )
            ),
            SysCallParamSig(
                'len',
                CType(
                    ['loff_t'],
                    ctypes.c_longlong,
                    0
                )
            ),
            SysCallParamSig(
                'advice',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'munmap': SysCallSig(
        'munmap',
        params=[
            SysCallParamSig(
                'addr',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'len',
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'mlock': SysCallSig(
        'mlock',
        params=[
            SysCallParamSig(
                'start',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'len',
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'munlock': SysCallSig(
        'munlock',
        params=[
            SysCallParamSig(
                'start',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'len',
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'mlockall': SysCallSig(
        'mlockall',
        params=[
            SysCallParamSig(
                'flags',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'munlockall': SysCallSig(
        'munlockall',
        params=[
            SysCallParamSig(
                None,
                CType(
                    ['void'],
                    ctypes.c_long,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'madvise': SysCallSig(
        'madvise',
        params=[
            SysCallParamSig(
                'start',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'len',
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'behavior',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'mincore': SysCallSig(
        'mincore',
        params=[
            SysCallParamSig(
                'start',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'len',
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'vec',
                CType(
                    ['unsigned', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'pivot_root': SysCallSig(
        'pivot_root',
        params=[
            SysCallParamSig(
                'new_root',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'put_old',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'chroot': SysCallSig(
        'chroot',
        params=[
            SysCallParamSig(
                'filename',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'mknod': SysCallSig(
        'mknod',
        params=[
            SysCallParamSig(
                'filename',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'mode',
                CType(
                    ['umode_t'],
                    ctypes.c_ushort,
                    0
                )
            ),
            SysCallParamSig(
                'dev',
                CType(
                    ['unsigned'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'link': SysCallSig(
        'link',
        params=[
            SysCallParamSig(
                'oldname',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'newname',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'symlink': SysCallSig(
        'symlink',
        params=[
            SysCallParamSig(
                'old',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'new',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'unlink': SysCallSig(
        'unlink',
        params=[
            SysCallParamSig(
                'pathname',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'rename': SysCallSig(
        'rename',
        params=[
            SysCallParamSig(
                'oldname',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'newname',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'chmod': SysCallSig(
        'chmod',
        params=[
            SysCallParamSig(
                'filename',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'mode',
                CType(
                    ['umode_t'],
                    ctypes.c_ushort,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'fchmod': SysCallSig(
        'fchmod',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'mode',
                CType(
                    ['umode_t'],
                    ctypes.c_ushort,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'fcntl': SysCallSig(
        'fcntl',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'cmd',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'arg',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'pipe': SysCallSig(
        'pipe',
        params=[
            SysCallParamSig(
                'fildes',
                CType(
                    ['int', '*'],
                    ctypes.c_int,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'pipe2': SysCallSig(
        'pipe2',
        params=[
            SysCallParamSig(
                'fildes',
                CType(
                    ['int', '*'],
                    ctypes.c_int,
                    1
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'dup': SysCallSig(
        'dup',
        params=[
            SysCallParamSig(
                'fildes',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'dup2': SysCallSig(
        'dup2',
        params=[
            SysCallParamSig(
                'oldfd',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'newfd',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'dup3': SysCallSig(
        'dup3',
        params=[
            SysCallParamSig(
                'oldfd',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'newfd',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'ioperm': SysCallSig(
        'ioperm',
        params=[
            SysCallParamSig(
                'from',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'num',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'on',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'ioctl': SysCallSig(
        'ioctl',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'cmd',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'arg',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'flock': SysCallSig(
        'flock',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'cmd',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'io_setup': SysCallSig(
        'io_setup',
        params=[
            SysCallParamSig(
                'nr_reqs',
                CType(
                    ['unsigned'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'ctx',
                CType(
                    ['aio_context_t', '*'],
                    ctypes.c_ulong,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'io_destroy': SysCallSig(
        'io_destroy',
        params=[
            SysCallParamSig(
                'ctx',
                CType(
                    ['aio_context_t'],
                    ctypes.c_ulong,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'io_getevents': SysCallSig(
        'io_getevents',
        params=[
            SysCallParamSig(
                'ctx_id',
                CType(
                    ['aio_context_t'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'min_nr',
                CType(
                    ['long'],
                    ctypes.c_long,
                    0
                )
            ),
            SysCallParamSig(
                'nr',
                CType(
                    ['long'],
                    ctypes.c_long,
                    0
                )
            ),
            SysCallParamSig(
                'events',
                CType(
                    ['struct', 'io_event', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'timeout',
                CType(
                    ['struct', 'timespec', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'io_submit': SysCallSig(
        'io_submit',
        params=[
            SysCallParamSig(
                None,
                CType(
                    ['aio_context_t'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['long'],
                    ctypes.c_long,
                    0
                )
            ),
            SysCallParamSig(
                '__foo',
                CType(
                    ['struct', 'iocb', '*', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'io_cancel': SysCallSig(
        'io_cancel',
        params=[
            SysCallParamSig(
                'ctx_id',
                CType(
                    ['aio_context_t'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'iocb',
                CType(
                    ['struct', 'iocb', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'result',
                CType(
                    ['struct', 'io_event', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'sendfile': SysCallSig(
        'sendfile',
        params=[
            SysCallParamSig(
                'out_fd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'in_fd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'offset',
                CType(
                    ['off_t', '*'],
                    ctypes.c_longlong,
                    1
                )
            ),
            SysCallParamSig(
                'count',
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'sendfile64': SysCallSig(
        'sendfile64',
        params=[
            SysCallParamSig(
                'out_fd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'in_fd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'offset',
                CType(
                    ['loff_t', '*'],
                    ctypes.c_longlong,
                    1
                )
            ),
            SysCallParamSig(
                'count',
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'readlink': SysCallSig(
        'readlink',
        params=[
            SysCallParamSig(
                'path',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'buf',
                CType(
                    ['char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'bufsiz',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'creat': SysCallSig(
        'creat',
        params=[
            SysCallParamSig(
                'pathname',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'mode',
                CType(
                    ['umode_t'],
                    ctypes.c_ushort,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'open': SysCallSig(
        'open',
        params=[
            SysCallParamSig(
                'filename',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'mode',
                CType(
                    ['umode_t'],
                    ctypes.c_ushort,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'close': SysCallSig(
        'close',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'access': SysCallSig(
        'access',
        params=[
            SysCallParamSig(
                'filename',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'mode',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'vhangup': SysCallSig(
        'vhangup',
        params=[
            SysCallParamSig(
                None,
                CType(
                    ['void'],
                    ctypes.c_long,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'chown': SysCallSig(
        'chown',
        params=[
            SysCallParamSig(
                'filename',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'user',
                CType(
                    ['uid_t'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'group',
                CType(
                    ['gid_t'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'lchown': SysCallSig(
        'lchown',
        params=[
            SysCallParamSig(
                'filename',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'user',
                CType(
                    ['uid_t'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'group',
                CType(
                    ['gid_t'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'fchown': SysCallSig(
        'fchown',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'user',
                CType(
                    ['uid_t'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'group',
                CType(
                    ['gid_t'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'utime': SysCallSig(
        'utime',
        params=[
            SysCallParamSig(
                'filename',
                CType(
                    ['char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'times',
                CType(
                    ['struct', 'utimbuf', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'utimes': SysCallSig(
        'utimes',
        params=[
            SysCallParamSig(
                'filename',
                CType(
                    ['char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'utimes',
                CType(
                    ['struct', 'timeval', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'lseek': SysCallSig(
        'lseek',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'offset',
                CType(
                    ['off_t'],
                    ctypes.c_longlong,
                    0
                )
            ),
            SysCallParamSig(
                'whence',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'llseek': SysCallSig(
        'llseek',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'offset_high',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'offset_low',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'result',
                CType(
                    ['loff_t', '*'],
                    ctypes.c_longlong,
                    1
                )
            ),
            SysCallParamSig(
                'whence',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'read': SysCallSig(
        'read',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'buf',
                CType(
                    ['char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'count',
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'readahead': SysCallSig(
        'readahead',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'offset',
                CType(
                    ['loff_t'],
                    ctypes.c_longlong,
                    0
                )
            ),
            SysCallParamSig(
                'count',
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'readv': SysCallSig(
        'readv',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'vec',
                CType(
                    ['const', 'struct', 'iovec', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'vlen',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'write': SysCallSig(
        'write',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'buf',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'count',
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'writev': SysCallSig(
        'writev',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'vec',
                CType(
                    ['const', 'struct', 'iovec', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'vlen',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'pread64': SysCallSig(
        'pread64',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'buf',
                CType(
                    ['char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'count',
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'pos',
                CType(
                    ['loff_t'],
                    ctypes.c_longlong,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'pwrite64': SysCallSig(
        'pwrite64',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'buf',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'count',
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'pos',
                CType(
                    ['loff_t'],
                    ctypes.c_longlong,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'preadv': SysCallSig(
        'preadv',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'vec',
                CType(
                    ['const', 'struct', 'iovec', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'vlen',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'pos_l',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'pos_h',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'preadv2': SysCallSig(
        'preadv2',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'vec',
                CType(
                    ['const', 'struct', 'iovec', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'vlen',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'pos_l',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'pos_h',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'pwritev': SysCallSig(
        'pwritev',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'vec',
                CType(
                    ['const', 'struct', 'iovec', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'vlen',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'pos_l',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'pos_h',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'pwritev2': SysCallSig(
        'pwritev2',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'vec',
                CType(
                    ['const', 'struct', 'iovec', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'vlen',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'pos_l',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'pos_h',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'getcwd': SysCallSig(
        'getcwd',
        params=[
            SysCallParamSig(
                'buf',
                CType(
                    ['char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'size',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'mkdir': SysCallSig(
        'mkdir',
        params=[
            SysCallParamSig(
                'pathname',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'mode',
                CType(
                    ['umode_t'],
                    ctypes.c_ushort,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'chdir': SysCallSig(
        'chdir',
        params=[
            SysCallParamSig(
                'filename',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'fchdir': SysCallSig(
        'fchdir',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'rmdir': SysCallSig(
        'rmdir',
        params=[
            SysCallParamSig(
                'pathname',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'lookup_dcookie': SysCallSig(
        'lookup_dcookie',
        params=[
            SysCallParamSig(
                'cookie64',
                CType(
                    ['u64'],
                    ctypes.c_ulonglong,
                    0
                )
            ),
            SysCallParamSig(
                'buf',
                CType(
                    ['char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'len',
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'quotactl': SysCallSig(
        'quotactl',
        params=[
            SysCallParamSig(
                'cmd',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'special',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'id',
                CType(
                    ['qid_t'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'addr',
                CType(
                    ['void', '*'],
                    ctypes.c_long,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'getdents': SysCallSig(
        'getdents',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'dirent',
                CType(
                    ['struct', 'linux_dirent', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'count',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'getdents64': SysCallSig(
        'getdents64',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'dirent',
                CType(
                    ['struct', 'linux_dirent64', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'count',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'setsockopt': SysCallSig(
        'setsockopt',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'level',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'optname',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'optval',
                CType(
                    ['char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'optlen',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'getsockopt': SysCallSig(
        'getsockopt',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'level',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'optname',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'optval',
                CType(
                    ['char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'optlen',
                CType(
                    ['int', '*'],
                    ctypes.c_int,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'bind': SysCallSig(
        'bind',
        params=[
            SysCallParamSig(
                None,
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['struct', 'sockaddr', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'connect': SysCallSig(
        'connect',
        params=[
            SysCallParamSig(
                None,
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['struct', 'sockaddr', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'accept': SysCallSig(
        'accept',
        params=[
            SysCallParamSig(
                None,
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['struct', 'sockaddr', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['int', '*'],
                    ctypes.c_int,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'accept4': SysCallSig(
        'accept4',
        params=[
            SysCallParamSig(
                None,
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['struct', 'sockaddr', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['int', '*'],
                    ctypes.c_int,
                    1
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'getsockname': SysCallSig(
        'getsockname',
        params=[
            SysCallParamSig(
                None,
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['struct', 'sockaddr', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['int', '*'],
                    ctypes.c_int,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'getpeername': SysCallSig(
        'getpeername',
        params=[
            SysCallParamSig(
                None,
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['struct', 'sockaddr', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['int', '*'],
                    ctypes.c_int,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'send': SysCallSig(
        'send',
        params=[
            SysCallParamSig(
                None,
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['void', '*'],
                    ctypes.c_long,
                    1
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['unsigned'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'sendto': SysCallSig(
        'sendto',
        params=[
            SysCallParamSig(
                None,
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['void', '*'],
                    ctypes.c_long,
                    1
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['unsigned'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['struct', 'sockaddr', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'sendmsg': SysCallSig(
        'sendmsg',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'msg',
                CType(
                    ['struct', 'user_msghdr', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['unsigned'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'sendmmsg': SysCallSig(
        'sendmmsg',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'msg',
                CType(
                    ['struct', 'mmsghdr', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'vlen',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['unsigned'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'recv': SysCallSig(
        'recv',
        params=[
            SysCallParamSig(
                None,
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['void', '*'],
                    ctypes.c_long,
                    1
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['unsigned'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'recvfrom': SysCallSig(
        'recvfrom',
        params=[
            SysCallParamSig(
                None,
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['void', '*'],
                    ctypes.c_long,
                    1
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['unsigned'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['struct', 'sockaddr', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['int', '*'],
                    ctypes.c_int,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'recvmsg': SysCallSig(
        'recvmsg',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'msg',
                CType(
                    ['struct', 'user_msghdr', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['unsigned'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'recvmmsg': SysCallSig(
        'recvmmsg',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'msg',
                CType(
                    ['struct', 'mmsghdr', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'vlen',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['unsigned'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'timeout',
                CType(
                    ['struct', 'timespec', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'socket': SysCallSig(
        'socket',
        params=[
            SysCallParamSig(
                None,
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'socketpair': SysCallSig(
        'socketpair',
        params=[
            SysCallParamSig(
                None,
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['int', '*'],
                    ctypes.c_int,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'socketcall': SysCallSig(
        'socketcall',
        params=[
            SysCallParamSig(
                'call',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'args',
                CType(
                    ['unsigned', 'long', '*'],
                    ctypes.c_ulong,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'listen': SysCallSig(
        'listen',
        params=[
            SysCallParamSig(
                None,
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'poll': SysCallSig(
        'poll',
        params=[
            SysCallParamSig(
                'ufds',
                CType(
                    ['struct', 'pollfd', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'nfds',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'timeout',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'select': SysCallSig(
        'select',
        params=[
            SysCallParamSig(
                'n',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'inp',
                CType(
                    ['fd_set', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'outp',
                CType(
                    ['fd_set', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'exp',
                CType(
                    ['fd_set', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'tvp',
                CType(
                    ['struct', 'timeval', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'old_select': SysCallSig(
        'old_select',
        params=[
            SysCallParamSig(
                'arg',
                CType(
                    ['struct', 'sel_arg_struct', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'epoll_create': SysCallSig(
        'epoll_create',
        params=[
            SysCallParamSig(
                'size',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'epoll_create1': SysCallSig(
        'epoll_create1',
        params=[
            SysCallParamSig(
                'flags',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'epoll_ctl': SysCallSig(
        'epoll_ctl',
        params=[
            SysCallParamSig(
                'epfd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'op',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'fd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'event',
                CType(
                    ['struct', 'epoll_event', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'epoll_wait': SysCallSig(
        'epoll_wait',
        params=[
            SysCallParamSig(
                'epfd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'events',
                CType(
                    ['struct', 'epoll_event', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'maxevents',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'timeout',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'epoll_pwait': SysCallSig(
        'epoll_pwait',
        params=[
            SysCallParamSig(
                'epfd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'events',
                CType(
                    ['struct', 'epoll_event', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'maxevents',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'timeout',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'sigmask',
                CType(
                    ['const', 'sigset_t', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'sigsetsize',
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'gethostname': SysCallSig(
        'gethostname',
        params=[
            SysCallParamSig(
                'name',
                CType(
                    ['char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'len',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'sethostname': SysCallSig(
        'sethostname',
        params=[
            SysCallParamSig(
                'name',
                CType(
                    ['char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'len',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'setdomainname': SysCallSig(
        'setdomainname',
        params=[
            SysCallParamSig(
                'name',
                CType(
                    ['char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'len',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'newuname': SysCallSig(
        'newuname',
        params=[
            SysCallParamSig(
                'name',
                CType(
                    ['struct', 'new_utsname', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'uname': SysCallSig(
        'uname',
        params=[
            SysCallParamSig(
                None,
                CType(
                    ['struct', 'old_utsname', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'olduname': SysCallSig(
        'olduname',
        params=[
            SysCallParamSig(
                None,
                CType(
                    ['struct', 'oldold_utsname', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'getrlimit': SysCallSig(
        'getrlimit',
        params=[
            SysCallParamSig(
                'resource',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'rlim',
                CType(
                    ['struct', 'rlimit', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'setrlimit': SysCallSig(
        'setrlimit',
        params=[
            SysCallParamSig(
                'resource',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'rlim',
                CType(
                    ['struct', 'rlimit', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'prlimit64': SysCallSig(
        'prlimit64',
        params=[
            SysCallParamSig(
                'pid',
                CType(
                    ['pid_t'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'resource',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'new_rlim',
                CType(
                    ['const', 'struct', 'rlimit64', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'old_rlim',
                CType(
                    ['struct', 'rlimit64', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'getrusage': SysCallSig(
        'getrusage',
        params=[
            SysCallParamSig(
                'who',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'ru',
                CType(
                    ['struct', 'rusage', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'umask': SysCallSig(
        'umask',
        params=[
            SysCallParamSig(
                'mask',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'msgget': SysCallSig(
        'msgget',
        params=[
            SysCallParamSig(
                'key',
                CType(
                    ['key_t'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'msgflg',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'msgsnd': SysCallSig(
        'msgsnd',
        params=[
            SysCallParamSig(
                'msqid',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'msgp',
                CType(
                    ['struct', 'msgbuf', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'msgsz',
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'msgflg',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'msgrcv': SysCallSig(
        'msgrcv',
        params=[
            SysCallParamSig(
                'msqid',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'msgp',
                CType(
                    ['struct', 'msgbuf', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'msgsz',
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'msgtyp',
                CType(
                    ['long'],
                    ctypes.c_long,
                    0
                )
            ),
            SysCallParamSig(
                'msgflg',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'msgctl': SysCallSig(
        'msgctl',
        params=[
            SysCallParamSig(
                'msqid',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'cmd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'buf',
                CType(
                    ['struct', 'msqid_ds', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'semget': SysCallSig(
        'semget',
        params=[
            SysCallParamSig(
                'key',
                CType(
                    ['key_t'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'nsems',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'semflg',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'semop': SysCallSig(
        'semop',
        params=[
            SysCallParamSig(
                'semid',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'sops',
                CType(
                    ['struct', 'sembuf', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'nsops',
                CType(
                    ['unsigned'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'semctl': SysCallSig(
        'semctl',
        params=[
            SysCallParamSig(
                'semid',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'semnum',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'cmd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'arg',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'semtimedop': SysCallSig(
        'semtimedop',
        params=[
            SysCallParamSig(
                'semid',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'sops',
                CType(
                    ['struct', 'sembuf', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'nsops',
                CType(
                    ['unsigned'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'timeout',
                CType(
                    ['const', 'struct', 'timespec', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'shmat': SysCallSig(
        'shmat',
        params=[
            SysCallParamSig(
                'shmid',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'shmaddr',
                CType(
                    ['char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'shmflg',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'shmget': SysCallSig(
        'shmget',
        params=[
            SysCallParamSig(
                'key',
                CType(
                    ['key_t'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'size',
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'flag',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'shmdt': SysCallSig(
        'shmdt',
        params=[
            SysCallParamSig(
                'shmaddr',
                CType(
                    ['char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'shmctl': SysCallSig(
        'shmctl',
        params=[
            SysCallParamSig(
                'shmid',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'cmd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'buf',
                CType(
                    ['struct', 'shmid_ds', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'ipc': SysCallSig(
        'ipc',
        params=[
            SysCallParamSig(
                'call',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'first',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'second',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'third',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'ptr',
                CType(
                    ['void', '*'],
                    ctypes.c_long,
                    1
                )
            ),
            SysCallParamSig(
                'fifth',
                CType(
                    ['long'],
                    ctypes.c_long,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'mq_open': SysCallSig(
        'mq_open',
        params=[
            SysCallParamSig(
                'name',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'oflag',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'mode',
                CType(
                    ['umode_t'],
                    ctypes.c_ushort,
                    0
                )
            ),
            SysCallParamSig(
                'attr',
                CType(
                    ['struct', 'mq_attr', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'mq_unlink': SysCallSig(
        'mq_unlink',
        params=[
            SysCallParamSig(
                'name',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'mq_timedsend': SysCallSig(
        'mq_timedsend',
        params=[
            SysCallParamSig(
                'mqdes',
                CType(
                    ['mqd_t'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'msg_ptr',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'msg_len',
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'msg_prio',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'abs_timeout',
                CType(
                    ['const', 'struct', 'timespec', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'mq_timedreceive': SysCallSig(
        'mq_timedreceive',
        params=[
            SysCallParamSig(
                'mqdes',
                CType(
                    ['mqd_t'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'msg_ptr',
                CType(
                    ['char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'msg_len',
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'msg_prio',
                CType(
                    ['unsigned', 'int', '*'],
                    ctypes.c_uint,
                    1
                )
            ),
            SysCallParamSig(
                'abs_timeout',
                CType(
                    ['const', 'struct', 'timespec', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'mq_notify': SysCallSig(
        'mq_notify',
        params=[
            SysCallParamSig(
                'mqdes',
                CType(
                    ['mqd_t'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'notification',
                CType(
                    ['const', 'struct', 'sigevent', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'mq_getsetattr': SysCallSig(
        'mq_getsetattr',
        params=[
            SysCallParamSig(
                'mqdes',
                CType(
                    ['mqd_t'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'mqstat',
                CType(
                    ['const', 'struct', 'mq_attr', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'omqstat',
                CType(
                    ['struct', 'mq_attr', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'pciconfig_iobase': SysCallSig(
        'pciconfig_iobase',
        params=[
            SysCallParamSig(
                'which',
                CType(
                    ['long'],
                    ctypes.c_long,
                    0
                )
            ),
            SysCallParamSig(
                'bus',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'devfn',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'pciconfig_read': SysCallSig(
        'pciconfig_read',
        params=[
            SysCallParamSig(
                'bus',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'dfn',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'off',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'len',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'buf',
                CType(
                    ['void', '*'],
                    ctypes.c_long,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'pciconfig_write': SysCallSig(
        'pciconfig_write',
        params=[
            SysCallParamSig(
                'bus',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'dfn',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'off',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'len',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'buf',
                CType(
                    ['void', '*'],
                    ctypes.c_long,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'prctl': SysCallSig(
        'prctl',
        params=[
            SysCallParamSig(
                'option',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'arg2',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'arg3',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'arg4',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'arg5',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'swapon': SysCallSig(
        'swapon',
        params=[
            SysCallParamSig(
                'specialfile',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'swap_flags',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'swapoff': SysCallSig(
        'swapoff',
        params=[
            SysCallParamSig(
                'specialfile',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'sysctl': SysCallSig(
        'sysctl',
        params=[
            SysCallParamSig(
                'args',
                CType(
                    ['struct', '__sysctl_args', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'sysinfo': SysCallSig(
        'sysinfo',
        params=[
            SysCallParamSig(
                'info',
                CType(
                    ['struct', 'sysinfo', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'sysfs': SysCallSig(
        'sysfs',
        params=[
            SysCallParamSig(
                'option',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'arg1',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'arg2',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'syslog': SysCallSig(
        'syslog',
        params=[
            SysCallParamSig(
                'type',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'buf',
                CType(
                    ['char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'len',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'uselib': SysCallSig(
        'uselib',
        params=[
            SysCallParamSig(
                'library',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'ni_syscall': SysCallSig(
        'ni_syscall',
        params=[
            SysCallParamSig(
                None,
                CType(
                    ['void'],
                    ctypes.c_long,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'ptrace': SysCallSig(
        'ptrace',
        params=[
            SysCallParamSig(
                'request',
                CType(
                    ['long'],
                    ctypes.c_long,
                    0
                )
            ),
            SysCallParamSig(
                'pid',
                CType(
                    ['long'],
                    ctypes.c_long,
                    0
                )
            ),
            SysCallParamSig(
                'addr',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'data',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'add_key': SysCallSig(
        'add_key',
        params=[
            SysCallParamSig(
                '_type',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                '_description',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                '_payload',
                CType(
                    ['const', 'void', '*'],
                    ctypes.c_long,
                    1
                )
            ),
            SysCallParamSig(
                'plen',
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'destringid',
                CType(
                    ['key_serial_t'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'request_key': SysCallSig(
        'request_key',
        params=[
            SysCallParamSig(
                '_type',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                '_description',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                '_callout_info',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'destringid',
                CType(
                    ['key_serial_t'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'keyctl': SysCallSig(
        'keyctl',
        params=[
            SysCallParamSig(
                'cmd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'arg2',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'arg3',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'arg4',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'arg5',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'ioprio_set': SysCallSig(
        'ioprio_set',
        params=[
            SysCallParamSig(
                'which',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'who',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'ioprio',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'ioprio_get': SysCallSig(
        'ioprio_get',
        params=[
            SysCallParamSig(
                'which',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'who',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'set_mempolicy': SysCallSig(
        'set_mempolicy',
        params=[
            SysCallParamSig(
                'mode',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'nmask',
                CType(
                    ['const', 'unsigned', 'long', '*'],
                    ctypes.c_ulong,
                    1
                )
            ),
            SysCallParamSig(
                'maxnode',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'migrate_pages': SysCallSig(
        'migrate_pages',
        params=[
            SysCallParamSig(
                'pid',
                CType(
                    ['pid_t'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'maxnode',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'from',
                CType(
                    ['const', 'unsigned', 'long', '*'],
                    ctypes.c_ulong,
                    1
                )
            ),
            SysCallParamSig(
                'to',
                CType(
                    ['const', 'unsigned', 'long', '*'],
                    ctypes.c_ulong,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'move_pages': SysCallSig(
        'move_pages',
        params=[
            SysCallParamSig(
                'pid',
                CType(
                    ['pid_t'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'nr_pages',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'pages',
                CType(
                    ['const', 'void', '*', '*'],
                    ctypes.c_long,
                    2
                )
            ),
            SysCallParamSig(
                'nodes',
                CType(
                    ['const', 'int', '*'],
                    ctypes.c_int,
                    1
                )
            ),
            SysCallParamSig(
                'status',
                CType(
                    ['int', '*'],
                    ctypes.c_int,
                    1
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'mbind': SysCallSig(
        'mbind',
        params=[
            SysCallParamSig(
                'start',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'len',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'mode',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'nmask',
                CType(
                    ['const', 'unsigned', 'long', '*'],
                    ctypes.c_ulong,
                    1
                )
            ),
            SysCallParamSig(
                'maxnode',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['unsigned'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'get_mempolicy': SysCallSig(
        'get_mempolicy',
        params=[
            SysCallParamSig(
                'policy',
                CType(
                    ['int', '*'],
                    ctypes.c_int,
                    1
                )
            ),
            SysCallParamSig(
                'nmask',
                CType(
                    ['unsigned', 'long', '*'],
                    ctypes.c_ulong,
                    1
                )
            ),
            SysCallParamSig(
                'maxnode',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'addr',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'inotify_init': SysCallSig(
        'inotify_init',
        params=[
            SysCallParamSig(
                None,
                CType(
                    ['void'],
                    ctypes.c_long,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'inotify_init1': SysCallSig(
        'inotify_init1',
        params=[
            SysCallParamSig(
                'flags',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'inotify_add_watch': SysCallSig(
        'inotify_add_watch',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'path',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'mask',
                CType(
                    ['u32'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'inotify_rm_watch': SysCallSig(
        'inotify_rm_watch',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'wd',
                CType(
                    ['__s32'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'spu_run': SysCallSig(
        'spu_run',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'unpc',
                CType(
                    ['__u32', '*'],
                    ctypes.c_uint,
                    1
                )
            ),
            SysCallParamSig(
                'ustatus',
                CType(
                    ['__u32', '*'],
                    ctypes.c_uint,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'spu_create': SysCallSig(
        'spu_create',
        params=[
            SysCallParamSig(
                'name',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'mode',
                CType(
                    ['umode_t'],
                    ctypes.c_ushort,
                    0
                )
            ),
            SysCallParamSig(
                'fd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'mknodat': SysCallSig(
        'mknodat',
        params=[
            SysCallParamSig(
                'dfd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'filename',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'mode',
                CType(
                    ['umode_t'],
                    ctypes.c_ushort,
                    0
                )
            ),
            SysCallParamSig(
                'dev',
                CType(
                    ['unsigned'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'mkdirat': SysCallSig(
        'mkdirat',
        params=[
            SysCallParamSig(
                'dfd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'pathname',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'mode',
                CType(
                    ['umode_t'],
                    ctypes.c_ushort,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'unlinkat': SysCallSig(
        'unlinkat',
        params=[
            SysCallParamSig(
                'dfd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'pathname',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'flag',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'symlinkat': SysCallSig(
        'symlinkat',
        params=[
            SysCallParamSig(
                'oldname',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'newdfd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'newname',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'linkat': SysCallSig(
        'linkat',
        params=[
            SysCallParamSig(
                'olddfd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'oldname',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'newdfd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'newname',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'renameat': SysCallSig(
        'renameat',
        params=[
            SysCallParamSig(
                'olddfd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'oldname',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'newdfd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'newname',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'renameat2': SysCallSig(
        'renameat2',
        params=[
            SysCallParamSig(
                'olddfd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'oldname',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'newdfd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'newname',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'futimesat': SysCallSig(
        'futimesat',
        params=[
            SysCallParamSig(
                'dfd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'filename',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'utimes',
                CType(
                    ['struct', 'timeval', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'faccessat': SysCallSig(
        'faccessat',
        params=[
            SysCallParamSig(
                'dfd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'filename',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'mode',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'fchmodat': SysCallSig(
        'fchmodat',
        params=[
            SysCallParamSig(
                'dfd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'filename',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'mode',
                CType(
                    ['umode_t'],
                    ctypes.c_ushort,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'fchownat': SysCallSig(
        'fchownat',
        params=[
            SysCallParamSig(
                'dfd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'filename',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'user',
                CType(
                    ['uid_t'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'group',
                CType(
                    ['gid_t'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'flag',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'openat': SysCallSig(
        'openat',
        params=[
            SysCallParamSig(
                'dfd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'filename',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'mode',
                CType(
                    ['umode_t'],
                    ctypes.c_ushort,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'newfstatat': SysCallSig(
        'newfstatat',
        params=[
            SysCallParamSig(
                'dfd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'filename',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'statbuf',
                CType(
                    ['struct', 'stat', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'flag',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'readlinkat': SysCallSig(
        'readlinkat',
        params=[
            SysCallParamSig(
                'dfd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'path',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'buf',
                CType(
                    ['char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'bufsiz',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'utimensat': SysCallSig(
        'utimensat',
        params=[
            SysCallParamSig(
                'dfd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'filename',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'utimes',
                CType(
                    ['struct', 'timespec', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'unshare': SysCallSig(
        'unshare',
        params=[
            SysCallParamSig(
                'unshare_flags',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'splice': SysCallSig(
        'splice',
        params=[
            SysCallParamSig(
                'fd_in',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'off_in',
                CType(
                    ['loff_t', '*'],
                    ctypes.c_longlong,
                    1
                )
            ),
            SysCallParamSig(
                'fd_out',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'off_out',
                CType(
                    ['loff_t', '*'],
                    ctypes.c_longlong,
                    1
                )
            ),
            SysCallParamSig(
                'len',
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'vmsplice': SysCallSig(
        'vmsplice',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'iov',
                CType(
                    ['const', 'struct', 'iovec', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'nr_segs',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'tee': SysCallSig(
        'tee',
        params=[
            SysCallParamSig(
                'fdin',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'fdout',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'len',
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'sync_file_range': SysCallSig(
        'sync_file_range',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'offset',
                CType(
                    ['loff_t'],
                    ctypes.c_longlong,
                    0
                )
            ),
            SysCallParamSig(
                'nbytes',
                CType(
                    ['loff_t'],
                    ctypes.c_longlong,
                    0
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'sync_file_range2': SysCallSig(
        'sync_file_range2',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'offset',
                CType(
                    ['loff_t'],
                    ctypes.c_longlong,
                    0
                )
            ),
            SysCallParamSig(
                'nbytes',
                CType(
                    ['loff_t'],
                    ctypes.c_longlong,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'get_robust_list': SysCallSig(
        'get_robust_list',
        params=[
            SysCallParamSig(
                'pid',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'head_ptr',
                CType(
                    ['struct', 'robust_list_head', '*', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'len_ptr',
                CType(
                    ['size_t', '*'],
                    ctypes.c_uint,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'set_robust_list': SysCallSig(
        'set_robust_list',
        params=[
            SysCallParamSig(
                'head',
                CType(
                    ['struct', 'robust_list_head', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'len',
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'getcpu': SysCallSig(
        'getcpu',
        params=[
            SysCallParamSig(
                'cpu',
                CType(
                    ['unsigned', '*'],
                    ctypes.c_uint,
                    1
                )
            ),
            SysCallParamSig(
                'node',
                CType(
                    ['unsigned', '*'],
                    ctypes.c_uint,
                    1
                )
            ),
            SysCallParamSig(
                'cache',
                CType(
                    ['struct', 'getcpu_cache', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'signalfd': SysCallSig(
        'signalfd',
        params=[
            SysCallParamSig(
                'ufd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'user_mask',
                CType(
                    ['sigset_t', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'sizemask',
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'signalfd4': SysCallSig(
        'signalfd4',
        params=[
            SysCallParamSig(
                'ufd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'user_mask',
                CType(
                    ['sigset_t', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'sizemask',
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'timerfd_create': SysCallSig(
        'timerfd_create',
        params=[
            SysCallParamSig(
                'clockid',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'timerfd_settime': SysCallSig(
        'timerfd_settime',
        params=[
            SysCallParamSig(
                'ufd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'utmr',
                CType(
                    ['const', 'struct', 'itimerspec', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'otmr',
                CType(
                    ['struct', 'itimerspec', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'timerfd_gettime': SysCallSig(
        'timerfd_gettime',
        params=[
            SysCallParamSig(
                'ufd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'otmr',
                CType(
                    ['struct', 'itimerspec', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'eventfd': SysCallSig(
        'eventfd',
        params=[
            SysCallParamSig(
                'count',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'eventfd2': SysCallSig(
        'eventfd2',
        params=[
            SysCallParamSig(
                'count',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'memfd_create': SysCallSig(
        'memfd_create',
        params=[
            SysCallParamSig(
                'uname_ptr',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'userfaultfd': SysCallSig(
        'userfaultfd',
        params=[
            SysCallParamSig(
                'flags',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'fallocate': SysCallSig(
        'fallocate',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'mode',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'offset',
                CType(
                    ['loff_t'],
                    ctypes.c_longlong,
                    0
                )
            ),
            SysCallParamSig(
                'len',
                CType(
                    ['loff_t'],
                    ctypes.c_longlong,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'old_readdir': SysCallSig(
        'old_readdir',
        params=[
            SysCallParamSig(
                None,
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['struct', 'old_linux_dirent', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'pselect6': SysCallSig(
        'pselect6',
        params=[
            SysCallParamSig(
                None,
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['fd_set', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['fd_set', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['fd_set', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['struct', 'timespec', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['void', '*'],
                    ctypes.c_long,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'ppoll': SysCallSig(
        'ppoll',
        params=[
            SysCallParamSig(
                None,
                CType(
                    ['struct', 'pollfd', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['struct', 'timespec', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['const', 'sigset_t', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'fanotify_init': SysCallSig(
        'fanotify_init',
        params=[
            SysCallParamSig(
                'flags',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'event_f_flags',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'fanotify_mark': SysCallSig(
        'fanotify_mark',
        params=[
            SysCallParamSig(
                'fanotify_fd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'mask',
                CType(
                    ['u64'],
                    ctypes.c_ulonglong,
                    0
                )
            ),
            SysCallParamSig(
                'fd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'pathname',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'syncfs': SysCallSig(
        'syncfs',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'fork': SysCallSig(
        'fork',
        params=[
            SysCallParamSig(
                None,
                CType(
                    ['void'],
                    ctypes.c_long,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'vfork': SysCallSig(
        'vfork',
        params=[
            SysCallParamSig(
                None,
                CType(
                    ['void'],
                    ctypes.c_long,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'clone': SysCallSig(
        'clone',
        params=[
            SysCallParamSig(
                None,
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['int', '*'],
                    ctypes.c_int,
                    1
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['int', '*'],
                    ctypes.c_int,
                    1
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'execve': SysCallSig(
        'execve',
        params=[
            SysCallParamSig(
                'filename',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'argv',
                CType(
                    ['const', 'const', 'char', '*', '*'],
                    ctypes.c_char,
                    2
                )
            ),
            SysCallParamSig(
                'envp',
                CType(
                    ['const', 'const', 'char', '*', '*'],
                    ctypes.c_char,
                    2
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'perf_event_open': SysCallSig(
        'perf_event_open',
        params=[
            SysCallParamSig(
                'attr_uptr',
                CType(
                    ['struct', 'perf_event_attr', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'pid',
                CType(
                    ['pid_t'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'cpu',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'group_fd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'mmap_pgoff': SysCallSig(
        'mmap_pgoff',
        params=[
            SysCallParamSig(
                'addr',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'len',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'prot',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'fd',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'pgoff',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'old_mmap': SysCallSig(
        'old_mmap',
        params=[
            SysCallParamSig(
                'arg',
                CType(
                    ['struct', 'mmap_arg_struct', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'name_to_handle_at': SysCallSig(
        'name_to_handle_at',
        params=[
            SysCallParamSig(
                'dfd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'name',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'handle',
                CType(
                    ['struct', 'file_handle', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'mnt_id',
                CType(
                    ['int', '*'],
                    ctypes.c_int,
                    1
                )
            ),
            SysCallParamSig(
                'flag',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'open_by_handle_at': SysCallSig(
        'open_by_handle_at',
        params=[
            SysCallParamSig(
                'mountdirfd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'handle',
                CType(
                    ['struct', 'file_handle', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'setns': SysCallSig(
        'setns',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'nstype',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'process_vm_readv': SysCallSig(
        'process_vm_readv',
        params=[
            SysCallParamSig(
                'pid',
                CType(
                    ['pid_t'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'lvec',
                CType(
                    ['const', 'struct', 'iovec', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'liovcnt',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'rvec',
                CType(
                    ['const', 'struct', 'iovec', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'riovcnt',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'process_vm_writev': SysCallSig(
        'process_vm_writev',
        params=[
            SysCallParamSig(
                'pid',
                CType(
                    ['pid_t'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'lvec',
                CType(
                    ['const', 'struct', 'iovec', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'liovcnt',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'rvec',
                CType(
                    ['const', 'struct', 'iovec', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'riovcnt',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'kcmp': SysCallSig(
        'kcmp',
        params=[
            SysCallParamSig(
                'pid1',
                CType(
                    ['pid_t'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'pid2',
                CType(
                    ['pid_t'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'type',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'idx1',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'idx2',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'finit_module': SysCallSig(
        'finit_module',
        params=[
            SysCallParamSig(
                'fd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'uargs',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'seccomp': SysCallSig(
        'seccomp',
        params=[
            SysCallParamSig(
                'op',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'uargs',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'getrandom': SysCallSig(
        'getrandom',
        params=[
            SysCallParamSig(
                'buf',
                CType(
                    ['char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'count',
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'bpf': SysCallSig(
        'bpf',
        params=[
            SysCallParamSig(
                'cmd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'attr',
                CType(
                    ['union', 'bpf_attr', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
            SysCallParamSig(
                'size',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'execveat': SysCallSig(
        'execveat',
        params=[
            SysCallParamSig(
                'dfd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'filename',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'argv',
                CType(
                    ['const', 'const', 'char', '*', '*'],
                    ctypes.c_char,
                    2
                )
            ),
            SysCallParamSig(
                'envp',
                CType(
                    ['const', 'const', 'char', '*', '*'],
                    ctypes.c_char,
                    2
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'membarrier': SysCallSig(
        'membarrier',
        params=[
            SysCallParamSig(
                'cmd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'copy_file_range': SysCallSig(
        'copy_file_range',
        params=[
            SysCallParamSig(
                'fd_in',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'off_in',
                CType(
                    ['loff_t', '*'],
                    ctypes.c_longlong,
                    1
                )
            ),
            SysCallParamSig(
                'fd_out',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'off_out',
                CType(
                    ['loff_t', '*'],
                    ctypes.c_longlong,
                    1
                )
            ),
            SysCallParamSig(
                'len',
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'mlock2': SysCallSig(
        'mlock2',
        params=[
            SysCallParamSig(
                'start',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'len',
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'pkey_mprotect': SysCallSig(
        'pkey_mprotect',
        params=[
            SysCallParamSig(
                'start',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'len',
                CType(
                    ['size_t'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'prot',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'pkey',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'pkey_alloc': SysCallSig(
        'pkey_alloc',
        params=[
            SysCallParamSig(
                'flags',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                'init_val',
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'pkey_free': SysCallSig(
        'pkey_free',
        params=[
            SysCallParamSig(
                'pkey',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'statx': SysCallSig(
        'statx',
        params=[
            SysCallParamSig(
                'dfd',
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                'path',
                CType(
                    ['const', 'char', '*'],
                    ctypes.c_char,
                    1
                )
            ),
            SysCallParamSig(
                'flags',
                CType(
                    ['unsigned'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'mask',
                CType(
                    ['unsigned'],
                    ctypes.c_uint,
                    0
                )
            ),
            SysCallParamSig(
                'buffer',
                CType(
                    ['struct', 'statx', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'ioperm': SysCallSig(
        'ioperm',
        params=[
            SysCallParamSig(
                None,
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'iopl': SysCallSig(
        'iopl',
        params=[
            SysCallParamSig(
                None,
                CType(
                    ['unsigned', 'int'],
                    ctypes.c_uint,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'modify_ldt': SysCallSig(
        'modify_ldt',
        params=[
            SysCallParamSig(
                None,
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['void', '*'],
                    ctypes.c_long,
                    1
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
        ],
        result=CType(['int'], ctypes.c_int, 0)
    ),
    'rt_sigreturn': SysCallSig(
        'rt_sigreturn',
        params=[
            SysCallParamSig(
                None,
                CType(
                    ['void'],
                    ctypes.c_long,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'set_thread_area': SysCallSig(
        'set_thread_area',
        params=[
            SysCallParamSig(
                None,
                CType(
                    ['struct', 'user_desc', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'get_thread_area': SysCallSig(
        'get_thread_area',
        params=[
            SysCallParamSig(
                None,
                CType(
                    ['struct', 'user_desc', '*'],
                    ctypes.c_void_p,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'arch_prctl': SysCallSig(
        'arch_prctl',
        params=[
            SysCallParamSig(
                None,
                CType(
                    ['int'],
                    ctypes.c_int,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
    'mmap': SysCallSig(
        'mmap',
        params=[
            SysCallParamSig(
                None,
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
            SysCallParamSig(
                None,
                CType(
                    ['unsigned', 'long'],
                    ctypes.c_ulong,
                    0
                )
            ),
        ],
        result=CType(['long'], ctypes.c_long, 0)
    ),
}

SYSCALL_NUMBERS = {
    0: 'read',
    1: 'write',
    2: 'open',
    3: 'close',
    4: 'stat',
    5: 'fstat',
    6: 'lstat',
    7: 'poll',
    8: 'lseek',
    9: 'mmap',
    10: 'mprotect',
    11: 'munmap',
    12: 'brk',
    13: 'rt_sigaction',
    14: 'rt_sigprocmask',
    15: 'rt_sigreturn',
    16: 'ioctl',
    17: 'pread64',
    18: 'pwrite64',
    19: 'readv',
    20: 'writev',
    21: 'access',
    22: 'pipe',
    23: 'select',
    24: 'sched_yield',
    25: 'mremap',
    26: 'msync',
    27: 'mincore',
    28: 'madvise',
    29: 'shmget',
    30: 'shmat',
    31: 'shmctl',
    32: 'dup',
    33: 'dup2',
    34: 'pause',
    35: 'nanosleep',
    36: 'getitimer',
    37: 'alarm',
    38: 'setitimer',
    39: 'getpid',
    40: 'sendfile',
    41: 'socket',
    42: 'connect',
    43: 'accept',
    44: 'sendto',
    45: 'recvfrom',
    46: 'sendmsg',
    47: 'recvmsg',
    48: 'shutdown',
    49: 'bind',
    50: 'listen',
    51: 'getsockname',
    52: 'getpeername',
    53: 'socketpair',
    54: 'setsockopt',
    55: 'getsockopt',
    56: 'clone',
    57: 'fork',
    58: 'vfork',
    59: 'execve',
    60: 'exit',
    61: 'wait4',
    62: 'kill',
    63: 'uname',
    64: 'semget',
    65: 'semop',
    66: 'semctl',
    67: 'shmdt',
    68: 'msgget',
    69: 'msgsnd',
    70: 'msgrcv',
    71: 'msgctl',
    72: 'fcntl',
    73: 'flock',
    74: 'fsync',
    75: 'fdatasync',
    76: 'truncate',
    77: 'ftruncate',
    78: 'getdents',
    79: 'getcwd',
    80: 'chdir',
    81: 'fchdir',
    82: 'rename',
    83: 'mkdir',
    84: 'rmdir',
    85: 'creat',
    86: 'link',
    87: 'unlink',
    88: 'symlink',
    89: 'readlink',
    90: 'chmod',
    91: 'fchmod',
    92: 'chown',
    93: 'fchown',
    94: 'lchown',
    95: 'umask',
    96: 'gettimeofday',
    97: 'getrlimit',
    98: 'getrusage',
    99: 'sysinfo',
    100: 'times',
    101: 'ptrace',
    102: 'getuid',
    103: 'syslog',
    104: 'getgid',
    105: 'setuid',
    106: 'setgid',
    107: 'geteuid',
    108: 'getegid',
    109: 'setpgid',
    110: 'getppid',
    111: 'getpgrp',
    112: 'setsid',
    113: 'setreuid',
    114: 'setregid',
    115: 'getgroups',
    116: 'setgroups',
    117: 'setresuid',
    118: 'getresuid',
    119: 'setresgid',
    120: 'getresgid',
    121: 'getpgid',
    122: 'setfsuid',
    123: 'setfsgid',
    124: 'getsid',
    125: 'capget',
    126: 'capset',
    127: 'rt_sigpending',
    128: 'rt_sigtimedwait',
    129: 'rt_sigqueueinfo',
    130: 'rt_sigsuspend',
    131: 'sigaltstack',
    132: 'utime',
    133: 'mknod',
    134: 'uselib',
    135: 'personality',
    136: 'ustat',
    137: 'statfs',
    138: 'fstatfs',
    139: 'sysfs',
    140: 'getpriority',
    141: 'setpriority',
    142: 'sched_setparam',
    143: 'sched_getparam',
    144: 'sched_setscheduler',
    145: 'sched_getscheduler',
    146: 'sched_get_priority_max',
    147: 'sched_get_priority_min',
    148: 'sched_rr_get_interval',
    149: 'mlock',
    150: 'munlock',
    151: 'mlockall',
    152: 'munlockall',
    153: 'vhangup',
    154: 'modify_ldt',
    155: 'pivot_root',
    156: '_sysctl',
    157: 'prctl',
    158: 'arch_prctl',
    159: 'adjtimex',
    160: 'setrlimit',
    161: 'chroot',
    162: 'sync',
    163: 'acct',
    164: 'settimeofday',
    165: 'mount',
    166: 'umount2',
    167: 'swapon',
    168: 'swapoff',
    169: 'reboot',
    170: 'sethostname',
    171: 'setdomainname',
    172: 'iopl',
    173: 'ioperm',
    174: 'create_module',
    175: 'init_module',
    176: 'delete_module',
    177: 'get_kernel_syms',
    178: 'query_module',
    179: 'quotactl',
    180: 'nfsservctl',
    181: 'getpmsg',
    182: 'putpmsg',
    183: 'afs_syscall',
    184: 'tuxcall',
    185: 'security',
    186: 'gettid',
    187: 'readahead',
    188: 'setxattr',
    189: 'lsetxattr',
    190: 'fsetxattr',
    191: 'getxattr',
    192: 'lgetxattr',
    193: 'fgetxattr',
    194: 'listxattr',
    195: 'llistxattr',
    196: 'flistxattr',
    197: 'removexattr',
    198: 'lremovexattr',
    199: 'fremovexattr',
    200: 'tkill',
    201: 'time',
    202: 'futex',
    203: 'sched_setaffinity',
    204: 'sched_getaffinity',
    205: 'set_thread_area',
    206: 'io_setup',
    207: 'io_destroy',
    208: 'io_getevents',
    209: 'io_submit',
    210: 'io_cancel',
    211: 'get_thread_area',
    212: 'lookup_dcookie',
    213: 'epoll_create',
    214: 'epoll_ctl_old',
    215: 'epoll_wait_old',
    216: 'remap_file_pages',
    217: 'getdents64',
    218: 'set_tid_address',
    219: 'restart_syscall',
    220: 'semtimedop',
    221: 'fadvise64',
    222: 'timer_create',
    223: 'timer_settime',
    224: 'timer_gettime',
    225: 'timer_getoverrun',
    226: 'timer_delete',
    227: 'clock_settime',
    228: 'clock_gettime',
    229: 'clock_getres',
    230: 'clock_nanosleep',
    231: 'exit_group',
    232: 'epoll_wait',
    233: 'epoll_ctl',
    234: 'tgkill',
    235: 'utimes',
    236: 'vserver',
    237: 'mbind',
    238: 'set_mempolicy',
    239: 'get_mempolicy',
    240: 'mq_open',
    241: 'mq_unlink',
    242: 'mq_timedsend',
    243: 'mq_timedreceive',
    244: 'mq_notify',
    245: 'mq_getsetattr',
    246: 'kexec_load',
    247: 'waitid',
    248: 'add_key',
    249: 'request_key',
    250: 'keyctl',
    251: 'ioprio_set',
    252: 'ioprio_get',
    253: 'inotify_init',
    254: 'inotify_add_watch',
    255: 'inotify_rm_watch',
    256: 'migrate_pages',
    257: 'openat',
    258: 'mkdirat',
    259: 'mknodat',
    260: 'fchownat',
    261: 'futimesat',
    262: 'newfstatat',
    263: 'unlinkat',
    264: 'renameat',
    265: 'linkat',
    266: 'symlinkat',
    267: 'readlinkat',
    268: 'fchmodat',
    269: 'faccessat',
    270: 'pselect6',
    271: 'ppoll',
    272: 'unshare',
    273: 'set_robust_list',
    274: 'get_robust_list',
    275: 'splice',
    276: 'tee',
    277: 'sync_file_range',
    278: 'vmsplice',
    279: 'move_pages',
    280: 'utimensat',
    281: 'epoll_pwait',
    282: 'signalfd',
    283: 'timerfd_create',
    284: 'eventfd',
    285: 'fallocate',
    286: 'timerfd_settime',
    287: 'timerfd_gettime',
    288: 'accept4',
    289: 'signalfd4',
    290: 'eventfd2',
    291: 'epoll_create1',
    292: 'dup3',
    293: 'pipe2',
    294: 'inotify_init1',
    295: 'preadv',
    296: 'pwritev',
    297: 'rt_tgsigqueueinfo',
    298: 'perf_event_open',
    299: 'recvmmsg',
    300: 'fanotify_init',
    301: 'fanotify_mark',
    302: 'prlimit64',
    303: 'name_to_handle_at',
    304: 'open_by_handle_at',
    305: 'clock_adjtime',
    306: 'syncfs',
    307: 'sendmmsg',
    308: 'setns',
    309: 'getcpu',
    310: 'process_vm_readv',
    311: 'process_vm_writev',
    312: 'kcmp',
    313: 'finit_module',
    314: 'sched_setattr',
    315: 'sched_getattr',
    316: 'renameat2',
    317: 'seccomp',
    318: 'getrandom',
    319: 'memfd_create',
    320: 'kexec_file_load',
    321: 'bpf',
    322: 'execveat',
    323: 'userfaultfd',
    324: 'membarrier',
    325: 'mlock2',
    326: 'copy_file_range',
    327: 'preadv2',
    328: 'pwritev2',
    329: 'pkey_mprotect',
    330: 'pkey_alloc',
    331: 'pkey_free',
    332: 'statx',
}
