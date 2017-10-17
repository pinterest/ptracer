#!/usr/bin/env python
#
# Copyright (C) 2017-present Pinterest Inc.
#
# This module is part of ptracer and is released under
# the Apache 2.0 License: http://www.apache.org/licenses/LICENSE-2.0


import argparse
import ctypes
import operator
import os
import re
import tempfile

import pycparser
from pycparserext import ext_c_parser
from pycparser import c_ast


def main():
    parser = argparse.ArgumentParser(
        description='generate ptrace/defs.py from sys/ptrace.h')
    parser.add_argument('-I', type=str, help='include path',
                        dest='include_path', nargs='*', default=[
                            '/usr/src/linux/include',
                            '/usr/src/linux/arch/x86/include/',
                            '/usr/src/linux/arch/x86/include/generated/'
                        ])
    parser.add_argument('--ptrace-h', type=str, dest='ptrace_h',
                        default='/usr/include/sys/ptrace.h',
                        help='path to sys/ptrace.h')
    parser.add_argument('--user-h', type=str, dest='user_h',
                        default='/usr/include/sys/user.h',
                        help='path to sys/user.h')
    parser.add_argument('--signal-h', type=str, dest='signal_h',
                        default='/usr/include/signal.h',
                        help='path to signal.h')
    parser.add_argument('--linux-src', type=str, dest='linux_tree',
                        default='/usr/src/linux',
                        help='path to linux kernel source tree')

    args = parser.parse_args()

    output = []
    output.append('# Automatically generated from system headers.')
    output.append('# DO NOT EDIT.')
    output.append('\nimport ctypes')
    output.append(
        '\nfrom .syscalldef import CType, SysCallSig, SysCallParamSig')

    output.extend(read_ptrace_h(args.ptrace_h, args.include_path))
    output.extend(read_user_h(args.user_h, args.include_path))
    output.extend(read_signal_h(args.signal_h, args.include_path))

    # Generic syscalls.
    syscalls_h = os.path.join(args.linux_tree, 'include/linux/syscalls.h')
    # Arch-specific syscalls.
    arch_syscalls_h = os.path.join(
        args.linux_tree, 'arch/x86/include/asm/syscalls.h')
    output.extend(read_syscalls_h([syscalls_h, arch_syscalls_h],
                                  args.include_path))

    unistd_h = os.path.join(
        args.linux_tree, 'arch/x86/include/generated/uapi/asm/unistd_64.h')
    output.extend(read_unistd_h(unistd_h, args.include_path))

    print('\n'.join(output))


def die(msg):
    raise ValueError(msg)


def get_header_text(path, include_path=[], defines=[], strip_includes=False):
    if strip_includes:
        with open(path, 'r') as f:
            text = f.read()

        text = re.sub(r'#include.*', '', text)
        tfile, path = tempfile.mkstemp()
        try:
            os.write(tfile, text.encode('utf-8'))
        finally:
            os.close(tfile)

    else:
        tfile = None

    cpp_args = []

    if include_path:
        for ip in include_path:
            cpp_args.extend(['-I', ip])

    if defines:
        for d in defines:
            cpp_args.extend(['-D', d])

    try:
        text = pycparser.preprocess_file(path, cpp_args=cpp_args)
    finally:
        if tfile is not None:
            os.unlink(path)

    return text


def read_ptrace_h(path, include_path):
    text = get_header_text(path, include_path)
    parser = ext_c_parser.GnuCParser()
    fileast = parser.parse(text, path)

    if not isinstance(fileast, c_ast.FileAST):
        die('could not parse user.h')

    output = ['\n']

    for decl in fileast.ext:
        if (not isinstance(decl, c_ast.Decl) or
                not isinstance(decl.type, c_ast.Enum)):
            continue

        for item in decl.type.values.enumerators:
            if item.name.startswith('PTRACE_'):
                output.append('{} = {}'.format(
                    item.name, render_const(item.value)))

    typedefs = parse_typedefs(fileast)
    structs = {'__ptrace_peeksiginfo_args'}
    output.extend(parse_structs(fileast, structs, typedefs))

    return output


def render_const(value):
    if isinstance(value, c_ast.Constant):
        return value.value
    elif isinstance(value, c_ast.BinaryOp):
        return '{} {} {}'.format(
            render_const(value.left), value.op, render_const(value.right))
    else:
        die('unexpected constant value: {!r}'.format(value))


def read_user_h(path, include_path):
    text = get_header_text(path, include_path)
    parser = ext_c_parser.GnuCParser()
    fileast = parser.parse(text, path)

    if not isinstance(fileast, c_ast.FileAST):
        die('could not parse user.h')

    typedefs = parse_typedefs(fileast)
    structs = {'user_regs_struct', 'user_fpregs_struct'}
    return parse_structs(fileast, structs, typedefs)


def read_signal_h(path, include_path):
    text = get_header_text(path, include_path)
    parser = ext_c_parser.GnuCParser()
    fileast = parser.parse(text, path)

    if not isinstance(fileast, c_ast.FileAST):
        die('could not parse signal.h')

    typedefs = parse_typedefs(fileast)
    structs = {'siginfo_t'}
    return parse_structs(fileast, structs, typedefs)


def read_syscalls_h(paths, include_path, defines=[]):
    output = ['\n\nSYSCALLS = {']

    for path in paths:
        output.extend(_read_syscalls_h(path, include_path, defines))

    output.append('}')

    return output


def _read_syscalls_h(path, include_path, defines):
    output = []

    text = get_header_text(path, include_path, defines=defines,
                           strip_includes=True)

    parser = pycparser.CParser()

    typedefs = [
        'typedef unsigned int qid_t;',
        'typedef long time_t;',
        'typedef unsigned int uid_t;',
        'typedef unsigned int gid_t;',
        'typedef unsigned short old_uid_t;',
        'typedef unsigned short old_gid_t;',
        'typedef int pid_t;',
        'typedef void *cap_user_header_t;',
        'typedef void *cap_user_data_t;',
        'typedef unsigned long old_sigset_t;',
        'typedef int timer_t;',
        'typedef int clockid_t;',
        'typedef unsigned int u32;',
        'typedef unsigned int __u32;',
        'typedef int __s32;',
        'typedef unsigned long long u64;',
        'typedef unsigned long sigset_t;',
        'typedef unsigned int size_t;',
        'typedef struct siginfo_t siginfo_t;',
        'typedef struct sigset_t sigset_t;',
        'typedef struct fd_set fd_set;',
        'typedef void *__sighandler_t;',
        'typedef long long off_t;',
        'typedef long long loff_t;',
        'typedef unsigned short umode_t;',
        'typedef unsigned long aio_context_t;',
        'typedef int key_t;',
        'typedef int mqd_t;',
        'typedef int key_serial_t;',
    ]

    text = '\n'.join(typedefs) + '\n' + text
    text = re.sub(r'asmlinkage|__user', '', text)
    text = re.sub(r'\*\s*\*\s*(\W)', '**__foo\\1', text)

    fileast = parser.parse(text, path)

    if not isinstance(fileast, c_ast.FileAST):
        die('could not parse syscalls.h')

    typedefs = parse_typedefs(fileast)

    for decl in fileast.ext:
        if (not isinstance(decl, c_ast.Decl) or
                not isinstance(decl.type, c_ast.FuncDecl)):
            continue

        if not decl.name.startswith('sys_'):
            continue

        name = decl.name[len('sys_'):]

        output.append('    {!r}: SysCallSig('.format(name))
        output.append('        {!r},'.format(name))
        output.append('        params=[')

        params = decl.type.args.params
        for param in params:
            pdecl = []
            pdecl.append('SysCallParamSig(')
            pdecl.append('    {!r},'.format(param.name))
            pdecl.append('    CType(')
            ctype, ptr_indirection = get_ctypes_type(param.type, typedefs)
            pdecl.append('        {!r},'.format(render_type(param.type)))
            pdecl.append('        {},'.format(ctype))
            pdecl.append('        {}'.format(ptr_indirection))
            pdecl.append('    )')
            pdecl.append('),')

            output.extend('            {}'.format(p) for p in pdecl)

        output.append('        ],')

        ctype, ptr_indirection = get_ctypes_type(decl.type.type, typedefs)
        output.append('        result=CType({!r}, {}, {})'.format(
            render_type(decl.type.type), ctype, ptr_indirection
        ))
        output.append('    ),')

    return output


def read_unistd_h(path, include_path):
    with open(path, 'r') as f:
        text = f.read()

    output = ['\nSYSCALL_NUMBERS = {']

    for name, no in re.findall(r'#define\s+__NR_(\w+)\s+(\d+)', text):
        output.append('    {}: {!r},'.format(no, name))

    output.append('}')

    return output


def parse_typedefs(fileast):
    typedefs = {}

    for decl in fileast.ext:
        if not isinstance(decl, c_ast.Typedef):
            continue

        typedefs[decl.name] = render_type(decl.type)

    return typedefs


def parse_structs(fileast, structs, typedefs):
    output = []

    for decl in fileast.ext:
        if ((not isinstance(decl, c_ast.Decl) or
                not isinstance(decl.type, c_ast.Struct)) and
                not isinstance(decl, c_ast.Typedef)):
            continue

        struct, struct_name = get_struct_and_name(decl)
        if struct_name not in structs:
            continue

        definitions = parse_struct(decl, typedefs)

        for name, base, fields in definitions:
            output.append('\n\nclass {}({}):'.format(name, base))
            output.append('    _fields_ = (')
            for field_name, field_type in fields:
                output.append('        ({!r}, {}),'.format(
                    field_name, field_type))
            output.append('    )')

    return output


_anon_struct_ctr = 1


def get_struct_and_name(decl):
    if isinstance(decl, c_ast.Typedef):
        struct = decl.type.type
        struct_name = decl.name
    else:
        struct = decl.type
        struct_name = struct.name

    if not struct_name:
        global _anon_struct_ctr

        struct_name = '_anon_{}'.format(_anon_struct_ctr)
        _anon_struct_ctr += 1

    return struct, struct_name


def parse_struct(decl, typedefs, is_union=False):
    definitions = []

    struct, struct_name = get_struct_and_name(decl)

    fields = []

    for field_decl in struct.decls:
        if isinstance(field_decl.type.type, c_ast.Union):
            definitions.extend(
                parse_struct(field_decl.type, typedefs, is_union=True))
            ctype = definitions[-1][0]

        elif isinstance(field_decl.type.type, c_ast.Struct):
            definitions.extend(
                parse_struct(field_decl.type, typedefs))
            ctype = definitions[-1][0]
        else:
            ctype = get_final_ctypes_type(field_decl.type, typedefs)

        fields.append((field_decl.name, ctype))

    base = 'ctypes.Union' if is_union else 'ctypes.Structure'
    definitions.append((struct_name, base, fields))

    return definitions


ctype_map = {
    ('void',): 'ctypes.c_long',
    ('char',): 'ctypes.c_char',
    ('unsigned', 'char',): 'ctypes.c_char',
    ('unsigned', 'short'): 'ctypes.c_ushort',
    ('unsigned', 'short', 'int'): 'ctypes.c_ushort',
    ('unsigned', 'int'): 'ctypes.c_uint',
    ('unsigned',): 'ctypes.c_uint',
    ('unsigned', 'long'): 'ctypes.c_ulong',
    ('unsigned', 'long', 'int'): 'ctypes.c_ulong',
    ('unsigned', 'long', 'long',): 'ctypes.c_ulonglong',
    ('unsigned', 'long', 'long', 'int'): 'ctypes.c_ulonglong',
    ('__uint64_t',): 'ctypes.c_uint64',
    ('__uint32_t',): 'ctypes.c_uint32',
    ('__uint16_t',): 'ctypes.c_uint16',
    ('short',): 'ctypes.c_short',
    ('short', 'int'): 'ctypes.c_short',
    ('int',): 'ctypes.c_int',
    ('signed', 'int'): 'ctypes.c_int',
    ('long',): 'ctypes.c_long',
    ('long', 'int'): 'ctypes.c_long',
    ('long', 'long'): 'ctypes.c_longlong',
    ('long', 'long', 'int'): 'ctypes.c_longlong',
    ('__int64_t',): 'ctypes.c_int64',
    ('__int32_t',): 'ctypes.c_int32',
    ('__int16_t',): 'ctypes.c_int16',
}


def get_ctypes_type(typedecl, typedefs):
    ptr_indirection = 0

    if isinstance(typedecl, c_ast.TypeDecl):
        if isinstance(typedecl.type, c_ast.IdentifierType):
            tnames = typedecl.type.names

            while True:
                if ((len(tnames) == 1 and tnames[0] in typedefs) or
                        (tnames[-1] in typedefs and tnames[-2] not in
                            {'struct', 'union'})):
                    tnames = list(tnames[:-1]) + list(typedefs[tnames[-1]])
                else:
                    break

            ptr_indirection = 1 if tnames[-1] == '*' else 0
            if ptr_indirection:
                tnames = tnames[:-1]

            if len(tnames) > 1 and tnames[-2] == 'struct':
                ctype = 'ctypes.c_void_p'
                ptr_indirection = 0
            elif len(tnames) > 1 and tnames[-2] == 'union':
                ctype = 'ctypes.c_void_p'
                ptr_indirection = 0
            else:
                ctype = ctype_map.get(tuple(tnames))
                if ctype is None:
                    die('unrecognized C type: {}'.format(' '.join(tnames)))

        elif isinstance(typedecl.type, c_ast.Struct):
            ctype = 'ctypes.c_void_p'

        elif isinstance(typedecl.type, c_ast.Union):
            ctype = 'ctypes.c_void_p'

        else:
            die('unexpected syntax in type declaration: {!r}'.format(
                typedecl.type))

    elif isinstance(typedecl, c_ast.PtrDecl):
        ctype, ptr_indirection = get_ctypes_type(
            typedecl.type, typedefs)

        if ctype != 'ctypes.c_void_p':
            ptr_indirection += 1

    elif isinstance(typedecl, c_ast.ArrayDecl):
        array_type, ptr_indirection = get_ctypes_type(typedecl.type, typedefs)
        dim = fold_const_expr(typedecl.dim, typedefs)
        ctype = '{} * {}'.format(array_type, dim)

    else:
        die('unexpected syntax in type declaration: {!r}'.format(
            typedecl))

    return ctype, ptr_indirection


def get_final_ctypes_type(typedecl, typedefs):
    ctype, ptr_indirection = get_ctypes_type(typedecl, typedefs)

    if ptr_indirection:
        if ctype == 'ctypes.c_char':
            ctype = 'ctypes.c_char_p'
        else:
            ctype = 'ctypes.c_void_p'

    return ctype


_binopmap = {
    '+': operator.add,
    '-': operator.sub,
    '*': operator.mul,
    '/': operator.floordiv,
    '<<': operator.lshift,
    '>>': operator.rshift
}


_unopmap = {
    '+': operator.pos,
    '-': operator.neg,
    'sizeof': ctypes.sizeof,
}


_literalmap = {
    'int': int,
    'char': int,
    'float': float,
}


def fold_const_expr(expr, typedefs):
    if isinstance(expr, c_ast.BinaryOp):
        left = fold_const_expr(expr.left, typedefs)
        right = fold_const_expr(expr.right, typedefs)
        oper = _binopmap.get(expr.op)
        if oper is None:
            die('cannot fold binop with {!r}'.format(expr.op))

        result = oper(left, right)

    elif isinstance(expr, c_ast.UnaryOp):
        operand = fold_const_expr(expr.expr, typedefs)
        oper = _unopmap.get(expr.op)

        if oper is None:
            die('cannot fold unop with {!r}'.format(expr.op))

        result = oper(operand)

    elif isinstance(expr, c_ast.Constant):
        lit_type = _literalmap.get(expr.type)
        if lit_type is None:
            die('unexpected constant type: {!r}'.format(expr.type))
        result = lit_type(expr.value)

    elif isinstance(expr, c_ast.Typename):
        # sizeof operand
        result = get_final_ctypes_type(expr.type, typedefs)
        _, _, typ = result.rpartition('.')
        result = getattr(ctypes, typ)

    else:
        die('cannot fold {!r} expr'.format(expr))

    return result


def render_type(typedecl):
    res = []

    if isinstance(typedecl, (c_ast.TypeDecl, c_ast.Typename)):
        res.extend(typedecl.quals)
        res.extend(render_type(typedecl.type))

    elif isinstance(typedecl, c_ast.PtrDecl):
        res.extend(typedecl.quals)
        res.extend(render_type(typedecl.type))
        res.append('*')

    elif isinstance(typedecl, c_ast.IdentifierType):
        res.extend(typedecl.names)

    elif isinstance(typedecl, c_ast.Struct):
        res.extend(['struct', typedecl.name])

    elif isinstance(typedecl, c_ast.Union):
        res.extend(['union', typedecl.name])

    elif isinstance(typedecl, (c_ast.FuncDecl, ext_c_parser.FuncDeclExt)):
        ret = render_type(typedecl.type)
        args = []
        for param in typedecl.args.params:
            args.append(' '.join(render_type(param)))
        ret.append('({})'.format(', '.join(args)))

        res.extend(ret)

    elif isinstance(typedecl, c_ast.ArrayDecl):
        res.extend(render_type(typedecl.type))
        if typedecl.dim is None:
            res.append('[]')
        elif isinstance(typedecl.dim, c_ast.Constant):
            res.append('[{}]'.format(typedecl.dim.value))
        else:
            die('non-constant dimension in array declaration')

    else:
        die('unexpected {!r}'.format(typedecl))

    return res


if __name__ == '__main__':
    main()
