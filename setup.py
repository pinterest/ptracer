import os
import os.path
import sys

import setuptools


CFLAGS = ['-Wall', '-Wsign-compare', '-Wconversion']


if sys.platform in ('win32', 'cygwin', 'cli'):
    raise RuntimeError('ptracer is a Unix-only library')

with open(os.path.join(os.path.dirname(__file__), 'README.rst')) as f:
    readme = f.read()

with open(os.path.join(
        os.path.dirname(__file__), 'ptracer', '__init__.py')) as f:
    for line in f:
        if line.startswith('__version__ ='):
            _, _, version = line.partition('=')
            VERSION = version.strip(" \n'\"")
            break
    else:
        raise RuntimeError(
            'unable to read the version from ptracer/__init__.py')

setuptools.setup(
    name='ptracer',
    version=VERSION,
    description='On-demand system call tracing for Python programs.',
    long_description=readme,
    classifiers=[
        'License :: OSI Approved :: Apache Software License',
        'Intended Audience :: Developers',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Operating System :: POSIX :: Linux',
        'Development Status :: 4 - Beta',
    ],
    platforms=['POSIX'],
    license='Apache License, Version 2.0',
    provides=['ptracer'],
    packages=['ptracer', 'ptracer.ptrace'],
    ext_modules=[
        setuptools.Extension(
            'ptracer._lltraceback',
            ['ptracer/_lltraceback.c'],
            extra_compile_args=CFLAGS,
        ),
        setuptools.Extension(
            'ptracer.ptrace._ptrace',
            ['ptracer/ptrace/_ptrace.c'],
            extra_compile_args=CFLAGS,
        )
    ],
    test_suite='tests.suite',
)
