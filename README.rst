ptracer -- a library for ptrace-based tracing of Python programs
================================================================

Ptracer is a library providing on-demand system call tracing in Python
programs.


Basic Usage
-----------

.. code-block:: python

    import traceback
    import ptracer

    def callback(syscall):
        print('{}({}) -> {}'.format(
            syscall.name,
            ', '.join(repr(arg.value) for arg in syscall.args),
            syscall.result.text))
        print('Traceback: ')
        print(''.join(traceback.format_list(syscall.traceback)))

    with ptracer.context(callback):
        open('/dev/null', 'wb')


Filtering
---------

Ptracer allows elaborate syscall filtering via the *filter* argument:

.. code-block:: python

    flt = [
        ptracer.SysCallPattern(
            name='open',
            args=[
                re.compile(b'/tmp/.*'),
                lambda arg: arg.value & os.O_WRONLY
            ],
            result=lambda res: res.value > 0
        )
    ]

    with ptracer.context(callback, filter=flt):
        # traced code
        ...


In the above example, ptracer will invoke the callback only for successful
attempts to open files in the "/tmp" directory for writing.


Documentation
-------------

The documentation is available on
`ptracer.readthedocs.io <https://ptracer.readthedocs.io/>`_.
