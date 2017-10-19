/* Copyright (C) 2017-present Pinterest Inc.
 *
 * This module is part of ptracer and is released under
 * the Apache 2.0 License: http://www.apache.org/licenses/LICENSE-2.0
 */

#include <errno.h>
#include <stdint.h>
#include <sys/ptrace.h>

#ifdef __linux__
#include <sys/prctl.h>
#endif

#include "Python.h"


#ifdef PR_SET_PTRACER
static PyObject*
_set_ptracer(PyObject *self, PyObject *args, PyObject *kwargs)
{
    static char *kwlist[] = {"pid", NULL};
    pid_t pid;
    int err = 0;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwargs, "i:set_ptracer", kwlist, &pid))
    {
        goto error;
    }

    if (prctl(PR_SET_PTRACER, pid, 0, 0, 0) < 0) {
        PyErr_SetFromErrno(PyExc_OSError);
        goto error;
    }

    goto finally;

error:
    err = 1;

finally:
    if (err) {
        return NULL;
    } else {
        Py_RETURN_NONE;
    }
}
#endif  // PR_SET_PTRACER


static PyObject*
_ptrace(PyObject *self, PyObject *args, PyObject *kwargs)
{
    static char *kwlist[] = {"request", "pid", "addr", "data", NULL};
    unsigned int request;
    pid_t pid;
    void *addr;
    void *data;
    int err = 0;
    long ptrace_result;
    PyObject *result;

#if UINTPTR_MAX == 0xffffffffffffffff
    static const char _ptrace_argfmt[] = "Ii|KK:ptrace";
#elif UINTPTR_MAX == 0xffffffff
    static const char _ptrace_argfmt[] = "Ii|kk:ptrace";
#endif

    if (!PyArg_ParseTupleAndKeywords(args, kwargs,
            _ptrace_argfmt, kwlist, &request, &pid, &addr, &data))
    {
        goto error;
    }

    errno = 0;
    ptrace_result = ptrace(request, pid, addr, data);
    if (ptrace_result == -1 && errno != 0) {
        PyErr_SetFromErrno(PyExc_OSError);
        goto error;
    }

    result = PyLong_FromLong(ptrace_result);
    if (result == NULL) {
        goto error;
    }

    goto finally;

error:
    err = 1;

finally:
    if (err) {
        return NULL;
    } else {
        return result;
    }
}


PyDoc_STRVAR(module_doc,
"ptrace binding");

static PyMethodDef module_methods[] = {
    {"ptrace",
     (PyCFunction)_ptrace, METH_VARARGS | METH_KEYWORDS,
     PyDoc_STR("process trace")},
#ifdef PR_SET_PTRACER
    {"set_ptracer",
     (PyCFunction)_set_ptracer, METH_VARARGS | METH_KEYWORDS,
     PyDoc_STR("allow *pid* to trace the current process")},
#endif
    {NULL, NULL}  /* sentinel */
};

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef module_def = {
    PyModuleDef_HEAD_INIT,
    "_ptrace",
    module_doc,
    0, /* non negative size to be able to unload the module */
    module_methods,
    NULL,
    NULL,
    NULL,
    NULL
};
#endif


PyMODINIT_FUNC
#if PY_MAJOR_VERSION >= 3
PyInit__ptrace(void)
#else
init_ptrace(void)
#endif
{
    PyObject *m;

#if PY_MAJOR_VERSION >= 3
    m = PyModule_Create(&module_def);
#else
    m = Py_InitModule3("_ptrace", module_methods, module_doc);
#endif
    if (m == NULL) {
#if PY_MAJOR_VERSION >= 3
        return NULL;
#else
        return;
#endif
    }

#if PY_MAJOR_VERSION >= 3
    return m;
#else
    return;
#endif
}
