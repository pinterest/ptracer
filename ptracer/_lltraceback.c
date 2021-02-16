/* Copyright (C) 2017-present Pinterest Inc.
 *
 * This module is part of ptracer and is released under
 * the Apache 2.0 License: http://www.apache.org/licenses/LICENSE-2.0
 */

#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <fcntl.h>

#ifdef __linux__
#include <sys/syscall.h>
#endif
#ifdef __APPLE__
#include <mach/mach.h>
#endif
#ifdef __DragonFly__
#include <sys/lwp.h>
#endif
#ifdef __FreeBSD__
#include <sys/thr.h>
#endif
#ifdef __NetBSD__
#include <lwp.h>
#endif

#include <pthread.h>

#include "Python.h"
#include "frameobject.h"


#if PY_MAJOR_VERSION >= 3
#  define PYSTRING_CHECK PyUnicode_Check
#else
#  define PYSTRING_CHECK PyString_Check
#endif

// bpo-42262 added Py_XNewRef() to Python 3.10.0a3
#if PY_VERSION_HEX < 0x030A00A3 && !defined(Py_XNewRef)
static inline PyObject* _Py_XNewRef(PyObject *obj)
{
    Py_XINCREF(obj);
    return obj;
}
#define Py_XNewRef(obj) _Py_XNewRef((PyObject*)(obj))
#endif

// bpo-40429 added PyThreadState_GetFrame() to Python 3.9.0b1
#if PY_VERSION_HEX < 0x030900B1
static inline PyFrameObject*
PyThreadState_GetFrame(PyThreadState *tstate)
{
    assert(tstate != NULL);
    return (PyFrameObject *)Py_XNewRef(tstate->frame);
}
#endif


static long
_portable_gettid(void)
{
    long tid = -1;

#if defined(__linux__)
    tid = syscall(__NR_gettid);
#elif defined (__APPLE__)
    tid = mach_thread_self();
    // On Mach thread_t is a refcounted resource (a "send right"),
    // so we need to "release" it.
    mach_port_deallocate(mach_task_self(), tid);
#elif defined (__DragonFly__)
    tid = lwp_gettid();
#elif defined (__FreeBSD__)
    thr_self(&tid);
#elif defined (__NetBSD__)
    tid = _lwp_self();
#elif defined (__OpenBSD__)
    tid = getthrid();
#else
    errno = ENOSYS;
#endif

    return tid;
}


static PyObject*
lltraceback_gettid(PyObject *self)
{
    return PyLong_FromLong(_portable_gettid());
}


struct lltraceback_thread_map_entry {
    long kernel_tid;
    long python_tid;
};


struct lltraceback_thread_map {
    size_t count;
    size_t capacity;
    struct lltraceback_thread_map_entry *entries;
};


struct lltraceback_state {
    int enabled;
    int ctlreadfd;
    int ctlwritefd;
    int inputfd;
    int outputfd;
    PyInterpreterState *interp;
    pthread_t thread_id;
    struct lltraceback_thread_map thread_map;
};


static struct lltraceback_state _state;


static struct lltraceback_thread_map_entry *
lltraceback_thread_map_find(struct lltraceback_thread_map *map,
                            long kernel_tid)
{
    size_t i;
    for (i = 0; i < map->count; i++) {
        if (map->entries[i].kernel_tid == kernel_tid) {
            return map->entries + i;
        }
    }

    return NULL;
}

static long
lltraceback_thread_map_get(struct lltraceback_thread_map *map, long kernel_tid)
{
    struct lltraceback_thread_map_entry *entry;

    entry = lltraceback_thread_map_find(map, kernel_tid);
    if (entry != NULL) {
        return entry->python_tid;
    } else {
        return 0L;
    }
}

static int
lltraceback_thread_map_insert(struct lltraceback_thread_map *map,
                              long kernel_tid, long python_tid)
{
    if (map->count == map->capacity) {
        struct lltraceback_thread_map_entry *new_map;
        size_t count = map->capacity + 100;
        size_t sz = sizeof(struct lltraceback_thread_map_entry) * count;
        if (map->entries == NULL) {
            new_map = PyMem_Malloc(sz);
        } else {
            new_map = PyMem_Realloc(map->entries, sz);
        }
        if (new_map == NULL) {
            return -1;
        }
        map->entries = new_map;
        map->capacity = count;
    }

    map->entries[map->count].kernel_tid = kernel_tid;
    map->entries[map->count].python_tid = python_tid;
    map->count += 1;

    return 0;
}

static int
lltraceback_thread_map_set(struct lltraceback_thread_map *map,
                           long kernel_tid, long python_tid)
{
    struct lltraceback_thread_map_entry *ex;

    ex = lltraceback_thread_map_find(map, kernel_tid);
    if (ex == NULL) {
        return lltraceback_thread_map_insert(map, kernel_tid, python_tid);
    } else {
        ex->python_tid = python_tid;
        return 0;
    }
}


static Py_ssize_t
_read(int fd, char *buf, size_t len)
{
    Py_ssize_t res;

    do {
        res = read(fd, buf, len);
    } while (res < 0 && errno == EINTR);

    return res;
}


static Py_ssize_t
_write(int fd, const char *buf, size_t count)
{
    Py_ssize_t res;

    do {
        res = write(fd, buf, count);
    } while (res < 0 && errno == EINTR);

    return res;
}


static void *
_fatal_error(const char *msg, int err)
{
    fprintf(stderr, "fatal error in lltraceback utility thread: %s (errno: %d)",
            msg, err);
    return NULL;
}


static ssize_t
_write_int32(int fd, int32_t i)
{
    uint32_t n = htonl((uint32_t)i);

    return _write(fd, (char *)&n, 4);
}
#define write_int32(fd, i) _write_int32((fd), (i));

static ssize_t
_write_string(int fd, PyObject *text)
{
    Py_ssize_t size;
#if PY_MAJOR_VERSION >= 3
    const char *s;
    s = PyUnicode_AsUTF8AndSize(text, &size);
#else
    char *s;
    PyString_AsStringAndSize(text, &s, &size);
#endif
    write_int32(fd, (int32_t)size);
    return _write(fd, s, (size_t)size);
}
#define write_string(fd, s) _write_string((fd), (s));


static ssize_t
_write_cstring(int fd, const char *s, Py_ssize_t len)
{
    write_int32(fd, (int32_t)len);
    return _write(fd, s, (size_t)len);
}
#define write_cstring(fd, s, l) _write_cstring((fd), (s), (l));


static int
dump_frame(int fd, PyFrameObject *frame)
{
    PyCodeObject *code;
    int lineno;
    int v, len;
    char lineno_str[11]; // ULONG_MAX is 10 chars long in base 10.
    char *lineno_ptr = &lineno_str[10];

    lineno_str[10] = 0;

    code = frame->f_code;
    if (code == NULL || code->co_filename == NULL ||
            !PYSTRING_CHECK(code->co_filename))
    {
        write_cstring(fd, "", 0);
    } else {
        write_string(fd, code->co_filename);
    }

#if (PY_MAJOR_VERSION <= 2 && PY_MINOR_VERSION < 7) \
||  (PY_MAJOR_VERSION >= 3 && PY_MINOR_VERSION < 2)
    lineno = PyCode_Addr2Line(code, frame->f_lasti);
#else
    lineno = PyFrame_GetLineNumber(frame);
#endif

    len = 0;
    v = lineno;
    do {
        *lineno_ptr = (char)('0' + (v % 10));
        lineno_ptr -= 1;
        v /= 10;
        len += 1;
    } while (v);

    write_cstring(fd, lineno_ptr + 1, len);

    if (code == NULL || code->co_name == NULL ||
            !PYSTRING_CHECK(code->co_name))
    {
        write_cstring(fd, "", 0);
    } else {
        write_string(fd, code->co_name);
    }

    return 0;
}

static int
dump_traceback(int fd, PyThreadState *tstate)
{
    PyFrameObject *frame;
    PyFrameObject *top_frame = NULL;
    int depth;

    if (tstate != NULL) {
        top_frame = PyThreadState_GetFrame(tstate);
    }

    if (top_frame == NULL) {
        write_int32(fd, 0);
        return 0;
    }

    depth = 0;
    frame = top_frame;
    while (frame != NULL) {
        if (!PyFrame_Check(frame))
            break;
        frame = frame->f_back;
        depth++;
    }

    write_int32(fd, depth);
    write_int32(fd, 3);

    frame = top_frame;
    while (frame != NULL) {
        if (!PyFrame_Check(frame))
            break;
        if (dump_frame(fd, frame) < 0) {
            return -1;
        }
        frame = frame->f_back;
    }

    return 0;
}


static void *
lltraceback_thread(void *arg)
{
    struct lltraceback_state *state = arg;
    int status;
    fd_set rfds;
    char buf[8];
    ssize_t read, total_read;
    int64_t _tid;
    long _thread_id;
    int nfds;
    PyThreadState *tstate;

    FD_ZERO(&rfds);
    read = 0;
    total_read = 0;

    if (state->inputfd > state->ctlreadfd) {
        nfds = state->inputfd + 1;
    } else {
        nfds = state->ctlreadfd + 1;
    }

    for (;;) {
        FD_SET(state->inputfd, &rfds);
        FD_SET(state->ctlreadfd, &rfds);

        status = select(nfds, &rfds, NULL, NULL, NULL);
        if (status < 0) {
            return _fatal_error("while selecting from input pipe", (errno));
        }

        if (FD_ISSET(state->ctlreadfd, &rfds)) {
            break;
        }

        read = _read(state->inputfd, buf + total_read,
                     (size_t)(8 - total_read));
        if (read < 0) {
            if (errno == EAGAIN) {
                continue;
            } else {
                return _fatal_error("while reading from input pipe", (errno));
            }
        }

        total_read += read;
        if (total_read < 8) {
            continue;
        } else {
            total_read = 0;
        }

        _tid = ((int64_t)htonl(*(uint32_t *)buf) << 32)
                    | htonl(*(uint32_t *)(buf + 4));

        _thread_id = lltraceback_thread_map_get(&state->thread_map, _tid);
        if (_thread_id == 0L) {
            if (dump_traceback(state->outputfd, NULL) < 0) {
                break;
            }
        } else {
            tstate = PyInterpreterState_ThreadHead(state->interp);
            // Find the requested thread state.
            while (tstate != NULL && (long)tstate->thread_id != _thread_id) {
                tstate = PyThreadState_Next(tstate);
            }
            if (dump_traceback(state->outputfd, tstate) < 0) {
                break;
            }
        }
    }

    return NULL;
}


static PyObject*
_new_thread_hook(PyObject *self, PyObject *args)
{
    long _tid;
    int res;
    int err = 0;
    PyThreadState *tstate;
    PyObject *pyres = NULL;
    PyObject *sys = NULL;
    PyObject *sys_settrace = NULL;
    PyObject *frame = NULL;
    PyObject *event = NULL;
    PyObject *arg = NULL;

    if (!PyArg_ParseTuple(args,
            "OOO:_new_thread_hook", &frame, &event, &arg))
    {
        goto error;
    }

    sys = PyImport_ImportModule("sys");
    if (sys == NULL) {
        goto error;
    }

    sys_settrace = PyObject_GetAttrString(sys, "settrace");
    if (sys_settrace == NULL) {
        goto error;
    }

    Py_INCREF(Py_None);
    pyres = PyObject_CallFunctionObjArgs(sys_settrace, Py_None, NULL);
    Py_DECREF(Py_None);
    if (pyres == NULL) {
        goto error;
    }

    _tid = _portable_gettid();
    if (_tid < 0) {
        PyErr_SetFromErrno(PyExc_OSError);
        goto error;
    }

    tstate = PyThreadState_Get();

    res = lltraceback_thread_map_set(
        &_state.thread_map, _tid, (long)tstate->thread_id);
    if (res == -1) {
        goto error;
    }

    goto finally;

error:
    err = 1;

finally:
    Py_XDECREF(pyres);
    Py_XDECREF(sys);
    Py_XDECREF(sys_settrace);

    if (err == 1) {
        return NULL;
    } else {
        Py_RETURN_NONE;
    }
}


static PyObject*
lltraceback_start_thread(PyObject *self, PyObject *args, PyObject *kwargs)
{
    static char *kwlist[] = {"inputfd", "outputfd", "thread_map", NULL};
    int inputfd, outputfd, status, err = 0;
    int controlfd[2];
    PyThreadState *tstate = PyThreadState_Get();
    PyObject *thread_map = NULL;
    PyObject *threading = NULL;
    PyObject *threading_settrace = NULL;
    PyObject *new_thread_hook_cb = NULL;
    PyObject *res = NULL;

    static PyMethodDef new_thread_hook_def = {
        "_new_thread_hook", (PyCFunction)_new_thread_hook, METH_VARARGS
    };

    if (!PyArg_ParseTupleAndKeywords(args, kwargs,
            "ii|O:start_thread", kwlist, &inputfd, &outputfd, &thread_map))
    {
        return NULL;
    }

    if (pipe(controlfd) != 0) {
        PyErr_SetFromErrno(PyExc_OSError);
        goto error;
    }

    if (fcntl(controlfd[0], F_SETFL, O_NONBLOCK) != 0) {
        PyErr_SetFromErrno(PyExc_OSError);
        goto error;
    }

    if (fcntl(inputfd, F_SETFL, O_NONBLOCK) != 0) {
        PyErr_SetFromErrno(PyExc_OSError);
        goto error;
    }

    _state.ctlreadfd = controlfd[0];
    _state.ctlwritefd = controlfd[1];
    _state.inputfd = inputfd;
    _state.outputfd = outputfd;
    _state.interp = tstate->interp;

    if (thread_map != NULL) {
        PyObject *key, *value;
        long kernel_tid, python_tid;
        Py_ssize_t pos = 0;

        if (!PyDict_Check(thread_map)) {
            PyErr_SetString(PyExc_ValueError, "thread_map must be a dict");
            goto error;
        }

        while (PyDict_Next(thread_map, &pos, &key, &value)) {
            kernel_tid = PyLong_AsLong(key);
            python_tid = PyLong_AsLong(value);

            lltraceback_thread_map_set(
                &_state.thread_map, kernel_tid, python_tid);
        }
    }

    lltraceback_thread_map_set(
        &_state.thread_map, _portable_gettid(), (long)tstate->thread_id);

    status = pthread_create(&_state.thread_id, NULL,
                            lltraceback_thread, &_state);
    if (status != 0) {
        PyErr_SetFromErrno(PyExc_OSError);
        goto error;
    }

    threading = PyImport_ImportModule("threading");
    if (threading == NULL) {
        goto error;
    }

    threading_settrace = PyObject_GetAttrString(threading, "settrace");
    if (threading_settrace == NULL) {
        goto error;
    }

    new_thread_hook_cb = PyCFunction_New(&new_thread_hook_def, self);
    if (new_thread_hook_cb == NULL) {
        goto error;
    }

    res = PyObject_CallFunctionObjArgs(
        threading_settrace, new_thread_hook_cb, NULL);
    if (res == NULL) {
        goto error;
    }
    Py_DECREF(res);

    goto finally;

error:
    memset(&_state, 0, sizeof(struct lltraceback_state));
    err = 1;

finally:
    Py_XDECREF(threading_settrace);
    Py_XDECREF(threading);
    Py_XDECREF(thread_map);
    Py_XDECREF(new_thread_hook_cb);

    if (err) {
        return NULL;
    } else {
        Py_RETURN_NONE;
    }
}


static PyObject*
lltraceback_stop_thread(PyObject *self)
{
    void *retval;

    if (_write(_state.ctlwritefd, "\x01", 1) < 0) {
        PyErr_SetFromErrno(PyExc_OSError);
        return NULL;
    }

    if (pthread_join(_state.thread_id, &retval) != 0) {
        PyErr_SetFromErrno(PyExc_OSError);
        return NULL;
    }

    close(_state.ctlreadfd);
    close(_state.ctlwritefd);

    Py_RETURN_NONE;
}


PyDoc_STRVAR(module_doc,
"low-level traceback helper");

static PyMethodDef module_methods[] = {
    {"start_thread",
     (PyCFunction)lltraceback_start_thread, METH_VARARGS | METH_KEYWORDS,
     PyDoc_STR("start lltraceback thread")},
    {"stop_thread",
     (PyCFunction)lltraceback_stop_thread, METH_NOARGS,
     PyDoc_STR("stop lltraceback thread")},
    {"gettid",
     (PyCFunction)lltraceback_gettid, METH_NOARGS,
     PyDoc_STR("return kernel thread identifier for the current thread")},
    {NULL, NULL}  /* sentinel */
};

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef module_def = {
    PyModuleDef_HEAD_INIT,
    "_lltraceback",
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
PyInit__lltraceback(void)
#else
init_lltraceback(void)
#endif
{
    PyObject *m;

#if PY_MAJOR_VERSION >= 3
    m = PyModule_Create(&module_def);
#else
    m = Py_InitModule3("_lltraceback", module_methods, module_doc);
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
