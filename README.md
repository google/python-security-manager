# Python Security Manager

## What is Python Security Manager? {#what}

The Python Security Manager (pysecmgr) is a middleware security layer in Python
that can monitor and prevent insecure logic from being run.

Note: pysecmgr is **not** a sandbox, see #limits for more details.

## Which python version is supported?

Pysecmgr needs at least python version 3.8, as it first introduced
[PEP 0578](https://peps.python.org/pep-0578/). Pysecmgr has been tested using
python 3.9.

## Why should I use it? {#why}

Pysecmgr is a defense in depth mechanism to protect against exploitation of
certain attacks including:

*   Path traversal and arbitrary files disclosure
*   OS command injection
*   Code injection
*   Arbitrary outbound network connections (including SSRF)
*   Source code disclosure
*   Insecure deserialization

To better understand how pysecmgr can help protect against those attacks, see
the pysecmgr codelab in `pysecmgr/codelab/README.md`

**When to use pysecmgr?**

*   Web applications are one of the primary use cases for pysecmgr as they
    usually handle untrusted user inputs.
*   Pysecmgr can be used by individual applications, and can also be integrated
    into frameworks to protect a wider audience.

**When not to use pysecmgr?**

*   For tooling related scripts that don’t take untrusted user inputs, pysecmgr
    might be too restrictive (e.g. unable to execute system command, restricted
    popen args).
*   Pysecmgr is not a sandbox and should not be used as the only security
    control to secure/restrict arbitrary and untrusted code provided by users.
    See pysecmgr [limitations](#limits).

## How does it work? {#how}

Pysecmgr relies on [PEP 0578](https://peps.python.org/pep-0578/) which
introduces audit hooks allowing security-sensitive Python methods to be
inspected by callback methods. During inspection, exceptions can be raised and
this allows the callback to prevent a method from being called/executed.

The Python Security Manager currently supports the following hooks:

*   **open**: pysecmgr hooks the "open" built-in function, os.open and io.open.
*   **socket.connect**: pysecmgr restrict socket ip and port or UNIX socket
    path.
*   **pickle.find_class**: pysecmgr prevents unpickling event by default.
*   **os.system**: pysecmgr prevents the use of os.system by default.
*   **subprocess.Popen**: pysecmgr restricts the arguments that can be passed to
    popen.
*   **exec**: pysecmgr hooks the "exec" and "eval" build-in function. Note that
    this hook’s allowlist behaves differently than the others as it does not
    allowlist the content being passed to exec but the Python modules that can
    use exec.
*   **import**: this hook is currently not enabled by default because it
    requires a lot of customizations for each application. It is considered an
    advanced feature for more security sensitive use cases.

The following table describes other pysecmgr supported functions whose
implementation is based on the above hooked functions. This is not a holistic
list and will be improved over time.

Functions                                                        | Support
---------------------------------------------------------------- | -------
eval                                                             | Supported, uses os.exec.
os.popen                                                         | Supported, uses subprocess.Popen.
subprocess.run                                                   | Supported, uses subprocess.Popen.
[os.spawn*](https://docs.python.org/3/library/os.html#os.spawnl) | Supported, uses os.exec.
urllib.request.urlopen                                           | Supported, uses socket.connect.
[os.exec*](https://docs.python.org/3/library/os.html#os.execl)   | Supported, uses os.exec.

## Limitations {#limits}

Pysecmgr has a few known limitations:

*   Pysecmgr is not catching bugs introduced by C/C++ (SWIG) code.
*   Some common python vulnerabilities are not covered by pysecmgr such as
    insecure yaml or XXE with lxml. Pyyaml is not using a pysecmgr supported
    audit hook to create python objects. Similarly, lxml also does not use
    supported audit hook.
*   Pysecmgr is **not a sandbox**, it does not hook all security sensitive calls
    (incl. C/C++ (SWIG) code) and can be
    [bypassed](https://daddycocoaman.dev/posts/bypassing-python38-audit-hooks-part-1/).
*   Pysecmgr does not patch insecure logic. It only blocks them.
*   Some functions such as shutil.rmtree are using the low level
    [os.open](https://docs.python.org/3/library/os.html#os.open) with a path
    relative to a directory file descriptor (dir_fd). This is unfortunately not
    supported by pysecmgr.

## Disclaimer
**This is not an officially supported Google product.**
