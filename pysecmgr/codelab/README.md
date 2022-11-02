# Python Security Manager

The Python Security Manager (pysecmgr) is a middleware security layer in Python
that can monitor and prevent insecure logic from being run.


## Running the demo app

```shell
# Create a virtual env and install dependencies
python3 -m venv venv
source venv/bin/activate
python3 -m pip install flask
python3 -m pip install flask_wtf
python3 -m pip install requests
python3 -m pip install protobuf==3.20
python3 -m pip install -e pysm/pysecmgr

# Run the demo app
python3 -m flask run
```

Open your browser at [http://127.0.0.1:5000](http://127.0.0.1:5000) to take a
look at the demo app.

### Vulnerable use of open()

Go to [http://127.0.0.1:5000/open](http://127.0.0.1:5000/open). The page loads
stories from disk by reading the corresponding files using `open(filename, 'r')`
with no further verification on the filename.

A malicious input for the filename (here passed as the GET parameter `?f=`)
would leak the app source
[http://127.0.0.1:5000/open?f=app.py](http://127.0.0.1:5000/open?f=app.py)

Or secret on the machine using path traversal:
[http://127.0.0.1:5000/open?f=../../../../../../../../../../../etc/passwd](http://127.0.0.1:5000/open?f=../../../../../../../../../../../etc/passwd).

### Vulnerable use of connect()

Go to [http://127.0.0.1:5000/connect](http://127.0.0.1:5000/connect). The page
loads snippets from remote urls using `requests.get(url).text` with no further
verification on url.

A malicious input for the url (here passed as the GET parameter `?url=`) would
allow a user to access localhost (SSRF):
[http://127.0.0.1:5000/connect?url=http%3A%2F%2Flocalhost%3A5000%2Fsecret](http://127.0.0.1:5000/connect?url=http%3A%2F%2Flocalhost%3A5000%2Fsecret).

### Vulnerable use of os.popen()

Go to [http://127.0.0.1:5000/lookup](http://127.0.0.1:5000/lookup). The page
displays the result of the lookup command using `os.popen('nslookup ' +
address)` with no verification on the address. os.popen uses
[`shell=True`](https://docs.python.org/3/library/subprocess.html#security-considerations)
by default which is vulnerable to command injection.

A malicious input for the address to lookup (e.g. `www.google.com; ls`) would
allow a user to perform command injection.

### Vulnerable use of eval()

Go to [http://127.0.0.1:5000/evaluate](http://127.0.0.1:5000/evaluate). The page
displays the result the `eval()` command. For example `1+1` would evaluate to 2.

A malicious input (e.g. `{"a": __import__('os').popen('ls').read()}`) for the
expression to evaluate would allow a user to perform code injection.

### Vulnerable use of pickle.loads()

Go to [http://127.0.0.1:5000/cookie](http://127.0.0.1:5000/cookie). The server
loads the cookie using pickle.

A malicious input for the cookie value (e.g.
`gASVIQAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjAZscyAtbGGUhZRSlC4=`) would allow a
user to perform insecure deserialization and execute code on the server (see
server logs).

## Fixing the demo app

Import the Python security manager into `app.py`

```python
from pysecmgr.security_manager import SecurityManager
```

And initiate the Python security manager before `app = Flask(__name__)`

```python
manager = SecurityManager(enforce=True)
# Flask and Pysm specifics
# ===============
manager.InstallCommonPythonRules()
manager.AddFile('/etc/mime.types', 'r')
manager.AddModuleAllowedToExec('dataclasses')
manager.AddModuleAllowedToExec('werkzeug.routing')
# App specific
# ============
manager.AddPathRegex(f'^{os.getcwd()}/[^/]+\.txt$', 'r')
manager.AddConnectionRegex('.*:443')
manager.AddProcessRegex(['nslookup', '.*\.google\.com'])
# Activate the Python security manager
manager.Activate()

```

Note that for the lookup function, we need to also modify the code to disable
the use of `shell=True`. This can be done for example by using
`subprocess.check_output` instead of `os.open`. In `app.py`, uncomment the
following lines:

```python
import subprocess

...

# lookup_output = os.popen('nslookup ' + address).read().replace(
#           '\n', '\n<br>') if address else ''
lookup_output = subprocess.check_output(
    ['nslookup', address]).decode('utf-8') if address else ''

```

The previous vulnerabilities are now mitigated:

*   Source code disclosure
    [http://127.0.0.1:5000/open?f=app.py](http://127.0.0.1:5000/open?f=app.py)
*   Path traversal
    [http://127.0.0.1:5000/open?f=../../../../../../../../../../../etc/passwd](http://127.0.0.1:5000/open?f=../../../../../../../../../../../etc/passwd)
*   SSRF
    [http://127.0.0.1:5000/connect?url=http%3A%2F%2Flocalhost%3A5000%2Fsecret](http://127.0.0.1:5000/connect?url=http%3A%2F%2Flocalhost%3A5000%2Fsecret)
*   OS command injection
    [http://127.0.0.1:5000/lookup](http://127.0.0.1:5000/lookup)
*   Code injection
    [http://127.0.0.1:5000/evaluate](http://127.0.0.1:5000/evaluate)
*   Insecure
    deserialization [http://127.0.0.1:5000/cookie](http://127.0.0.1:5000/cookie)
