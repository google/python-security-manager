# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Vulnerable demo app for the Python security manager's codelab."""

# Quick install
# =============
# # Make a virtual env and install external dependencies
# python3 -m venv venv
# source venv/bin/activate
# python3 -m pip install flask
# python3 -m pip install flask_wtf
# python3 -m pip install requests
# python3 -m pip install protobuf==3.20
#
# # Install the Python security manager
#
# Run
# ===
# python3 -m flask run

import base64
import os
import pickle

import flask
from flask import Flask
from flask import request
from flask_wtf import csrf
from flask_wtf.csrf import CSRFProtect
import requests

# import subprocess
# from pysecmgr.security_manager import SecurityManager
# manager = SecurityManager(enforce=True)
# # Flask and Pysm specifics
# # ===============
# manager.InstallCommonPythonRules()
# manager.AddFile('/etc/mime.types', 'r')
# manager.AddModuleAllowedToExec('dataclasses')
# manager.AddModuleAllowedToExec('werkzeug.routing')
# # App specific
# # ============
# manager.AddPathRegex(f'^{os.getcwd()}/[^/]+\.txt$', 'r')
# manager.AddConnectionRegex('.*:443')
# manager.AddProcessRegex(['nslookup', '.*\.google\.com'])
# # Activate the Python security manager
# manager.Activate()

print(f'Running app from {os.getcwd()}')
csrf_protect = CSRFProtect()
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(32)
csrf_protect.init_app(app)


@app.route('/')
def home() -> str:
  """Choose your own adventure page."""
  return """
      <link rel="stylesheet" href="static/css/main.css">
      <p>Python Security Manager's test dummy</p>
      <ul>
        <li><a href='open'>Open a file</a></li>
        <li><a href='connect'>Connect to a URL</a></li>
        <li><a href="lookup">DNS lookup an address</a></li>
        <li><a href="evaluate">Evaluate an expression</a></li>
        <li><a href="cookie">Set and get cookie value</a></li>
      </ul>
    """


@app.route('/open')
def open_story() -> str:
  """Open function vulnerable to path traversal, and code disclosure."""
  story = ''
  error = ''
  filename = request.args.get('f', '')
  try:
    with open(filename, 'r') as f:
      story = f.read()
  except Exception as e:  
    error = f'{e}'
  return f"""
      <p style="color:red">{error if error and filename else ''}</p>
      <p>Choose a story</p>
      <ul>
        <li><a href="?f=red.txt">Little red riding hood</a></li>
        <li><a href="?f=alice.txt">Alice in wonderland</a></li>
      </ul>
      <p>{story}</p>
    """


@app.route('/connect')
def connect_snippet() -> str:
  """Connect function vulnerable to SSRF."""
  snippet = ''
  error = ''
  url = request.args.get('url', '')
  try:
    snippet = requests.get(url).text
  except Exception as e:  
    error = f'{e}'
  return f"""
      <p style="color:red">{error if error and url else ''}</p>
      <p>Choose an url to fetch</p>
      <p>e.g. <a href="https://pastebin.com/raw/2Kizn57M">https://pastebin.com/raw/2Kizn57M</a></p>
      <form action="" method="GET">
        <input type="text" name="url"/>
        <button type="submit">snip</button>
      </form>
      <p>{snippet}</p>
    """


@app.route('/secret')
def secret() -> str:
  """Shhh."""
  return """Penguins have knees, shhh it's a secret"""


@app.route('/lookup', methods=['GET', 'POST'])
def lookup() -> str:
  """Lookup function vulnerable to Command Injection."""
  address = request.form.get('address', '')
  lookup_output, error = '', ''

  if address:
    try:
      lookup_output = os.popen('nslookup ' + address).read().replace(
          '\n', '\n<br>')

      # # os.popen is insecure by default as it’s vulnerable to command
      # # injection (using shell=True). It needs to be replaced by
      # # subprocess.check_output for example. When enabling the python security
      # # manager, replace the two lines above by:
      # lookup_output = subprocess.check_output(
      #    ['nslookup', address]).decode('utf-8')
    except Exception as e:  
      error = f'{e}'
  return f"""
    <link rel="stylesheet" href="static/css/main.css">
    <p style="color:red">{error}</p>
    Result: {lookup_output}
    <form action = "/lookup" method="POST">
       <p><h3>Enter address to lookup</h3></p>
       <p>e.g. <code>www.google.com</code></p>
       <p><input type = 'text' name = 'address'/></p>
       <p><input type = 'submit' value = 'Lookup'/></p>
       <input type="hidden" name="csrf_token" value="{csrf.generate_csrf()}"/>
    </form>
    """


@app.route('/evaluate', methods=['GET', 'POST'])
def evaluate() -> str:
  """Evaluate function vulnerable to Command Injection."""
  expression = request.form.get('expression', '')
  result, error = '', ''

  if expression:
    try:
      result = str(eval(expression)).replace('\n', '\n<br>')  
    except Exception as e:  
      error = f'{e}'
  return f"""
  <link rel="stylesheet" href="static/css/main.css">
  <p style="color:red">{error}</p>
  Result: {result}
  <form action = "/evaluate" method="POST">
     <p><h3>Enter expression to evaluate</h3></p>
     <p>e.g. <code>1+1</code></p>
     <p><input type = 'text' name = 'expression'/></p>
     <p><input type = 'submit' value = 'Evaluate'/></p>
     <input type="hidden" name="csrf_token" value="{csrf.generate_csrf()}"/>
  </form>
  """


@app.route('/cookie', methods=['GET', 'POST'])
def cookie() -> flask.wrappers.Response:
  """Cookie function vulnerable to Pickle Insecure Deserialization."""
  error, cookie_value = '', ''
  b64cookie = request.form.get('value', request.cookies.get('value', ''))

  if b64cookie:
    try:
      cookie_value = pickle.loads(base64.b64decode(b64cookie))
    except Exception as e:  
      error = f'{e}'

  form = f"""
  <link rel="stylesheet" href="static/css/main.css">
  <p style="color:red">{error}</p>
  Cookie value: {cookie_value}
  <form action = "/cookie" method="POST">
     <p><h3>Enter base64 value to be stored in cookie</h3></p>
     <p>e.g. <code>gASVFwAAAAAAAACME215c3VwZXJzZWNyZXRjb29raWWULg==</code></p>
     <p><input type='text' name='value'/></p>
     <p><input type='submit' value='Set Cookie'/></p>
      <input type="hidden" name="csrf_token" value="{csrf.generate_csrf()}"/>
  </form>
  """
  resp = flask.make_response(form)
  if b64cookie:
    resp.set_cookie('value', b64cookie)

  return resp
