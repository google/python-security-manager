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

"""Benchmark to get an estimation of the runtime impact of the python security manager.

Note that it is a pessimistic benchmark as we tried to limit the IO to a
maximum, not reading file content, no waiting for network calls, and we use
`enforce=False` to prevent the code to shortcircuit when an action would be
blocked (otherwise the code runs faster with pysm because it performs less
actions).
"""

import os
import pickle
import subprocess
import timeit

from pysecmgr import security_manager


class PickleMe():
  """This is only used as an example of pickled class in a test."""


def setup_pysm():
  manager = security_manager.SecurityManager(enforce=True, audit=True)
  manager.AddFolder("/this/is/good/", "r")
  manager.AddFolder("/this/is/also/good/", "rw")
  manager.AllowSymlink()
  manager.AddProcessRegex(args=["echo", "running", "unittest"])
  manager.AddProcessRegex(args=["echo", "running", "benchmark"])
  manager.AddModuleAllowedToExec("timeit")
  manager.Activate()


def time_me():
  """Trigger all the handlers from the pysm, to assesse their impact."""
  # exec
  try:
    exec("1 == 1")  
  except SyntaxError:
    pass  # Exec is not allowed
  # eval
  try:
    eval("1 == 1")  
  except SyntaxError:
    pass  # Exec is not allowed
  # system
  try:
    os.system("pwd > /dev/null")
  except SyntaxError:
    pass  # os.system is not allowed
  # pickle
  pickled = pickle.dumps(PickleMe())
  try:
    pickle.loads(pickled)
  except pickle.PickleError:
    pass  # pickle.find_class is not allowed
  # open
  try:
    open("/this/is/good/yes", "r")
  except IOError:
    pass  # No such file or directory
  try:
    open("/this/is/not/good", "r")
  except IOError:
    pass  # Path is not allowed
  # popen
  subprocess.run(["echo", "running", "benchmark"],
                 capture_output=True,
                 check=True)
  try:
    subprocess.run(["echo", "forbidden", "command"],
                   capture_output=True,
                   check=True)
  except SyntaxError:
    pass  #  'Process is not allowed


def main():
  iterations = 1000
  base_time = timeit.timeit(
      "time_me()", setup="from __main__ import time_me", number=iterations)
  print(f"base runtime: {base_time} ({base_time / iterations} * {iterations})")
  setup_pysm()
  pysm_time = timeit.timeit(
      "time_me()", setup="from __main__ import time_me", number=iterations)
  print(f"pysm runtime: {pysm_time} ({base_time / iterations} * {iterations})")
  print(
      (f"delta: {pysm_time - base_time}"
       f" ({round((pysm_time - base_time) * 100 / base_time, 2)} %)"
      )
  )


if __name__ == "__main__":
  main()
