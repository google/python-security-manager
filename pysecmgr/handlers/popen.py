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

"""Inspector module that allowlists command made through Popen events."""

import json
import logging
import os
import re
from typing import Any, Dict, Tuple, Union, Mapping, Sequence

from pysecmgr import configurator
from pysecmgr import inspector
from pysecmgr.config import config_pb2


class PopenInspector(inspector.Inspector):
  """This class inspects python popen() calls.

  When enforce mode is enabled, rejects processes with shell=True and processes
  that do not match the allowlist.

  Raises:
    ValueError: When the process is rejected because shell=True
    SyntaxError: When the process is not allowed
  """

  def __init__(self, enforce: bool, audit: bool = False):
    """Initializes the PopenInspector class.

    Args:
      enforce: Enable blocking mode. This will raise an error when popen is
      called with a process that is not allowed.
      audit: Enables logging of calls to popen() for analysis and forensics.
    """
    self._allowed_processes = []
    self._reject_shell = (
        config_pb2.PopenConfig.reject_shell.DESCRIPTOR.default_value  
    )
    self._enforce_allowlist = (
        config_pb2.PopenConfig.enforce_allowlist.DESCRIPTOR.default_value  
    )
    self._enforce = enforce
    self._audit = audit

  def LoadConfig(  
      self, config: config_pb2.PopenConfig) -> bool:
    """Loads the configuration for this inspector.

    Args:
      config: general configuration for this class.

    Returns:
      A bool indicating whether the config was successfully loaded.
    """
    for process in config.allowed_processes:
      try:
        args = [re.compile(v) for v in process.args]
        self._allowed_processes.append({
            "args":
                args,
            "cwd":
                re.compile(process.cwd) if process.cwd else None,
            "executable":
                re.compile(process.executable) if process.executable else None
        })
      except re.error:
        logging.error("Unable to compile configuration: %s", str(re.error))
        return False

    self._enforce_allowlist = config.enforce_allowlist
    self._reject_shell = config.reject_shell

    return True

  @inspector.Enforceable
  def CheckCall(self, args: Tuple[str, Union[str, Sequence[str]], str, Any]):
    """Checks if the popen() call is allowed.

    Args:
      args: A tuple containing popen() audit event arguments described below.
          executable specifies a replacement program to execute
          args is a sequence of program arguments or a single string
          cwd overrides the current working directory

    Raises:
      ValueError: exception if args has invalid formatting
      SyntaxError: exception when popen is not allowed.
    """
    executable, args, cwd, unused_env = args
    if self._reject_shell: self._CheckUsingShell(args)

    if self._enforce_allowlist:
      self._CheckMatchAllowlist(executable, args, cwd)

  def GenerateLogEntry(
      self, args: Tuple[str, Union[str, Sequence[str]], str,
                        Any]) -> Dict[str, Any]:
    """Compute a log entry for popen() calls."""
    executable, args, cwd, env = args
    log_entry = {}
    log_entry["args"] = args
    log_entry["cwd"] = cwd
    log_entry["executable"] = executable
    log_entry["env"] = env
    try:
      self._CheckUsingShell(args)
    except ValueError:
      log_entry["shell"] = True
    return log_entry

  def _CheckUsingShell(self, args: Union[str, Sequence[str]]):
    """Detect if Popen is called with shell=True.

    Args:
      args: sequence of program arguments, string or path-like object
        passed to popen.

    Returns:
      A bool indicating whether Popen is called with shell=True.
    """
    # If args is a string, shell is True
    # This also covers Windows when args is initially a list but shell is True:
    # https://github.com/python/cpython/blob/v3.9.9/Lib/subprocess.py#L1407
    if not isinstance(args, list):
      raise ValueError("The use of shell=True is not allowed")

    # Identify when shell is true, refer to the popen implementation:
    # https://github.com/python/cpython/blob/v3.9.9/Lib/subprocess.py#L1682
    if len(args) > 1 and args[0:2] in [
        ["/system/bin/sh", "-c"],
        ["/bin/sh", "-c"]
    ]:
      raise ValueError("The use of shell=True is not allowed")

  def _CheckMatchAllowlist(self, executable: str, args: Union[str,
                                                              Sequence[str]],
                           cwd: str):
    for allowed_process in self._allowed_processes:
      if self._MatchProcess(allowed_process, executable, args, cwd):
        return True
    raise SyntaxError("Process is not allowed")

  def _MatchProcess(self, allowed_process: Mapping[str, Any], executable: str,
                    args: Union[str, Sequence[str]], cwd: str) -> bool:
    """Match a process information with an allowlist configuration.

    Return False if allowlist doesn’t include a regex for cwd but the current
    process set those arguments.

    Args:
      allowed_process: process allowed from configuration
      executable: replacement program to execute
      args: sequence of program arguments, string or path-like object
        passed to popen.
      cwd: overrides the current working directory

    Returns:
      A bool indicating whether the process match the specific configuration
      entry
    """
    if len(allowed_process.get("args")) != len(args):
      return False
    for i, v in enumerate(allowed_process.get("args")):
      if not v.fullmatch(args[i]):
        return False

    if cwd and (
        allowed_process.get("cwd") is None or
        not allowed_process.get("cwd").fullmatch(os.path.normpath(cwd))):  
      return False

    if executable and (
        args[0] != executable and
        (allowed_process.get("executable") is None
         or not allowed_process.get("executable").fullmatch(executable))):  
      return False

    return True


class PopenConfigurator(configurator.Configurator):
  """Parses log files and turns them into a config."""

  def __init__(self):
    self._config = config_pb2.PopenConfig()
    self._config.reject_shell = True
    self._config.enforce_allowlist = True

  def ParseJsonEvent(self, json_data: str) -> bool:
    """Parses the JSON string and updates the config.

    Args:
      json_data: A JSON string containing the args of the popen call.

    Returns:
      True on success and false on failure.
    """
    try:
      json_data = json.loads(json_data)
    except json.decoder.JSONDecodeError:
      logging.warning("Unable to parse: %s", json_data)
      return False

    if not ({"args", "cwd", "executable"} <= set(json_data)):
      logging.warning("Missing field from %s", json_data)
      return False

    args = json_data["args"]
    cwd = json_data["cwd"]
    executable = json_data["executable"]

    process = config_pb2.Process()
    for arg in args:
      process.args.append("^{}$".format(re.escape(arg)))
    if cwd:
      process.cwd = cwd
    process.executable = "^{}$".format(re.escape(executable))

    if process not in self._config.allowed_processes:
      self._config.allowed_processes.append(process)
    return True

  def GetConfig(self):
    return self._config

  def Merge(self, config: config_pb2.Config) -> None:
    config.popen_config.CopyFrom(self._config)
