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

"""Inspector module that allowlists modules that can call the exec event."""

import inspect
import json
import logging
from typing import Any, Dict, Tuple

from pysecmgr import configurator
from pysecmgr import inspector
from pysecmgr.config import config_pb2


class ExecInspector(inspector.Inspector):
  """This class inspects python exec() calls.

  Inspect exec() calls and rejects them if they are not made from an allowed
  module.
  """

  def __init__(self, enforce: bool, audit: bool = False):
    self._allowed_modules = set()
    self._enforce_allowlist = (
        config_pb2.ExecConfig.enforce_allowlist.DESCRIPTOR.default_value  
    )
    self._enforce = enforce
    self._audit = audit

  def LoadConfig(  
      self, config: config_pb2.ExecConfig) -> bool:
    """Loads the configuration for this inspector.

    Args:
      config: general configuration for this class.

    Returns:
      A bool indicating whether the config was successfully loaded.
    """
    self._enforce_allowlist = config.enforce_allowlist
    self._allowed_modules = set(config.allowed_modules)
    return True

  @inspector.Enforceable
  def CheckCall(self, args: Tuple[Any, Tuple[str, int]]):
    """Checks if the exec() call is allowed.

    If enforce_allowlist is True, inspect the python stack frames to find the
    module calling exec and rejects it if not allowlisted.

    Args:
      args: A tuple containing the specifics of the exec() call.

    Raises:
      SyntaxError: exception when exec is not allowed.
    """
    if not self._enforce_allowlist: return

    (cmd, *_) = args
    if isinstance(cmd, str):
      raise SyntaxError("Exec is not allowed from string")

    self._CheckExecFromAllowedModule()

  def _CheckExecFromAllowedModule(self):
    try:
      # Find the frame that is calling exec, need to go back up the following
      # frames: _CheckExecFromAllowedModule, CheckCall, Inner (Inspector class)
      # Hook (SecurityManager)
      name = inspect.currentframe().f_back.f_back.f_back.f_back.f_globals[  
          "__name__"]
    except AttributeError as e:
      raise SyntaxError("Code not allowed to call exec.") from e

    if name not in self._allowed_modules:
      raise SyntaxError(
          "Module {} not allowed to call exec."
          .format(name))

  def GenerateLogEntry(self, args: Tuple[Any, Tuple[str,
                                                    int]]) -> Dict[str, Any]:
    """Compute a log entry for exec() calls."""
    (cmd, *scope) = args
    log_entry = {}
    if isinstance(cmd, str):
      log_entry["code"] = log_entry["consts"] = str(cmd)
    else:
      log_entry["code"] = str(cmd.co_code)
      log_entry["consts"] = str(cmd.co_consts)
      log_entry["filename"] = str(cmd.co_filename)
    try:
      # skip through a few frames to get back to the original caller.
      log_entry["module"] = inspect.currentframe(
      ).f_back.f_back.f_back.f_globals[  
          "__name__"]
    except AttributeError:
      pass
    log_entry["scope"] = str(scope)
    return log_entry


class ExecConfigurator(configurator.Configurator):
  """Parses log files and turns them into a config."""

  def __init__(self):
    self._config = config_pb2.ExecConfig()
    self._config.enforce_allowlist = True

  def ParseJsonEvent(self, json_data: str) -> bool:
    """Parses the JSON string and updates the config.

    Exec should not be used in first party code. Allowlist is only for imports
    or third party libraries that are already using exec. Since this handler is
    not allowlisting the Exec arguments but the module calling Exec, the
    resulting configuration should be reviewed manually to make sure exec is not
    used with untrusted inputs.

    Args:
      json_data: A JSON string containing the args of the exec call.

    Returns:
      True on success and false on failure.
    """
    try:
      json_data = json.loads(json_data)
    except json.decoder.JSONDecodeError:
      logging.warning("Unable to parse: %s", json_data)
      return False

    if "module" not in json_data:
      logging.warning("Module not found in: %s", json_data)
      return False

    if json_data["module"] not in self._config.allowed_modules:
      self._config.allowed_modules.append(json_data["module"])

    return True

  def GetConfig(self):
    return self._config

  def Merge(self, config: config_pb2.Config) -> None:
    config.exec_config.CopyFrom(self._config)
