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

"""Inspector module that rejects any command made through the os.system event."""

from typing import Any, Dict, Tuple

from pysecmgr import configurator
from pysecmgr import inspector
from pysecmgr.config import config_pb2


class SystemInspector(inspector.Inspector):
  """This class inspects python os.system() calls and rejects them."""

  def __init__(self, enforce: bool, audit: bool = True):
    self._enforce = enforce
    self._audit = audit

  def LoadConfig(  
      self, config: config_pb2.SystemConfig) -> bool:
    """Loads the configuration for this inspector.

    Args:
      config: general configuration for this class.

    Returns:
      A bool indicating whether the config was successfully loaded.
    """
    return True

  @inspector.Enforceable
  def CheckCall(self, args: Tuple[str]):
    """Checks if the os.system() call is allowed.

    Args:
      args: A tuple containing the specifics of the os.system() call.

    Raises:
      SyntaxError: exception when os.system is not allowed.
    """
    raise SyntaxError("os.system is not allowed")

  def GenerateLogEntry(self, args: Tuple[str]) -> Dict[str, Any]:
    """Compute a log entry for system() calls."""
    cmd, = args
    log_entry = {}
    log_entry["cmd"] = str(cmd)
    return log_entry


class SystemConfigurator(configurator.Configurator):
  """Parses log files and turns them into a config."""

  def __init__(self):
    self._config = config_pb2.SystemConfig()

  def ParseJsonEvent(self, json_data: str) -> bool:
    """Parses the JSON string and updates the config.

    Args:
      json_data: A JSON string containing the args of the system call.

    Returns:
      True on success and false on failure.
    """
    return True

  def GetConfig(self):
    return self._config

  def Merge(self, config: config_pb2.Config) -> None:
    config.system_config.CopyFrom(self._config)
