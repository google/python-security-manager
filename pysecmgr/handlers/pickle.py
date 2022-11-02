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

"""Inspector module that rejects any unpickling event."""

import pickle
from typing import Any, Dict, Tuple

from pysecmgr import configurator
from pysecmgr import inspector
from pysecmgr.config import config_pb2


class PickleInspector(inspector.Inspector):
  """This class inspects python pickle.find_class() calls and rejects them."""

  def __init__(self, enforce: bool, audit: bool = False):
    self._enforce = enforce
    self._audit = audit
    self._reject_pickle_find_class = (
        config_pb2.PickleConfig.reject_pickle_find_class.DESCRIPTOR.  
        default_value  
    )

  def LoadConfig(  
      self, config: config_pb2.PickleConfig) -> bool:
    """Loads the configuration for this inspector.

    Args:
      config: general configuration for this class.

    Returns:
      A bool indicating whether the config was successfully loaded.
    """
    self._reject_pickle_find_class = config.reject_pickle_find_class
    return True

  @inspector.Enforceable
  def CheckCall(self, args: Tuple[str, str]):
    """Checks if the pickle.find_class() call is allowed.

    Args:
      args: A tuple containing the specifics of the pickle.find_class() call.

    Raises:
      pickle.PickleError: exception when pickle.find_class is not allowed.
    """
    if self._reject_pickle_find_class:
      raise pickle.PickleError("pickle.find_class is not allowed")

  def GenerateLogEntry(self, args: Tuple[str, str]) -> Dict[str, Any]:
    """Compute a log entry for pickle.find_class() calls."""
    module_name, global_name = args
    log_entry = {}
    log_entry["module_name"] = str(module_name)
    log_entry["global_name"] = str(global_name)
    return log_entry


class PickleConfigurator(configurator.Configurator):
  """Parses log files and turns them into a config."""

  def __init__(self):
    self._config = config_pb2.PickleConfig()
    self._config.reject_pickle_find_class = (
        config_pb2.PickleConfig.reject_pickle_find_class.DESCRIPTOR.  
        default_value  
    )

  def ParseJsonEvent(self, json_data: str) -> bool:
    """Parses the JSON string and updates the config.

    Args:
      json_data: A JSON string containing the args of the pickle call.

    Returns:
      True on success and false on failure.
    """
    return True

  def GetConfig(self):
    return self._config

  def Merge(self, config: config_pb2.Config) -> None:
    config.pickle_config.CopyFrom(self._config)
