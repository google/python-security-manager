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

"""Inspector module for import() calls."""
import json
import logging
from typing import Any, Callable, Dict, Sequence, Tuple

from pysecmgr import configurator
from pysecmgr import inspector
from pysecmgr.config import config_pb2


class ImportInspector(inspector.Inspector):
  """This class inspects python import() calls and allows or rejects them.

    Typical usage example:

      instance = ImportInspector(config)
      instance.check(import_call_tuple_with_args)
  """

  def __init__(self, enforce: bool, audit: bool = False):
    self._allowed_import_modules = set()
    self._enforce_allowlist = (
        config_pb2.ImportConfig.enforce_allowlist.DESCRIPTOR.default_value  
    )
    self._enforce = enforce
    self._audit = audit

  def LoadConfig(  
      self, config: config_pb2.ImportConfig) -> bool:
    """Loads the configuration for this inspector.

    Args:
      config: general configuration for this class.

    Returns:
      A bool indicating whether the config was successfully loaded.
    """
    self._allowed_import_modules = config.allowed_imports
    self._enforce_allowlist = config.enforce_allowlist

    return True

  @inspector.Enforceable
  def CheckCall(self, args: Tuple[str, str, Sequence[str], Any,
                                  Sequence[Callable[[Any], Any]]]):
    """Checks if the import() call is allowed.

    Checks if the import module name is allowed, and whether the hash of the
    module is an allowlisted one.

    Args:
      args: A tuple containing the specifics of the import() call.

    Raises:
      ImportError: exception when the import is not allowed.
    """
    (module, unused_filename, unused_sys_path, unused_sys_meta_path,
     unused_sys_path_hooks) = args
    if self._enforce_allowlist:
      self._CheckMatchAllowlist(module)

  def GenerateLogEntry(
      self, args: Tuple[str, str, Sequence[str], Any, Sequence[Callable[[Any],
                                                                        Any]]]
  ) -> Dict[str, Any]:
    """Compute a log entry for import() calls."""
    (module, unused_filename, unused_sys_path, unused_sys_meta_path,
     unused_sys_path_hooks) = args
    log_entry = {}
    log_entry["module"] = module
    return log_entry

  def _CheckMatchAllowlist(self, module: str):
    if module not in self._allowed_import_modules:
      raise ImportError(f"Module is not allowed for: {module}")


class ImportConfigurator(configurator.Configurator):
  """Parses log files and turns them into a config."""

  def __init__(self):
    self._config: config_pb2.ImportConfig = config_pb2.ImportConfig()
    self._config.enforce_allowlist = True

  def ParseJsonEvent(self, json_data: str) -> bool:
    """Parses the JSON string and updates the config.

    Args:
      json_data: A JSON string containing the args of an import call.

    Returns:
      True on success and false on failure.
    """
    try:
      json_data = json.loads(json_data)
    except json.decoder.JSONDecodeError:
      logging.warning("Unable to parse: %s", json_data)
      return False

    if "module" not in json_data:
      logging.warning('Missing key "module" from: %s', json_data)
      return False
    if json_data["module"] not in self._config.allowed_imports:
      self._config.allowed_imports.append(json_data["module"])
    return True

  def GetConfig(self):
    return self._config

  def Merge(self, config: config_pb2.Config) -> None:
    config.import_config.CopyFrom(self._config)
