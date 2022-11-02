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

"""Python security manager configurator module.

Utility script to generate the configuration file for the Python security manager based on usage logs.

  Typical usage example:

  configurator = SecurityManagerConfigurator()
  configurator.Parse(entries)
  config = configurator.GetConfig()
"""

import collections.abc
import logging
import os.path
import re

from typing import Sequence

from absl import app
from absl import flags

from pysecmgr import inspector
from pysecmgr.config import config_pb2
from pysecmgr.handlers import connect as connect_handler
from pysecmgr.handlers import exec as exec_handler
from pysecmgr.handlers import imports as import_handler
from pysecmgr.handlers import open as open_handler
from pysecmgr.handlers import pickle as pickle_handler
from pysecmgr.handlers import popen as popen_handler
from pysecmgr.handlers import system as system_handler


_INPUT_LOG_PATH = flags.DEFINE_string(
    "input_log_path", None, "Path of the log file to be parsed."
)
_OUTPUT_CONFIG_PATH = flags.DEFINE_string(
    "output_config_path", None, "Path of the config to be generated."
)
_OUTPUT_FORMAT = flags.DEFINE_enum(
    "output_format",
    "python",
    ["python", "proto"],
    'Output format ("python" or "proto").',
)


class SecurityManagerConfigurator():
  """Configure the python security manager based on usage logs."""

  def __init__(self):
    configurators_list = [
        connect_handler.ConnectConfigurator(),
        exec_handler.ExecConfigurator(),
        import_handler.ImportConfigurator(),
        open_handler.OpenConfigurator(),
        pickle_handler.PickleConfigurator(),
        popen_handler.PopenConfigurator(),
        system_handler.SystemConfigurator()
    ]
    self._configurators = {
        c.__class__.__name__.replace("Configurator", "Inspector"): c
        for c in configurators_list
    }

  def _ParseEntry(self, entry: str) -> None:
    """Parse a single log entry from the handlers into a configuration."""
    inspector_names = "|".join(self._configurators.keys())
    log_entry_re = re.compile(
        r".*{}:({}):(.*}})(?::Stack \(most recent call last\))?[\s\S]*".format(
            inspector.LOGGING_PREFIX, inspector_names
        )
    )
    log_match = log_entry_re.match(entry)

    if not log_match:
      return

    class_name, json_data = log_match.groups()
    if class_name not in self._configurators:
      logging.error('Cannot find a configurator: "%s"', class_name)
      return
    self._configurators[class_name].ParseJsonEvent(json_data)

  def Parse(self, entries: collections.abc.Iterable[str]) -> None:
    """Parse the log entries from the handlers into a configuration."""
    for entry in entries:
      self._ParseEntry(entry)

  def _MergeConfigs(self, config: config_pb2.Config) -> None:
    """Merge each handlers’ sub-configurations into one."""
    for configurator in self._configurators.values():
      configurator.Merge(config)

  def GetConfig(self) -> config_pb2.Config:
    """Return the snapshot of the currently computed config."""
    config = config_pb2.Config()
    self._MergeConfigs(config)
    return config

  def GetConfigAsProtoText(self) -> str:
    """Return the snapshot of the currently computed config as proto text."""
    return str(self.GetConfig())

  def GetConfigAsPython(self) -> str:
    """Return the snapshot of the currently computed config as python."""
    config = self.GetConfig()
    cmds = [
        "        "#       please manually review before using in prod.",
        "manager = security_manager.SecurityManager(enforce=True)"
    ]
    for path, mode in config.open_config.allowed_paths.items():
      if os.path.isabs(path):
        cmds.append(f"manager.AddFile({repr(path)}, {repr(mode)})")
      else:
        cmds.append(f"manager.AddRelativeFile({repr(path)}, {repr(mode)})")
    for s in config.connect_config.allowed_addresses:
      cmds.append("manager.AddConnectionRegex("
                  f"conn={repr(s)})")
    for process in config.popen_config.allowed_processes:
      cmds.append("manager.AddProcessRegex("
                  f"args={repr(process.args)},"
                  f" cwd={repr(process.cwd)},"
                  f" executable={repr(process.executable)})")
    for module in config.exec_config.allowed_modules:
      cmds.append(f"manager.AddModuleAllowedToExec({repr(module)})")
    for imp in config.import_config.allowed_imports:
      cmds.append(f"manager.AddImport({repr(imp)})")
    cmds.append("# Do not change config after activating the manager")
    cmds.append("manager.Activate()")
    return "\n".join(cmds)


def main(argv: Sequence[str]):
  del argv  # Unused.
  logs = open(_INPUT_LOG_PATH.value, "r").readlines()
  configurator = SecurityManagerConfigurator()
  configurator.Parse(logs)
  config_str = ""
  if _OUTPUT_FORMAT.value == "python":
    config_str = configurator.GetConfigAsPython()
  elif _OUTPUT_FORMAT.value == "proto":
    config_str = configurator.GetConfigAsProtoText()
  else:
    raise ValueError("Unknown output format")
  with open(_OUTPUT_CONFIG_PATH.value, "w") as f:
    f.write(config_str)

if __name__ == "__main__":
  flags.mark_flag_as_required("input_log_path")
  flags.mark_flag_as_required("output_config_path")
  app.run(main)
