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

"""The Python Security Manager main module.

This is a middleware security layer in Python that can monitor and prevent
insecure logic from being run. As a defence-in-depth security mechanism, it can
reduce the prevalance and impact of common vulnerabilities.

A typical usage example:

pysecmgr = SecurityManager(enforce=True)
pysecmgr.InstallCommonPythonRules()
pysecmgr.Activate()
"""

from collections.abc import Callable
import functools
import logging
import os.path
import re
import sys
from typing import Tuple, Dict, Any, Sequence, Optional

from google.protobuf import json_format
from google.protobuf import text_format

from pysecmgr.config import config_pb2
from pysecmgr.handlers import connect as connect_handler
from pysecmgr.handlers import exec as exec_handler
from pysecmgr.handlers import imports as import_handler
from pysecmgr.handlers import open as open_handler
from pysecmgr.handlers import pickle as pickle_handler
from pysecmgr.handlers import popen as popen_handler
from pysecmgr.handlers import system as system_handler


def Preactivation(func: Callable[..., None]) -> Callable[..., None]:
  """Decorator to prevent configuration methods called after Activate()."""

  @functools.wraps(func)
  def Inner(self, *args, **kwargs):
    if self.IsActivated():
      raise RuntimeError(
          "Configuration methods cannot be called after Activate()"
      )
    func(self, *args, **kwargs)

  return Inner


class SecurityManager:
  """Activates Python Security Manager with all configured audit hooks."""

  def __init__(self, enforce: bool = True, audit: bool = True):
    """Initializes an instance of SecurityManager.

    Args:
      enforce: Enable blocking mode.
      audit: Enable audit logging.
    """
    self._enforce = enforce
    self._audit = audit
    self._config = config_pb2.Config()
    self._activated = False

  def IsActivated(self) -> bool:
    """Returns the activation status of a SecurityManager instance."""
    return self._activated

  def IsEnforced(self) -> bool:
    return self._enforce

  def HasAudit(self) -> bool:
    return self._audit

  @Preactivation
  def LoadConfig(self, config: Dict[str, Any]):
    """Loads the configuration and validates the protobuf schema.

    Args:
      config: Configurations for the available inspector modules.
    """
    self._config = json_format.ParseDict(
        js_dict=config if config else {},
        message=config_pb2.Config(),
        ignore_unknown_fields=True,
    )

  def GetConfig(self) -> config_pb2.Config:
    """Returns the loaded configuration protobuf."""
    return self._config

  def LogConfig(self):
    logging.info(
        "%s:%s:%s:%s:%s",
        "PYSECMGR_CONFIG",
        "Activated={}".format(self.IsActivated()),
        "Enforce={}".format(self.IsEnforced()),
        "Audit={}".format(self.HasAudit()),
        text_format.MessageToString(self.GetConfig(), as_utf8=True))

  @Preactivation
  def AddFile(self, file_path: str, perm: str):
    """Adds a rule that allows access to a file.

    Args:
      file_path: Full file path.
      perm: Allowed permissions. Should only contains characters "rwxabt+"
        according to https://docs.python.org/3/library/functions.html#open.
        Validated in AddPathRegex().

    Raises:
      ValueError: Path or permission is invalid.
    """
    if not file_path:
      raise ValueError("Path cannot be empty")
    path_regex = "^{}$".format(re.escape(file_path))
    self.AddPathRegex(path_regex, perm)

  @Preactivation
  def AddRelativeFile(self, relative_file_path: str, perm: str):
    """Adds a rule that allows access to a relative file.

    Args:
      relative_file_path: Relative file path.
      perm: Allowed permissions. Should only contains characters "rwxabt+"
        according to https://docs.python.org/3/library/functions.html#open.
        Validated in AddPathRegex().

    Raises:
      ValueError: Path or permission is invalid.
    """
    if not relative_file_path:
      raise ValueError("Path cannot be empty")
    file_path = os.path.abspath(relative_file_path)
    self.AddFile(file_path, perm)

  @Preactivation
  def AddFolder(self, folder_path: str, perm: str):
    """Adds a rule that allows access to all files inside a folder.

    Args:
      folder_path: Full folder path.
      perm: Allowed permissions. Should only contains characters "rwxabt+"
        according to https://docs.python.org/3/library/functions.html#open.
        Validated in AddPathRegex().

    Raises:
      ValueError: Path or permissions are invalid.
    """
    if not folder_path:
      raise ValueError("Path cannot be empty")
    if folder_path[-1] == "/":
      folder_path = folder_path[:-1]
    # Allowlist the folder
    self.AddFile(folder_path, perm)
    # Allowlist the sub-folders and files. The path is normalized in the open
    # hook before matching the regex, so matching any character except null at
    # the end of the folder path should be fine.
    path_re = r"^{}\/[^\x00]*$".format(re.escape(folder_path))
    self.AddPathRegex(path_re, perm)

  @Preactivation
  def AddRelativeFolder(self, relative_folder_path: str, perm: str):
    """Adds a rule that allows access to all files inside a relative folder.

    Args:
      relative_folder_path: Relative folder path.
      perm: Allowed permissions. Should only contains characters "rwxabt+"
        according to https://docs.python.org/3/library/functions.html#open.
        Validated in AddPathRegex().

    Raises:
      ValueError: Path or permissions are invalid.
    """
    if not relative_folder_path:
      raise ValueError("Path cannot be empty")
    folder_path = os.path.abspath(relative_folder_path)
    self.AddFolder(folder_path, perm)

  @Preactivation
  def AddPathRegex(self, path: str, perm: str):
    """Adds a rule that allows access to a path.

    Args:
      path: Regular expression that defines the path(s) this rule applies to.
      perm: Allowed permissions. Should only contains characters "rwxabt+"
        according to https://docs.python.org/3/library/functions.html#open.

    Raises:
      ValueError: Path or permission is invalid.
    """
    try:
      re.compile(path)
    except re.error as e:
      raise ValueError("Path regular expression is invalid") from e

    uperm = set(perm)
    if uperm > set({"r", "w", "x", "a", "b", "t", "+"}):
      raise ValueError("Permission string can only contain rwxabt+")

    self._config.open_config.allowed_paths[path] = "".join(uperm)

  @Preactivation
  def AddConnectionRegex(self, conn: str):
    """Adds a rule that allows an outgoing network connection.

    Currently, only AF_INET, AF_INET6 and AF_UNIX socket families are supported.

    Args:
      conn: Regular expression defining the destination of an outgoing network
        network connection. The format is an address followed by the ":"
        character and then the port.

    Raises:
      ValueError: Connection regular expression is invalid.
    """
    try:
      re.compile(conn)
    except re.error as e:
      raise ValueError("Connection regular expression is invalid") from e

    self._config.connect_config.allowed_addresses.append(conn)

  @Preactivation
  def AddProcessRegex(
      self,
      args: Sequence[str],
      cwd: Optional[str] = "",
      executable: Optional[str] = "",
  ):
    """Adds a rule that allows the creation of a process via subprocess.Popen().

    Args:
      args: List of regular expressions in the same order as the program
        argument sequence in the args argument of the Popen() constructor.
      cwd: Regular expression for the cwd argument of the Popen() constructor.
      executable: Regular expression for the executable argument of the Popen()
        constructor.

    Raises:
      ValueError: A regular expression is invalid.
    """
    try:
      re.compile(cwd)
    except re.error as e:
      raise ValueError(
          "Current working directory regular expression is invalid"
      ) from e

    try:
      re.compile(executable)
    except re.error as e:
      raise ValueError("Executable regular expression is invalid") from e

    try:
      [re.compile(v) for v in args]
    except re.error as e:
      raise ValueError("Argument regular expression is invalid") from e

    process = self._config.popen_config.allowed_processes.add()
    process.args[:] = args
    process.cwd = cwd
    process.executable = executable

  @Preactivation
  def AddModuleAllowedToExec(self, module_name: str):
    """Adds a rule that allows the specified module to call exec().

    Args:
      module_name: Python module name.
    """
    self._config.exec_config.allowed_modules.append(module_name)

  @Preactivation
  def AddImport(self, module_name: str):
    """Adds a rule that allows a specific module to be imported.

    Args:
      module_name: Python module name.
    """
    self._config.import_config.allowed_imports.append(module_name)

  @Preactivation
  def AllowAllImports(self):
    """Allows all module imports by not enforcing the allowlist."""
    self._config.import_config.enforce_allowlist = False

  @Preactivation
  def EnforceImportAllowlist(self):
    """Enforces the module import allowlist."""
    self._config.import_config.enforce_allowlist = True

  @Preactivation
  def AllowUnpickling(self):
    """Allows the unpickling operation from the pickle module. Discouraged.

    It is possible to construct malicious pickle data that will execute
    arbitrary code during unpickling operations. Never unpickle data that could
    have come from an untrusted source.
    """
    self._config.pickle_config.reject_pickle_find_class = False

  @Preactivation
  def AllowPathBacktracking(self):
    """Allows dot-dot-slash (../) sequences in os.open() paths. Discouraged.

    Dot-dot-slash (../) sequences can result in path traversal vulnerabilities.
    """
    self._config.open_config.reject_path_backtracking = False

  @Preactivation
  def AllowSymlink(self):
    """Allows symlink files to be opened using os.open()."""
    self._config.open_config.reject_symlink = False

  @Preactivation
  def AllowPopenShell(self):
    """Allows subprocess.Popen() to execute via a shell. Discouraged."""
    self._config.popen_config.reject_shell = False

  @Preactivation
  def AllowAllPaths(self):
    """Allows unrestricted access to file system paths. Discouraged."""
    self._config.open_config.enforce_allowlist = False

  @Preactivation
  def AllowAllAddresses(self):
    """Allows unrestricted creation of sockets. Discouraged."""
    self._config.connect_config.enforce_allowlist = False

  @Preactivation
  def AllowAllProcesses(self):
    """Allows unrestricted creation of processes. Discouraged."""
    self._config.popen_config.enforce_allowlist = False

  @Preactivation
  def AllowAllExec(self):
    """Allows unrestricted use of exec(). Discouraged."""
    self._config.exec_config.enforce_allowlist = False

  @Preactivation
  def InstallCommonPythonRules(self):
    """Convenience method to prepopulate generic rules automatically."""
    # Allow Python to import core runtime system modules
    self.AddModuleAllowedToExec("importlib._bootstrap")

    # Allow the collections module to use exec()
    self.AddModuleAllowedToExec("collections")

  def Activate(self):
    """Enforces Python Security Manager rules by adding audit hooks.

    Raises:
      RuntimeError: Python Security Manager was already activated.
    """
    if self._activated:
      raise RuntimeError("Python Security Manager was already activated")
    self._activated = True
    self._CreateHookMap()
    sys.addaudithook(self._Hook)

  def _CreateHookMap(self):
    """Creates a map of Python audit hooks and configuration."""
    self._hook_id_mapping = {
        "exec": exec_handler.ExecInspector(self._enforce, self._audit),
        "import": import_handler.ImportInspector(self._enforce, self._audit),
        "open": open_handler.OpenInspector(self._enforce, self._audit),
        "os.system": system_handler.SystemInspector(self._enforce, self._audit),
        "pickle.find_class": pickle_handler.PickleInspector(
            self._enforce, self._audit
        ),
        "socket.connect": connect_handler.ConnectInspector(
            self._enforce, self._audit
        ),
        "subprocess.Popen": popen_handler.PopenInspector(
            self._enforce, self._audit
        ),
    }

    self._config_id_mapping = {
        "exec": self._config.exec_config,
        "import": self._config.import_config,
        "open": self._config.open_config,
        "os.system": self._config.system_config,
        "pickle.find_class": self._config.pickle_config,
        "socket.connect": self._config.connect_config,
        "subprocess.Popen": self._config.popen_config,
    }

    for event, hook in self._hook_id_mapping.items():
      if not hook.LoadConfig(self._config_id_mapping[event]):
        sys.exit(1)

  def _Hook(self, hook_id: str, args: Tuple):  
    """Invokes the defined inspectors for Python audit hook events."""
    if hook_id in self._hook_id_mapping:
      self._hook_id_mapping[hook_id].CheckCall(args)
