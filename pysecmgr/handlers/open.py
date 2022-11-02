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

"""Inspector module that matches open() paths against regular expressions."""
import inspect
import json
import logging
import os.path
import pathlib
import platform
import re
import sys
from typing import Any, Dict, Tuple, Union

from pysecmgr import configurator
from pysecmgr import inspector
from pysecmgr.config import config_pb2


class OpenInspector(inspector.Inspector):
  """This class inspects python open() calls and allows or rejects them.

    Typical usage example:

      instance = OpenInspector(config)
      instance.check(open_call_tuple_with_args)
  """

  def __init__(self, enforce: bool, audit: bool = False):
    self._reject_path_backtracking = (
        config_pb2.OpenConfig.reject_path_backtracking.DESCRIPTOR.default_value  
    )
    self._enforce_allowlist = (
        config_pb2.OpenConfig.enforce_allowlist.DESCRIPTOR.default_value  
    )
    self._allowed_path_regexes = {}
    self._allowed_path_ops = {}
    self._reject_symlink = (
        config_pb2.OpenConfig.reject_symlink.DESCRIPTOR.default_value  
    )
    self._enforce = enforce
    self._audit = audit

  def LoadConfig(  
      self, config: config_pb2.OpenConfig) -> bool:
    """Loads the configuration for this inspector.

    Args:
      config: general configuration for this class.

    Returns:
      A bool indicating whether the config was successfully loaded.
    """
    for path_regex in config.allowed_paths:
      try:
        self._allowed_path_regexes[path_regex] = re.compile(path_regex)
        self._allowed_path_ops[path_regex] = config.allowed_paths[path_regex]
      except re.error:
        logging.error("Unable to compile %s: %s", path_regex, str(re.error))
        return False

    self._reject_path_backtracking = config.reject_path_backtracking
    self._enforce_allowlist = config.enforce_allowlist
    self._reject_symlink = config.reject_symlink

    return True

  @inspector.Enforceable
  def CheckCall(self, args: Tuple[str, str, Any]):
    """Checks if the open() call is allowed.

    Checks if the open path is allowed, whether the operation
    (e.g. read, write) for that path is allowed.

    Args:
      args: A tuple containing the specifics of the open() call.

    Raises:
      IOError: exception when the open is not allowed.
    """
    (path, flags, unused_flags) = args
    # Allow all file descriptor
    if isinstance(path, int): return

    if self._reject_path_backtracking: self._CheckPathBacktracking(path)

    if self._reject_symlink: self._CheckSymlink(path)

    # Normalize the path and make absolute if relative, eq to
    # normpath(join(os.getcwd(), path))
    path = os.path.abspath(path)

    if self._enforce_allowlist:
      try:
        self._CheckMatchAllowlist(path, flags)
      except IOError as e:
        # Allow traceback to open files in the sys.path 
        if self._IsAllowedTraceback(path, flags):
          return
        # Allow import to open files in the sys.path 
        if self._IsAllowedImport(path, flags):
          return
        raise e

  def GenerateLogEntry(self, args: Tuple[str, str, Any]) -> Dict[str, Any]:
    """Compute a log entry for open() calls."""
    (path, flags, unused_flags) = args
    log_entry = {}
    log_entry["path"] = path
    log_entry["abs_path"] = os.path.abspath(path)
    log_entry["is_absolute"] = os.path.isabs(path)
    log_entry["flags"] = flags
    return log_entry

  def _CheckPathBacktracking(self, path: str):
    """Checks if the path includes the `../` pattern."""
    payload = ["../"]
    if platform.system() == "Windows":
      payload.append("..\\")

    # path can either be a string or an open file descriptor
    if not isinstance(path, str):
      path = os.fspath(path)

    # Only raise an error if normal path is not the same as the path
    # This is to prevent catching path with "..../" in them for example
    # Adding a slash at the end to allow opening directory
    if os.path.join(os.getcwd(), path) not in [
        os.path.abspath(path),
        "{}/".format(os.path.abspath(path)),
    ]:
      if any([(p in path) for p in payload]):
        raise IOError("Path backtracking is not allowed: {}".format(path))

  def _CheckSymlink(self, path: str):
    """Checks if a path is a symlink."""
    if os.path.islink(path):
      raise IOError("Symlink are not allowed for path: {}".format(path))

  def _CheckMatchAllowlist(self, path: str, flags: Union[str, None]):
    """Checks if a path and flags matched the allowlist."""
    matched_path_regex = None
    for path_regex in self._allowed_path_regexes:
      if self._allowed_path_regexes[path_regex].fullmatch(path):
        matched_path_regex = path_regex
        break

    if not matched_path_regex:
      raise IOError("Path is not allowed: {}".format(path))

    # Flag can be null when using pathlib, default is r
    if not flags:
      flags = "r"

    # Check if the flag is allowed
    for flag in flags:
      if flag not in self._allowed_path_ops[matched_path_regex]:
        raise IOError('Open "{}" with flags "{}" is not allowed'.format(
            path, flags))

  def _IsInSysPath(self, path: str) -> bool:
    for p in sys.path:
      # Path should be relative to a directory in sys.path (e.g. it could be in
      # a submodule). Parent modules’ __path__ can have realpaths relative to a
      # symlink from sys.path, so resolved symlink value from sys.path also
      # needs to be checked.
      if pathlib.PurePath(path).is_relative_to(p) or pathlib.PurePath(
          path).is_relative_to(os.path.realpath(p)):
        return True
    return False

  def _IsCalledByTraceback(self) -> bool:
    # Frames before traceback can only be tokenize or linecache
    expected_frames = ["traceback", "linecache", "tokenize"]
    try:
      # Find the frame that is calling open, need to go back up the following
      # frames: _IsCalledByTraceback, _IsAllowedTraceback, CheckCall,
      # Inner (Inspector class), Hook (SecurityManager)
      frame = inspect.currentframe().f_back.f_back.f_back.f_back.f_back  
      while frame and expected_frames:
        if frame.f_globals["__name__"] == expected_frames[-1]:
          if expected_frames[-1] == "traceback":
            return True
          frame = frame.f_back
        else:
          expected_frames.pop()
    except AttributeError:
      return False
    return False

  def _IsCalledByImport(self) -> bool:
    try:
      # Find the frame that is calling open, need to go back up the following
      # frames: _IsCalledByTraceback, _IsAllowedTraceback, CheckCall,
      # Inner (Inspector class), Hook (SecurityManager)
      frame = inspect.currentframe().f_back.f_back.f_back.f_back.f_back  
      if frame.f_globals["__name__"] == "importlib._bootstrap_external":
        return True
      return False
    except AttributeError:
      return False

  def _IsAllowedTraceback(self, path: str, flags: Union[str, None]) -> bool:
    # path should be in sys.path or a subdirectory
    if not self._IsInSysPath(path):
      return False

    # open should be called by traceback
    if not self._IsCalledByTraceback():
      return False

    return True

  def _IsAllowedImport(self, path: str, flags: Union[str, None]) -> bool:
    # path should be in sys.path or a subdirectory
    if not self._IsInSysPath(path):
      return False

    # open should be called by traceback
    if not self._IsCalledByImport():
      return False

    return True


class OpenConfigurator(configurator.Configurator):
  """Parses log files and turns them into a config."""

  def __init__(self):
    self._config: config_pb2.OpenConfig = config_pb2.OpenConfig()

  def ParseJsonEvent(self, json_data: str) -> bool:
    """Parses the JSON string and updates the config.

    Args:
      json_data: A JSON string containing the path and flags of the open call.

    Returns:
      True on success and false on failure.
    """
    try:
      json_data = json.loads(json_data)
    except json.decoder.JSONDecodeError:
      logging.warning("Unable to parse: %s", json_data)
      return False

    attrs = ["path", "flags"]
    for attr in attrs:
      if attr not in json_data:
        logging.warning("'%s' not found in: %s", attr, json_data)
        return False

      self._AddEntry(
          json_data["path"],
          json_data["flags"],
          self._config.allowed_paths,
      )
    return True

  def _AddEntry(self, path, flags, allowed_paths):
    if path not in allowed_paths:
      allowed_paths[path] = flags
    else:
      for flag in flags:
        if flag not in allowed_paths[path]:
          allowed_paths[path] += flag

  def GetConfig(self):
    return self._config

  def Merge(self, config: config_pb2.Config) -> None:
    config.open_config.CopyFrom(self._config)
