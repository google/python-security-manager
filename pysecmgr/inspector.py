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

"""Module containing abstract class for inspector implementations."""
import abc
from collections.abc import Callable
import functools
import inspect
import json
import logging
import traceback
from typing import Any, Dict, Tuple

LOGGING_PREFIX = "AUDIT_EVENT"


class Inspector(abc.ABC):
  """Abstract class for inspector implementations.

  Method-specific inspectors should inherit from this class.
  """

  @abc.abstractmethod
  def LoadConfig(self, config: Dict[str, Any]) -> bool:
    """Implementations initiate using the given configuration."""
    raise NotImplementedError("Must be implemented in subclasses.")

  @abc.abstractmethod
  def CheckCall(self, args: Tuple[Any, ...]) -> None:
    """Implementations inspect Python method calls."""
    raise NotImplementedError("Must be implemented in subclasses.")

  @abc.abstractmethod
  def GenerateLogEntry(self, args: ...) -> Dict[str, Any]:
    """Implementations compute a log entry with the relevant arguments."""
    raise NotImplementedError("Must be implemented in subclasses.")

  def LogEvent(self, json_data: str) -> None:
    """Logs an audit event.

    Used by inspector implementations to log an audit event for the
    purpose of allowing a separate tool to parse these events and create
    a configuration file.

    Args:
      json_data: A JSON string containing the details of the audit event.
    """
    logging.info(
        "%s:%s:%s:%s",
        LOGGING_PREFIX,
        self.__class__.__name__,
        json_data,
        self._ExtractStack())

  def _ExtractStack(self):
    """Extract the stack trace.

    This function re-implement the traceback extract_stack function while
    avoiding opening a file to read the codeline value (lookup_lines=False).
    This because using the "open" function inside an open hook handler triggers
    an infinite loop.

    Returns:
      String representation of the stack trace.
    """

    try:
      # Go back up the following frames: _ExtractStack and LogEvent
      f = inspect.currentframe().f_back.f_back  
    except AttributeError:
      return None

    stack = traceback.StackSummary.extract(
        traceback.walk_stack(f),
        lookup_lines=False)
    stack.reverse()
    result = "Stack (most recent call last):\n"
    for s in stack:
      result += '  File "{}", line {}, in {}\n'.format(
          s.filename, s.lineno, s.name)
    return result


def Enforceable(func: Callable[..., None]) -> Callable[..., None]:
  """Decorator to prevent exceptions when enforcement is disabled."""

  @functools.wraps(func)
  def Inner(*args, **kwargs):
    self = args[0]
    if not self._enforce and not self._audit:  
      return
    try:
      func(*args, **kwargs)
    except Exception as e:  
      if self._audit:  
        log_entry = self.GenerateLogEntry(*args[1:])
        try:
          self.LogEvent(json.dumps(log_entry))
        except TypeError as te:
          error = {}
          error["serialization_error"] = str(te)
          error["log_entry"] = repr(log_entry)
          self.LogEvent(json.dumps(error))
      if self._enforce:  
        raise e

  return Inner
