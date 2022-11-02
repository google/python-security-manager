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

"""Module containing abstract class used to configure inspectors."""

import abc
from typing import Any, Dict

from pysecmgr.config import config_pb2


class Configurator(abc.ABC):
  """Abstract class for configurator implementations.

  Method-specific configurators should inherit from this class.
  """

  @abc.abstractmethod
  def ParseJsonEvent(self, json_data: str) -> bool:
    """Implementations parse a JSON string containing info on the audit event.

    Args:
      json_data: An event expressed as a JSON string.

    Returns:
      True on success and False on failure.
    """
    raise NotImplementedError("Must be implemented in subclasses.")

  @abc.abstractmethod
  def GetConfig(self) -> Dict[str, Any]:
    """Implementations return the configuration created from log entries."""
    raise NotImplementedError("Must be implemented in subclasses.")

  @abc.abstractmethod
  def Merge(self, config: config_pb2.Config) -> None:
    """Implementations merge the runtime and supplied configurations."""
    raise NotImplementedError("Must be implemented in subclasses.")
