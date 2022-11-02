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

"""Inspector module that matches connect() address against regular expressions."""
import json
import logging
import re
from typing import Any, Dict, Sequence, Tuple, Union

from pysecmgr import configurator
from pysecmgr import inspector
from pysecmgr.config import config_pb2


class ConnectInspector(inspector.Inspector):
  """This class inspects python connect() calls and allows or rejects them.

    Typical usage example:

      instance = ConnectInspector(config)
      instance.check(connect_call_tuple_with_args)
  """

  def __init__(self, enforce: bool, audit: bool = False):
    self._allowed_address_regexes = []
    self._enforce = enforce
    self._audit = audit
    self._enforce_allowlist = (
        config_pb2.ConnectConfig.enforce_allowlist.DESCRIPTOR.default_value  
    )

  def LoadConfig(  
      self, config: config_pb2.ConnectConfig) -> bool:
    """Loads the configuration for this inspector.

    Args:
      config: general configuration for this class.

    Returns:
      A bool indicating whether the config was successfully loaded.
    """
    for address_regex in config.allowed_addresses:
      try:
        self._allowed_address_regexes.append(re.compile(address_regex))
      except re.error:
        logging.error("Unable to compile %s: %s", address_regex, str(re.error))
        return False

    self._enforce_allowlist = config.enforce_allowlist

    return True

  @inspector.Enforceable
  def CheckCall(self, args: Tuple[Any, Tuple[str, int]]):
    """Checks if the connect() call is allowed.

    Checks whether the connect host:port is allowed.

    Args:
      args: A tuple containing a socket and an address.
          The format of address depends on the address family.

    Raises:
      OSError: exception when the connect is not allowed.
      IndexError: if the address is not in expected format.
    """

    sock, address = args
    if self._enforce_allowlist:
      self._CheckMatchAllowlist(sock.family.name, address)

  def GenerateLogEntry(self, args: Tuple[Any, Tuple[str,
                                                    int]]) -> Dict[str, Any]:
    """Compute a log entry for connect() calls."""
    sock, address = args
    log_entry = {}
    log_entry["family"] = sock.family.name
    log_entry["address"] = address
    return log_entry

  def _CheckMatchAllowlist(self, family: str,
                           address: Union[Sequence[Union[str, int]], str]):
    if family not in ["AF_INET", "AF_INET6", "AF_UNIX"]:
      # Unsupported socket family
      return

    if family == "AF_INET":
      address = ":".join([str(obj) for obj in address])
    elif family == "AF_INET6":
      address = "[{ip}]:{port}".format(ip=address[0], port=address[1])

    for address_regex in self._allowed_address_regexes:
      if address_regex.fullmatch(address):
        return

    raise OSError(-2, "Address is not allowed: {}".format(address))


class ConnectConfigurator(configurator.Configurator):
  """Parses log files and turns them into a config."""

  def __init__(self):
    self._config = config_pb2.ConnectConfig()

  def ParseJsonEvent(self, json_data: str) -> bool:
    """Parses the JSON string and updates the config.

    Args:
      json_data: A JSON string containing the host and port of the connect call.

    Returns:
      True on success and false on failure.
    """
    try:
      socket_event = json.loads(json_data)
    except json.decoder.JSONDecodeError:
      logging.warning("Unable to parse: %s", json_data)
      return False

    family = socket_event.get("family")
    address = socket_event.get("address")
    if isinstance(address, Sequence):
      if len(address) < 2:
        logging.warning("Wrong address format: %s", str(address))
        return False

    allowed_address = ""
    if family == "AF_INET":
      allowed_address = r"^{ip}:{port}$".format(
          ip=re.escape(address[0]), port=re.escape(str(address[1])))
    elif family == "AF_INET6":
      allowed_address = r"^\[{ip}\]:{port}$".format(
          ip=re.escape(address[0]), port=re.escape(str(address[1])))
    elif family == "AF_UNIX":
      allowed_address = r"^{}$".format(re.escape(address))
    else:
      logging.warning("Address family not supported: %s", str(family))
      return False

    if allowed_address not in self._config.allowed_addresses:
      self._config.allowed_addresses.append(allowed_address)
    return True

  def GetConfig(self):
    return self._config

  def Merge(self, config: config_pb2.Config) -> None:
    config.connect_config.CopyFrom(self._config)
