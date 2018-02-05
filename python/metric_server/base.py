# Copyright 2014 ETH Zurich
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
:mod:`base` --- Base metric server
==================================
"""
import logging
from abc import ABCMeta

from lib.packet.host_addr import HostAddrIPv4
from scion_elem.scion_elem import SCIONElement


class MetricServer(SCIONElement, metaclass=ABCMeta):

    def __init__(self, server_id, conf_dir, prom_export=None):
        """
        :param str conf_dir: configuration directory.
        :param str prom_export: prometheus export address.
        """
        super().__init__(server_id, conf_dir, public=[(HostAddrIPv4('127.0.0.254'), 31067)], bind=None, prom_export=prom_export)

    def run(self):
        """
        Run an instance of the Metric Server.
        """
        logging.debug('Hello from Metric Server')
        super().run()
