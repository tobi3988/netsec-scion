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

from lib.packet.ctrl_pld import CtrlPayload
from lib.packet.host_addr import HostAddrIPv4
from lib.packet.ctrl_extn_data import CtrlExtnDataList
from lib.packet.scion_addr import ISD_AS
from scion_elem.scion_elem import SCIONElement

API_TOUT = 15


class MetricServer(SCIONElement, metaclass=ABCMeta):
    def __init__(self, server_id, conf_dir, prom_export=None):
        """
        :param str conf_dir: configuration directory.
        :param str prom_export: prometheus export address.
        """
        logging.debug('server id from metric is: ' + server_id)
        if server_id == 'ms1-10-1':
            self.publicIp = (HostAddrIPv4('127.0.0.254'), 31067)
            self.sendIt = False
        else:
            self.publicIp = (HostAddrIPv4('127.0.0.253'), 31066)
            self.sendIt = True
        super().__init__(server_id, conf_dir, public=[self.publicIp], bind=None, prom_export=prom_export)

    def run(self):
        """
        Run an instance of the Metric Server.
        """
        logging.info('addr is ' + str(self.addr))
        if self.sendIt:
            isd_as = ISD_AS.from_values(1, 10)
            path = self._get_path_via_sciond(isd_as).fwd_path()
            meta = self._build_meta(isd_as, HostAddrIPv4('127.0.0.254'), port=31067, path=path)
            self.send_meta(CtrlPayload(CtrlExtnDataList.from_values()), meta)
        super().run()
