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
import random
import threading
from abc import ABCMeta

# External packages
import time

import lib.app.sciond as lib_sciond

from lib.defines import METRIC_SERVICE
from lib.packet.ctrl_pld import CtrlPayload
from lib.packet.host_addr import HostAddrIPv4
from lib.packet.ctrl_extn_data import CtrlExtnDataList, CtrlExtnData
from lib.packet.scion_addr import ISD_AS
from lib.thread import thread_safety_net
from lib.util import load_yaml_file
from scion_elem.scion_elem import SCIONElement


MAX_INTERVAL = 30

MEAN_INTERVAL = 10.0
LAMBDA = 1.0 / MEAN_INTERVAL

API_TOUT = 30


class MetricServer(SCIONElement, metaclass=ABCMeta):
    SERVICE_TYPE = METRIC_SERVICE

    def __init__(self, server_id, conf_dir, prom_export=None):
        """
        :param str conf_dir: configuration directory.
        :param str prom_export: prometheus export address.
        """
        logging.debug('server id from metric server is: ' + server_id)
        self.metric_servers = load_yaml_file(conf_dir + '/../../../'+'metrics_list')
        super().__init__(server_id, conf_dir, prom_export=prom_export)

    def run(self):
        """
        Run an instance of the Metric Server.
        """
        for interface in self.topology.child_interfaces:
            self.start_measurements_for_interface(interface)
        for interface in self.topology.parent_interfaces:
            self.start_measurements_for_interface(interface)

        super().run()

    def start_measurements_for_interface(self, interface):
        isd_as = interface.isd_as
        threading.Thread(
            target=thread_safety_net, args=(self.send_measurements, isd_as),
            name="MS.measure" + str(isd_as), daemon=True).start()

    def send_measurements(self, isd_as):
        address = self.metric_servers[str(isd_as)][0]
        logging.debug("metric server to contact is " + str(address))
        path = self._get_path_via_sciond(isd_as)
        while path is None:
            time.sleep(1)
            path = self._get_path_via_sciond(isd_as)
            logging.debug("waiting to get valid path")
        meta = self._build_meta(isd_as, HostAddrIPv4(address["Addr"]), port=int(address["L4Port"]),
                                path=path.fwd_path())
        sequence_number = 0
        while self.run_flag.is_set():
            timestamp = str(int(round(time.time() * 1000))).encode()
            self.send_meta(CtrlPayload(
                CtrlExtnDataList.from_values(items=[CtrlExtnData.from_values(type=b'timestamp', data=timestamp),
                                                    CtrlExtnData.from_values(type=b'seq', data=str(sequence_number).encode())])), meta)
            sequence_number += 1
            time.sleep(self._sampe_interval())

    def _sampe_interval(self):
        interval = random.expovariate(LAMBDA)
        if interval > MAX_INTERVAL:
            interval = MAX_INTERVAL
        return interval
