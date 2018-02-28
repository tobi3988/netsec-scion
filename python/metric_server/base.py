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
from collections import defaultdict

import copy

import lib.app.sciond as lib_sciond

from lib.defines import METRIC_SERVICE
from lib.packet.ctrl_pld import CtrlPayload
from lib.packet.host_addr import HostAddrIPv4
from lib.packet.ctrl_extn_data import CtrlExtnDataList, CtrlExtnData
from lib.packet.scion_addr import ISD_AS
from lib.thread import thread_safety_net
from lib.types import PayloadClass
from lib.util import load_yaml_file
from metric_server.constants import LAMBDA, MAX_INTERVAL, RECALCULATE_METRICS_INTERVAL_SECONDS, \
    TIME_RANGE_TO_KEEP_MEASUREMENTS
from metric_server.lib.lib import get_timestamp_in_ms, remove_duplicates
from metric_server.metrics.latency import calculate_one_way_delay, calculate_one_way_delay_variation
from metric_server.metrics.packet_loss import calculate_packet_loss
from metric_server.metrics.packet_reordering import calculate_packet_reordering
from scion_elem.scion_elem import SCIONElement


class MetricServer(SCIONElement, metaclass=ABCMeta):
    SERVICE_TYPE = METRIC_SERVICE

    def __init__(self, server_id, conf_dir, prom_export=None):
        """
        :param str conf_dir: configuration directory.
        :param str prom_export: prometheus export address.
        """
        logging.debug('server id from metric server is: ' + server_id)
        super().__init__(server_id, conf_dir, prom_export=prom_export)
        self.metric_servers = load_yaml_file(conf_dir + '/../../../' + 'metrics_list')
        self.CTRL_PLD_CLASS_MAP = {
            PayloadClass.CTRLEXTNDATALIST: {PayloadClass.CTRLEXTNDATALIST: self.handle_extn},
        }
        self.measurement_streams = defaultdict(lambda: [])
        self.aggregated_metrics = defaultdict(lambda: One_Hop_Metric(None))
        self.measurement_stream_lock = threading.Lock()

    def run(self):
        """
        Run an instance of the Metric Server.
        """
        for interface in self.topology.child_interfaces:
            self.start_measurements_for_interface(interface)
        for interface in self.topology.parent_interfaces:
            self.start_measurements_for_interface(interface)
        self.start_metric_calculations()
        super().run()

    def start_measurements_for_interface(self, interface):
        isd_as = interface.isd_as
        threading.Thread(
            target=thread_safety_net, args=(self.send_measurements, isd_as),
            name="MS.measure_" + str(isd_as), daemon=True).start()

    def send_measurements(self, isd_as):
        address = self.metric_servers[str(isd_as)][0]
        path = self._get_path_via_sciond(isd_as)
        while path is None:
            time.sleep(1)
            path = self._get_path_via_sciond(isd_as)
            logging.debug("waiting to get valid path")
        meta = self._build_meta(isd_as, HostAddrIPv4(address["Addr"]), port=int(address["L4Port"]),
                                path=path.fwd_path())
        sequence_number = 0
        while self.run_flag.is_set():
            timestamp = str(get_timestamp_in_ms()).encode()
            self.send_meta(CtrlPayload(
                CtrlExtnDataList.from_values(items=[CtrlExtnData.from_values(type=b'timestamp', data=timestamp),
                                                    CtrlExtnData.from_values(type=b'seq',
                                                                             data=str(sequence_number).encode())])),
                meta)
            sequence_number += 1
            time.sleep(self._sampe_interval())

    def _sampe_interval(self):
        interval = random.expovariate(LAMBDA)
        if interval > MAX_INTERVAL:
            interval = MAX_INTERVAL
        return interval

    def handle_extn(self, payload, meta=None):
        logging.debug("cpld is " + str(payload))
        logging.debug("meta is " + str(meta.ia))
        received_at = get_timestamp_in_ms()
        sent_at = None
        sequence_number = None
        measurement = payload.union
        for element in measurement.items():
            if element.type == b"timestamp":
                sent_at = int(element.data.decode())
            if element.type == b"seq":
                sequence_number = int(element.data.decode())
        measurement = Measurement(sequence_number, sent_at, received_at)
        with self.measurement_stream_lock:
            self.measurement_streams[str(meta.ia)].append(measurement)

    def start_metric_calculations(self):
        threading.Thread(
            target=thread_safety_net, args=(self.calculate_metrics,),
            name="MS.calc_metrics", daemon=True).start()

    def calculate_metrics(self):
        while self.run_flag.is_set():
            streams_copy = {}
            self.clean_measurement_stream()
            with self.measurement_stream_lock:
                streams_copy = copy.deepcopy(self.measurement_streams)
            for isd_as in streams_copy.keys():
                measurements = streams_copy[isd_as]
                self.aggregated_metrics[isd_as].isd_as = isd_as

                self.aggregated_metrics[isd_as].avg_one_way_delay = calculate_one_way_delay(measurements)
                self.aggregated_metrics[isd_as].packet_loss = calculate_packet_loss(measurements)
                self.aggregated_metrics[isd_as].packet_reordering = calculate_packet_reordering(measurements)
                self.aggregated_metrics[isd_as].one_way_delay_variation = calculate_one_way_delay_variation(measurements)
                logging.debug("avg owd is %d" % self.aggregated_metrics[isd_as].avg_one_way_delay)
                logging.debug("packet loss is %1.4f" % self.aggregated_metrics[isd_as].packet_loss)
                logging.debug("packet reordering is %1.4f" % self.aggregated_metrics[isd_as].packet_reordering)
                logging.debug("delay variation is %s" % str(self.aggregated_metrics[isd_as].one_way_delay_variation))
            time.sleep(RECALCULATE_METRICS_INTERVAL_SECONDS)

    def clean_measurement_stream(self):
        # TODO get rid off duplicated sequencenumbers
        with self.measurement_stream_lock:
            timeout = get_timestamp_in_ms() - TIME_RANGE_TO_KEEP_MEASUREMENTS
            for isd_as in self.measurement_streams.keys():
                measurements = self.measurement_streams[isd_as]
                cleaned_measurements = list(
                    filter(lambda measurement: measurement.sent_at > timeout, measurements))
                cleaned_measurements = remove_duplicates(cleaned_measurements,
                                                         lambda measurement: measurement.sequence_number)
                self.measurement_streams[isd_as] = cleaned_measurements
                logging.debug("length after clean is: %d" % len(cleaned_measurements))


class Measurement:
    def __init__(self, sequence_number, sent_at, received_at):
        self.received_at = received_at
        self.sequence_number = sequence_number
        self.sent_at = sent_at
        self.one_way_delay = received_at - sent_at

    def __str__(self):
        s = []
        s.append("{received_at: %d" % self.received_at)
        s.append("sequence_number: %d" % self.sequence_number)
        s.append("sent_at: %d}" % self.sent_at)

        return "\n".join(s)


class One_Hop_Metric:
    def __init__(self, isd_as):
        self.isd_as = isd_as
        self.avg_one_way_delay = -1
        self.packet_loss = 0.0
        self.packet_reordering = 0.0
        self.one_way_delay_variation = {}

    def __str__(self):
        s = []
        s.append("{isd_as: %s" % self.isd_as)
        s.append("avg_one_way_delay: %d" % self.avg_one_way_delay)
        s.append("packet_loss: %1.4f" % self.packet_loss)
        s.append("packet_reordering: %1.4f" % self.packet_reordering)
        return "\n".join(s)
