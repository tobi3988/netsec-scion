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
from metric_server.metrics.latency import calculate_one_way_delay, calculate_one_way_delay_variation, \
    calculate_variance, calculate_percentile999, calculate_normalized_mean
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
            PayloadClass.METRICS: {PayloadClass.METRICS: self.handle_metrics_from_bs},
        }
        self.measurement_streams = defaultdict(lambda: [])
        self.aggregated_metrics = defaultdict(lambda: One_Hop_Metric(None, str(self.topology.isd_as)))
        self.all_aggregated_metrics = {}
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
        path = self.get_one_hop_path(isd_as)
        while path is None:
            time.sleep(1)
            path = self.get_one_hop_path(isd_as)
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

    def get_one_hop_path(self, isd_as):
        paths = self._get_paths_via_sciond(isd_as)
        if paths is not None:
            for path in paths:
                logging.debug('path is %s' % str(path.path()))
                if path.path().number_of_ifs() == 2:
                    return path.path()
        return None

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

    def handle_metrics_from_bs(self, payload, meta=None):
        logging.debug("cpld is " + str(payload))
        logging.debug("meta is " + str(meta))
        self.add_one_hop_to_all_metrics(One_Hop_Metric.from_payload_metric(payload))

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
                self.aggregated_metrics[isd_as].from_isd_as = str(isd_as)

                self.aggregated_metrics[isd_as].avg_one_way_delay = calculate_one_way_delay(measurements)
                self.aggregated_metrics[isd_as].packet_loss = calculate_packet_loss(measurements)
                self.aggregated_metrics[isd_as].packet_reordering = calculate_packet_reordering(measurements)
                variance = calculate_variance(measurements)
                self.aggregated_metrics[isd_as].variance = variance
                self.aggregated_metrics[isd_as].percentile999 = calculate_percentile999(measurements)
                self.aggregated_metrics[isd_as].mean_normalized = calculate_normalized_mean(measurements)

                # logging.debug("avg owd is %d" % self.aggregated_metrics[isd_as].avg_one_way_delay)
                # logging.debug("packet loss is %1.4f" % self.aggregated_metrics[isd_as].packet_loss)
                # logging.debug("packet reordering is %1.4f" % self.aggregated_metrics[isd_as].packet_reordering)
                # logging.debug("delay variation is %s" % str(self.aggregated_metrics[isd_as].one_way_delay_variation))
                self.send_metrics_to_beacon_server(isd_as)
                self.add_one_hop_to_all_metrics(self.aggregated_metrics[isd_as])
            time.sleep(RECALCULATE_METRICS_INTERVAL_SECONDS)

    def clean_measurement_stream(self):
        with self.measurement_stream_lock:
            timeout = get_timestamp_in_ms() - TIME_RANGE_TO_KEEP_MEASUREMENTS
            for isd_as in self.measurement_streams.keys():
                measurements = self.measurement_streams[isd_as]
                cleaned_measurements = list(
                    filter(lambda measurement: measurement.sent_at > timeout, measurements))
                cleaned_measurements = remove_duplicates(cleaned_measurements,
                                                         lambda measurement: measurement.sequence_number)
                self.measurement_streams[isd_as] = cleaned_measurements

    def send_metrics_to_beacon_server(self, metrics_for_isd_as):
        isd_as = self.topology.isd_as
        path = self._get_path_via_sciond(isd_as)
        while path is None:
            time.sleep(1)
            path = self._get_path_via_sciond(isd_as)
            logging.debug("waiting to get valid path")
        beacon_servers = self.topology.beacon_servers
        for bs in beacon_servers:
            address = bs.public
            meta = self._build_meta(isd_as, address[0][0], port=int(address[0][1]),
                                    path=path.fwd_path())
            metrics = self.aggregated_metrics[metrics_for_isd_as]
            self.send_meta(CtrlPayload(
                CtrlExtnDataList.from_values(
                    items=[CtrlExtnData.from_values(type=b'from_isd_as', data=str(metrics.from_isd_as).encode()),
                           CtrlExtnData.from_values(type=b'to_isd_as', data=str(metrics.to_isd_as).encode()),
                           CtrlExtnData.from_values(type=b'avg_owd',
                                                    data=str(metrics.avg_one_way_delay).encode()),
                           CtrlExtnData.from_values(type=b'pkt_reordering',
                                                    data=str(metrics.packet_reordering).encode()),
                           CtrlExtnData.from_values(type=b'mean_normalized',
                                                    data=str(metrics.mean_normalized).encode()),
                           CtrlExtnData.from_values(type=b'variance',
                                                    data=str(metrics.variance).encode()),
                           CtrlExtnData.from_values(type=b'percentile999',
                                                    data=str(metrics.percentile999).encode()),
                           CtrlExtnData.from_values(type=b'pkt_loss',
                                                    data=str(metrics.packet_loss).encode())])), meta)

    def add_one_hop_to_all_metrics(self, metric):
        self.all_aggregated_metrics[metric.from_isd_as + metric.to_isd_as] = metric


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
    def __init__(self, from_isd_as, to_isd_as):
        self.from_isd_as = from_isd_as
        self.to_isd_as = to_isd_as
        self.avg_one_way_delay = 0
        self.packet_loss = 0.0
        self.packet_reordering = 0.0
        self.mean_normalized = 0.0
        self.variance = 0.0
        self.percentile999 = 0.0

    @classmethod
    def from_payload_metric(cls, payload):
        raw = payload.union
        metrics = cls(raw.from_isd_as(), raw.to_isd_as())
        metrics.avg_one_way_delay = raw.avg_one_way_delay()
        metrics.packet_reordering = raw.packet_reordering()
        metrics.packet_loss = raw.packet_loss()
        metrics.percentile999 = raw.percentile999()
        metrics.mean_normalized = raw.mean_normalized()
        metrics.variance = raw.variance()
        return metrics

    def __str__(self):
        s = ["{from_isd_as: %s" % self.from_isd_as,
             "to_isd_as: %s" % self.to_isd_as,
             "avg_one_way_delay: %d" % self.avg_one_way_delay,
             "packet_loss: %1.4f" % self.packet_loss,
             "packet_reordering: %1.4f" % self.packet_reordering,
             "variance: %1.4f" % self.variance,
             "percentile999: %1.4f" % self.percentile999,
             "mean_normalized: %s" % str(self.mean_normalized), "}"]
        return "\n".join(s)
