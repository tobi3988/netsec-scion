# External packages
import logging

import capnp  # noqa

import proto.metrics_capnp as P
from lib.packet.packet_base import Cerealizable


class MetricsPCBExt(Cerealizable):
    NAME = "Metrics"
    P_CLS = P.MetricsPCBExt

    @classmethod
    def from_values(cls):
        logging.debug("create metric PCB extension")
        p = cls.P_CLS.new_message(payload=b'metrics payload')
        return cls(p)
