# External packages
import logging

import capnp  # noqa

import proto.metrics_capnp as P
from lib.packet.packet_base import Cerealizable


class MetricsPCBExt(Cerealizable):
    NAME = "Metrics"
    P_CLS = P.MetricsPCBExt

    @classmethod
    def from_values(cls, metrics):
        p = cls.P_CLS.new_message(fromIsdAs=metrics.from_isd_as, toIsdAs=metrics.to_isd_as,
                                  avgOwd=metrics.avg_one_way_delay, pktReordering=metrics.packet_reordering,
                                  variance=metrics.variance, pktLoss=metrics.packet_loss,
                                  percentile999=metrics.percentile999, meanNormalized=metrics.mean_normalized)
        return cls(p)

    def from_isd_as(self):
        return self.p.fromIsdAs

    def to_isd_as(self):
        return self.p.toIsdAs

    def avg_one_way_delay(self):
        return self.p.avgOwd

    def packet_reordering(self):
        return self.p.pktReordering

    def variance(self):
        return self.p.variance

    def mean_normalized(self):
        return self.p.meanNormalized

    def percentile999(self):
        return self.p.percentile999

    def packet_loss(self):
        return self.p.pktLoss
