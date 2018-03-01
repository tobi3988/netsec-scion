import logging
from collections import defaultdict

from metric_server.lib.lib import percentile


def calculate_one_way_delay_variation(measurements):
    result = defaultdict(lambda: 0)
    if len(measurements) < 2:
        return result
    latencies = list(map(lambda measurement: measurement.one_way_delay, measurements))
    min_latency = min(latencies)
    latencies = list(map(lambda latency: latency - min_latency, latencies))  # normalize
    latencies.sort()
    for index in range(0, 10):
        percentage = index * 0.1
        result[index * 10] = percentile(latencies, percentage)
    return result


def calculate_one_way_delay(measurements):
    avg_one_way_delay = 0
    for measurement in measurements:
        measurement.avg_one_way_delay = measurement.received_at - measurement.sent_at
        avg_one_way_delay += measurement.avg_one_way_delay
    if measurements:
        return avg_one_way_delay / len(measurements)
    else:
        return -1
