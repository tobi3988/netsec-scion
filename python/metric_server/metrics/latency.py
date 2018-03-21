import logging
from collections import defaultdict
from statistics import mean, pvariance

from metric_server.lib.lib import percentile


def calculate_one_way_delay_variation(measurements):
    result = defaultdict(lambda: 0)
    if len(measurements) < 2:
        return result
    latencies = normalize_and_sort_measurements(measurements)
    for index in range(0, 10):
        percentage = index * 0.1
        result[index * 10] = percentile(latencies, percentage)
    return result


def normalize_and_sort_measurements(measurements):
    latencies = list(map(lambda measurement: measurement.one_way_delay, measurements))
    min_latency = min(latencies)
    latencies = list(map(lambda latency: latency - min_latency, latencies))  # normalize
    latencies.sort()
    return latencies


def calculate_one_way_delay(measurements):
    avg_one_way_delay = 0
    for measurement in measurements:
        measurement.avg_one_way_delay = measurement.received_at - measurement.sent_at
        avg_one_way_delay += measurement.avg_one_way_delay
    if measurements:
        return avg_one_way_delay / len(measurements)
    else:
        return avg_one_way_delay


def calculate_normalized_mean(measurements):
    if len(measurements) < 2:
        return 0
    latencies = normalize_and_sort_measurements(measurements)
    return mean(latencies)


def calculate_variance(measurements):
    if len(measurements) < 2:
        return 0
    latencies = normalize_and_sort_measurements(measurements)
    return pvariance(latencies)


def calculate_skew(mean, variance):
    # TODO implement it.
    return (6)


def calculate_percentile999(measurements):
    if len(measurements) < 2:
        return 0
    latencies = normalize_and_sort_measurements(measurements)
    return percentile(latencies, 0.999)
