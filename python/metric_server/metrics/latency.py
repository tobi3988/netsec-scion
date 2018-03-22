import logging
from collections import defaultdict
from statistics import mean, pvariance

from metric_server.lib.lib import percentile

NORMALDIST999 = 3.09


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


def calculate_percentile999(measurements):
    if len(measurements) < 2:
        return 0
    latencies = normalize_and_sort_measurements(measurements)
    return percentile(latencies, 0.999)


def calculate_third_moment(metric):
    return calculate_skewness(metric) ** (1.5)


def calculate_total_skewness(variance, third_moment):
    return third_moment / float(variance ** (1.5))


def calculate_percentile999_for_path(metrics):
    mean = sum(metric.mean_normalized for metric in metrics)
    variance = sum(metric.variance for metric in metrics)
    third_moment = sum(calculate_third_moment(metric) for metric in metrics)
    skew = calculate_total_skewness(variance, third_moment)
    return mean + variance ** 0.5 * (NORMALDIST999 - (skew / 6.0) * (1 - NORMALDIST999 ** 2))


def calculate_skewness(metric):
    percentil = float(metric.percentil999)
    mean = float(metric.normalized_mean)
    return 6 * ((NORMALDIST999 - ((percentil - mean) / metric.variance)) / (1 - NORMALDIST999 ** 2))


def calculate_one_way_delay_for_path(metrics):
    return mean(metric.one_way_delay for metric in metrics)
