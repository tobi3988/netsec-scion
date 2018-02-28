from metric_server.constants import PACKETLOSS_TIMEOUT
from metric_server.lib.lib import get_timestamp_in_ms


def calculate_packet_loss(measurements):
    lost_packets = 0
    now = get_timestamp_in_ms()
    measurements = list(
        filter(lambda measurement: measurement.sent_at < now - PACKETLOSS_TIMEOUT, measurements))
    number_of_packets = len(measurements)
    if number_of_packets == 0:
        return 0.0
    measurements.sort(key=lambda measurement: measurement.sequence_number)
    previous_packet = measurements[0]
    for index, measurement in enumerate(measurements):
        if measurement.received_at - measurement.sent_at > PACKETLOSS_TIMEOUT:
            lost_packets += 1.0
        if index != 0:
            number_of_missing_packets = (measurement.sequence_number - previous_packet.sequence_number) - 1
            lost_packets += number_of_missing_packets
            number_of_packets += number_of_missing_packets
        previous_packet = measurement
    return float(lost_packets) / float(number_of_packets)
