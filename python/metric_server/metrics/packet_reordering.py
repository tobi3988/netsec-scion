
def calculate_packet_reordering(measurements):
    if len(measurements) < 2:
        return 0.0
    next_expected_sequence_number = 0
    number_of_reordered_packets = 0
    for index, measurement in enumerate(measurements):
        if index != 0:
            if next_expected_sequence_number > measurement.sequence_number:
                number_of_reordered_packets += 1
                continue
            next_expected_sequence_number = measurement.sequence_number + 1
    return float(number_of_reordered_packets) / float(len(measurements))
