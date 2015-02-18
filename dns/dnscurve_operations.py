"""
dnscurve_operations.py

Copyright 2014 ETH Zurich

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
import random
import time

def int_to_string(number, length):
    if number >= 256 ** length:
        raise ValueError('The number must be < 256^l')
    result_str = ''
    while len(result_str) < length:
        result_str += chr(number % 256)
        number /= 256
        number = int(number)
    return result_str

def generate_random_string(nb_char):
    """
    Random string generator.

    Generates a random string of nb_char size.
    """
    return ''.join([chr(random.randint(0, 255)) for i in range(nb_char)])

def dnscurve_generate_nonce(time_bytes = 8, rand_nb_bytes = 4):
    """
    Generates a random nonce as specified by DJB.

    Details and motivations in [Cryptography in NaCl].
    The nonce is generated using the time function (since Epoch)
    in seconds and a random generated number.
    """
    current_time = str(int(time.time()))
    current_time_bytes = int_to_string(int(current_time), \
                                time_bytes).encode('utf-8')
    random_string = generate_random_string(rand_nb_bytes)
    random_string_bytes = random_string.encode('utf-8')
    generated_nonce = current_time_bytes[-time_bytes:] \
                    + random_string_bytes[:rand_nb_bytes]

    return generated_nonce

def dnscurve_encode_streamlined(nonce, crypto_box, sender_pk):
    """
    Expands the query with the streamlined format.
    """
    if len(nonce)!= 24:
        raise ValueError('Invalid Nonce')
    #The last byte of the key is always between 0 and 127.
    if len(sender_pk) != 32 or sender_pk[-1] > 127:
        raise ValueError('Invalid public key')
    streamlined_packet = 'Q6fnvWj8'.encode('utf-8') + sender_pk \
                                       + nonce[:12] + crypto_box
    return streamlined_packet

def dnscurve_decode_streamlined(received_packet):
    """
    Decodes the streamlined format.
    """
    if len(received_packet) < 52 or      \
        received_packet[:8] != b'Q6fnvWj8':
        raise ValueError("This is not a valid streamlined query.")
    return (received_packet[8:40], received_packet[40:52], received_packet[52:])    