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
:mod:`drkey` --- Handler to process the DRKey extension header.
===========================================
"""
# Stdlib
import logging
import struct

# SCION
from lib.packet.packet_base import HeaderBase

import lib.crypto.symcrypto import cbc_encrypt, get_roundkey_cache

def drkey_handler(spkt, next_hop):
	for ext in spkt.hdr.extension_hdrs():
		if isinstance(ext, DRKeyExtHdr):
			shared_key = cbc_encrypt(get_roundkey_cache('abababababababab'), ext.sid)