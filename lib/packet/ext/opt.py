# Copyright 2015 ETH Zurich
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

#stdlib
import base64
import struct

from lib.packet.ext_hdr import ExtensionHeader

from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from lib.crypto.symcrypto import get_cbcmac, get_roundkey_cache

class OPTExt(ExtensionHeader):
    """
    The OPT protocol for source and path validation
    
    0          8         16            32         40         56       64
    | next hdr | hdr len |  reserved   | DataHash (16 B = 2 lines) ..
                                       | SessionID  (16 B = 2 lines) ...
                                       | Time (4 B)                   |
              PVF (16 B = 2 lines) ...    
    
    :param next hdr:
    :type next hdr: unsigned char
    :param hdr len:
    :type hdr len: unsigned char
    :param reserved: reserved bytes
    :type reserved: 2 B
    :param dataHash:
    :type dataHash: 16 B
    :param SessionID:
    :type SessionID: 16 B
    :cvar Time: current time
    :type Time: 4 B
    :cvar PVF: path validation field
    :type PVF: 16 B
    
    """

    TYPE = 3  # Extension header type
    MIN_LEN = 56
    
    def __init__(self, raw=None):
        """
        Initialize an instance of the class OPTExt
        
        :param raw:
        :type raw: 
        """
        
        ExtensionHeader.__init__(self)
        if raw is not None:
            self.parse(raw)
            self.parse_payload()
        
    def parse_payload(self):
        """
        Parse the payload to extract the session setup information
        """
        payload = self.payload
        
        self.reserved = bytes(struct.unpack("!2s", payload[:2])[0])
        self.dataHash = bytes(struct.unpack("!16s", payload[2:18])[0])
        self.sessionID = bytes(struct.unpack("!16s", payload[18:34])[0])
        self.time = struct.unpack("!i", payload[34:38])[0]
        self.pvf = bytes(struct.unpack("!16s", payload[38:54])[0])
    
    @staticmethod
    def from_values(dataHash, sessionID, time, pvf):
        """
        Create an instance of the OPTExt class.

         :type dataHash: 16 B
        :param SessionID:
        :type SessionID: 16 B
        :cvar Time: current time
        :type Time: 4 B
        :cvar PVF: path validation field
        :type PVF: 16 B

        :returns: OPT extension.
        :rtype: :class:`OPTExt`
        """
        ext = OPTExt()
        ext.set_payload(b'a'*56)
        ext.reserved = b'\x00' * 2
        ext.dataHash = dataHash
        ext.sessionID = sessionID
        ext.time = time
        ext.pvf = pvf
       
        return ext
           
    def pack(self):
        """
        Pack the extension header to bytes
        """
        packing = []
        packing.append(struct.pack("!2s", self.reserved))
        packing.append(struct.pack("!16s", self.dataHash))
        packing.append(struct.pack("!16s", self.sessionID))
        packing.append(struct.pack("!i", self.time))
        packing.append(struct.pack("!16s", self.pvf))
       
        self.payload = b"".join(packing)
        ExtensionHeader.set_payload(self, self.payload)

        return ExtensionHeader.pack(self)
    
    def __str__(self):
        
        ret_str = "[OPT Ext - start]\n"
        
        ret_str += "  [next_hdr: %d, len: %d reserved: " % (self.next_hdr, len(self)) + str(self.reserved) +"]\n"
        ret_str += "  [DataHash: " + str(self.dataHash[:8]) + "]...\n"
        ret_str += "  [SessionID: " + str(self.sessionID[:8]) + "]...\n"
        ret_str += "  [Time: %d]" % (self.time) + "\n"
        ret_str += "  [PVF: " + str(self.pvf[:8]) + "]...\n"

        ret_str += "[OPT Ext - end]"
        return ret_str
           
    def update_pvf(self, pvf):
        """
        Updates the PVF value according to the hop transited by the packet
        """
        self.pvf = pvf


def opt_handler(**kwargs):
    """
    The handler for the DRKey extension
    """
    ext = kwargs['ext']
    conf = kwargs['conf']
    topo = kwargs['topo']
    pkt = kwargs['spkt']
    logging = kwargs['logging']
    
    logging.info(str(topo.ad_id)+' received: %s', pkt)
    
    # Derive the PRF key from the AS master key
    nodeSecret = b"\x00" * 16
    cipher = AES.new(conf.master_ad_key, AES.MODE_CBC, nodeSecret)
    prfKey = cipher.encrypt(conf.master_ad_key)
    # Generate the key to be shared with the source
    cipher = AES.new(prfKey, AES.MODE_CBC, nodeSecret)
    sharedKey = cipher.encrypt(ext.sessionID)
    
    # Update the PVF
    PVFInput = bytearray()
    PVFInput.extend(ext.dataHash)
    PVFInput.extend(ext.pvf)
    expandedSharedkey = get_roundkey_cache(sharedKey)
    newPVF = get_cbcmac(expandedSharedkey, PVFInput)
    # todo: validate hash?
    
    ext.update_pvf(newPVF)
   
    logging.info("pvf after node %d: %s", topo.ad_id, str(newPVF))

            
        
        
        
        
        
        