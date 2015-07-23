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
import struct

from lib.packet.ext_hdr import ExtensionHeader

class DRKeyExt(ExtensionHeader):
    """
    0          8         16           32            48               64
    | next hdr | hdr len |  SessionID                                 |
    
                         | PubKey                                     |       
                                                                      |   
                                                                      |
                                                                      |  
                         | Time                                       |
    AuthTag
                                                                      |
    Auth
    
    
    
    
                                                                      |
    EncSharedKey1
                                                                      |
    SignedSharedKey1
    
    
    
    
    
    
                                                                      |
    EncSharedKey2
                                                                      |
    SignedSharedKey2
    
    
    
    
    
    
                                                                      |
    ...                                                        
    
    0          8         16         144    400     432       560    944      944 + 80*8*nrHops
    | next hdr | hdr len | SessionID | PKey | Time | Auth tag | Auth | hop info |
    
    :param next hdr:
    :type next hdr: unsigned char
    :param hdr len:
    :type hdr len: unsigned char
    :param SessionID:
    :type SessionID: 16 B
    :param PubKey: session public key
    :type PubKey: 32 B
    :cvar Time: current time
    :type Time: 4 B
    :cvar AuthTag:
    :type AuthTag: 16 B
    :cvar Auth: session authenticator
    :type Auth: 48 B
    --------------- 118 B = 944 bits => 944/16 = 59 header lines
    :param EncSharedKey_i
    :type EncSharedKey_i: 16 B
    :param SignedSharedKey_i
    :type SignedSharedKey_i: 64 B
    """

    TYPE = 33  # Extension header type
    MIN_LEN = 118
    HOP_OVERHEAD = 80 # 16 B shared key, 64 B signature
    
    
    def __init__(self, raw=None):
        """
        Initialize an instance of the class DRKeyExt
        
        :param raw:
        :type raw: 
        """
        
        super(ExtensionHeader, self).__init__(self)
        self.hopInfo=[]
        if raw is not None:
            super(ExtensionHeader, self).parse(raw)
            self.parse_payload()
        
    def parse_payload(self):
        """
        Parse the payload to extract the session setup information
        """
        payload = self.payload
        
        self.sessionID = struct.unpack("!16B", payload[:16])
        self.pubKey = struct.unpack("!32B", payload[16:48])
        self.time = struct.unpack("!i", payload[48:52])
        self.authTag = struct.unpack("!16B", payload[52:68])
        self.auth = struct.unpack("!48B", payload[68:118])
        
        payload = payload[118:]
        
        while payload:
            encKey = struct.unpack("!16B", payload[:16])
            signedKey = struct.unpack("!64B", payload[16:80])
            self.hopInfo.append((encKey, signedKey))
            payload = payload[80:]
    
    @classmethod
    def from_values(sessionID, pubKey, time, authTag, auth, nrHops):
        """
        Create an instance of the DRKeyExt class.

        :param sessionID: the DRKey session id
        :type sessionID: 16 B
        :param pubKey: the DRKey session public key
        :type pubKey: 32 B
        :param time: current time
        :type time: 4 B
        :param authTag: the authenticator tag for the session authenticator
        :type authTag: 16 B
        :param auth: session authenticator
        :type auth: 48 B

        :returns: DRKey extension.
        :rtype: :class:`DRKeyExt`
        """
        ext = DRKeyExt()
        ext.sessionID = sessionID
        ext.pubKey = pubKey
        ext.time = time
        ext.authTag = authTag
        ext.auth = auth
        ext.hopInfo = [b"\x00" * nrHops * DRKeyExt.HOP_OVERHEAD]
        return ext
           
    def change_hop_key(self, hopNr, encKey, sigKey):
        """
        Enables the DRKey extension handler to append the encrypted and signed key to the header
        
        hopNr considers the first router as hop number 0
        """
        
        self.hopInfo[hopNr] = (encKey, sigKey)
          
    def pack(self):
        """
        Pack the extension header to bytes
        """
        
        self.payload = self.payload[:118]

        for (encKey, sigKey) in self.hopInfo:
            tmp = struct.pack("!16B64B", encKey, sigKey)
            self.payload.join(tmp)

        return ExtensionHeader.pack(self)
    
    def __str__(self):
        
        ret_str = "[DRKey Ext - start]\n"
        ret_str += "  [next_hdr:%d, len:%d self.sessionID%d]\n" % (self.next_hdr, len(self), self.sessionID[:6])
        ret_str += "  [%d]\n" % (self.sessionID[6:14])
        ret_str += "  [%d PubKey:%d]\n" % (self.sessionID[14:16], self.pubKey[:6])
        ret_str += "  [%d]\n" % (self.pubKey[6:14])
        ret_str += "  [%d]\n" % (self.pubKey[14:22])
        ret_str += "  [%d]\n" % (self.pubKey[22:30])
        ret_str += "  [%d Time:%d]\n" % (self.pubKey[30:32], self.time)
        ret_str += "  [AuthTag:%d]\n" % (self.authTag[:8])
        ret_str += "  [%d]\n" % (self.authTag[8:16])
        ret_str += "  [AuthTag:%d]\n" % (self.auth[:8])
        ret_str += "  [%d]\n" % (self.auth[8:16])
        ret_str += "  [%d]\n" % (self.auth[16:24])
        ret_str += "  [%d]\n" % (self.auth[24:32])
        ret_str += "  [%d]\n" % (self.auth[32:40])
        ret_str += "  [%d]\n" % (self.auth[40:48])
        
        for (encKey, sigKey) in self.hopInfo:
            ret_str += "  [EncKey:%d]\n" % (encKey[:8])
            ret_str += "  [%d]\n" % (encKey[8:16])
            ret_str += "  [SigKey:%d]\n" % (sigKey[:8])
            ret_str += "  [%d]\n" % (sigKey[8:16])
            ret_str += "  [%d]\n" % (sigKey[16:24])
            ret_str += "  [%d]\n" % (sigKey[24:32])
            ret_str += "  [%d]\n" % (sigKey[32:40])
            ret_str += "  [%d]\n" % (sigKey[40:48])
            ret_str += "  [%d]\n" % (sigKey[48:56])
            ret_str += "  [%d]\n" % (sigKey[56:64])
            
        ret_str += "[DRKey Ext - end]"
        return ret_str     

  
            
        
        
        
        
        
        