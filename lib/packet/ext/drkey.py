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

from lib.crypto.asymcrypto import sign
from lib.crypto.symcrypto import get_roundkey_cache
from lib.packet.ext_hdr import ExtensionHeader
from lib.util import get_sig_key_file_path, read_file

from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA384
from Crypto.PublicKey import RSA

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
    HOP_OVERHEAD_ENC = 16 # 16 B encrypted shared key
    HOP_OVERHEAD_SIG = 64 # 64 B signature of encrypted shared key
    HOP_OVERHEAD = HOP_OVERHEAD_ENC + HOP_OVERHEAD_SIG
    
    
    def __init__(self, raw=None):
        """
        Initialize an instance of the class DRKeyExt
        
        :param raw:
        :type raw: 
        """
        
        ExtensionHeader.__init__(self)
        self.hopInfo=[]
        if raw is not None:
            self.parse(raw)
            print("payload is ")
            print(self.payload)
            self.parse_payload()
        
    def parse_payload(self):
        """
        Parse the payload to extract the session setup information
        """
        payload = self.payload
        
        print(payload[:16])
        
        self.sessionID = struct.unpack("!16s", payload[:16])
        self.pubKey = struct.unpack("!32s", payload[16:48])
        self.time = struct.unpack("!i", payload[48:52])
        self.authTag = struct.unpack("!16s", payload[52:68])
        self.auth = struct.unpack("!48s", payload[68:118])
        
        payload = payload[118:]
        
        while payload:
            encKey = struct.unpack("!16s", payload[:16])
            signedKey = struct.unpack("!64s", payload[16:80])
            self.hopInfo.append((encKey, signedKey))
            payload = payload[80:]
    
    @staticmethod
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
        for _ in range(0,nrHops):
            ext.hopInfo.append((b"\x00" * ext.HOP_OVERHEAD_ENC, b"\x00" * ext.HOP_OVERHEAD_SIG))
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
        packing = []
        packing.append(struct.pack("!16s", self.sessionID))
        packing.append(struct.pack("!32s", self.pubKey))
        packing.append(struct.pack("!i", self.time))
        packing.append(struct.pack("!16s", self.authTag))
        packing.append(struct.pack("!48s", self.auth))

        for (encKey, sigKey) in self.hopInfo:
            tmp = struct.pack("!16s64s", encKey, sigKey)
            packing.append(tmp)
        print(packing)
        self.payload = b"".join(packing)

        return ExtensionHeader.pack(self)
    
    def __str__(self):
        
        ret_str = "[DRKey Ext - start]\n"
        ret_str += "  [next_hdr:%d, len:%d self.sessionID:" % (self.next_hdr, len(self)) + str(self.sessionID[:6]) +"]\n"
        ret_str += "  [" + str(self.sessionID[6:14]) +"]\n"
        ret_str += "  [" + str(self.sessionID[14:16]) +" PubKey:" + str(self.pubKey[:6]) +"]\n"
        ret_str += "  [" + str(self.pubKey[6:14]) +"]\n"
        ret_str += "  [" + str(self.pubKey[14:22]) + "]\n"
        ret_str += "  [" + str(self.pubKey[22:30]) + "]\n"
        ret_str += "  [" + str(self.pubKey[30:32]) + " Time:%d]\n" % (self.time)
        ret_str += "  [AuthTag:" + str(self.authTag[:8]) + "]\n"
        ret_str += "  [" + str(self.authTag[8:16]) + "]\n"
        ret_str += "  [Auth:" + str(self.auth[:8]) + "]\n"
        ret_str += "  [" + str(self.auth[8:16]) + "]\n"
        ret_str += "  [" + str(self.auth[16:24]) + "]\n"
        ret_str += "  [" + str(self.auth[24:32]) + "]\n"
        ret_str += "  [" + str(self.auth[32:40]) + "]\n"
        ret_str += "  [" + str(self.auth[40:48]) + "]\n"
        
        print(self.hopInfo)
        for (encKey, sigKey) in self.hopInfo:
            ret_str += "  [EncKey:" + str(encKey[:8]) + "]\n"
            ret_str += "  [" + str(encKey[8:16]) + "]\n"
            ret_str += "  [SigKey:" + str(sigKey[:8]) + "]\n"
            ret_str += "  [" + str(sigKey[8:16]) + "]\n"
            ret_str += "  [" + str(sigKey[16:24]) + "]\n"
            ret_str += "  [" + str(sigKey[24:32]) + "]\n"
            ret_str += "  [" + str(sigKey[32:40]) + "]\n"
            ret_str += "  [" + str(sigKey[40:48]) + "]\n"
            ret_str += "  [" + str(sigKey[48:56]) + "]\n"
            ret_str += "  [" + str(sigKey[56:64]) + "]\n"
            
        ret_str += "[DRKey Ext - end]"
        return ret_str
    
def drkey_handler(**kwargs):
    """
    The handler for the DRKey extension
    """
    ext = kwargs['ext']
    conf = kwargs['conf']
    topo = kwargs['topo']
    
    # Derive the PRF key from the AS master key
    prfKey = AES.new(conf.master_ad_key, AES.MODE_CBC)
    print("len prfKey" + str(len(prfKey)))
    # Generate the key to be shared with the source
    cipher = AES.new(prfKey, AES.MODE_CBC)
    sharedKey = cipher.encrypt(ext.sessionID)
    print("len shared key " + str(len(sharedKey)))
    # Encrypt the key with the public key of the session
    pubkey = RSA.importKey(ext.pubKey)
    cipher = PKCS1_OAEP.new(pubkey)
    encSharedKey = cipher.encrypt(sharedKey, SHA384)
    print("len enc " + str(len(encSharedKey)))
    # Sign using ed25519 the encrypted shared key
    sigKeyFile = get_sig_key_file_path(topo.isd_id, topo.ad_id)
    signingKey = read_file(sigKeyFile)
    signingKey = base64.b64decode(signingKey)
    sign(encSharedKey, signingKey)
  
            
        
        
        
        
        
        