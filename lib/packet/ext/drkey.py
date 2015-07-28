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
from lib.packet.ext_hdr import ExtensionHeader
from lib.util import get_sig_key_file_path, read_file

from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

class DRKeyExt(ExtensionHeader):
    """
    DRKey header containing the source-generated values. The keys
    generated at each hop are in the DRKeyExtCont header. A packet that
    contains a DRKeyExt MUST contain at least one DRKeyExtCont header.
    
    0          8         16           32     40      48       56      64
    | next hdr | hdr len |  reserved         | maxHops| crtHop |
    SessionID  (16 B = 2 lines) ...                           |
    PubKey (294 B = 36 lines, 6 B) ...                           
                                              | Time (4 B)  
               | AuthTag (16 B = 2 lines) ... 
               | Auth (1207 B = 150 lines, 7 B)  ...                  |           
    
    :param next hdr:
    :type next hdr: unsigned char
    :param hdr len:
    :type hdr len: unsigned char
    :param reserved: reserved bytes
    :type reserved: 3 B
    :param maxHops: nr of hops to process the extension
    :type maxHops: unsigned char
    :param crtHop: the nr of the current hop
    :type crtHop: unsigned char
    :param SessionID:
    :type SessionID: 16 B
    :param PubKey: session public key
    :type PubKey: 294 B
    :cvar Time: current time
    :type Time: 4 B
    :cvar AuthTag:
    :type AuthTag: 16 B
    :cvar Auth: session authenticator
    :type Auth: 1207 B
    --------------- 1544 B = 193 header lines
    """

    TYPE = 33  # Extension header type
    MIN_LEN = 1544
    HOP_OVERHEAD_ENC = 256 # 256 B encrypted shared key
    HOP_OVERHEAD_SIG = 64 # 64 B signature of encrypted shared key
    HOP_OVERHEAD = HOP_OVERHEAD_ENC + HOP_OVERHEAD_SIG
    
    
    def __init__(self, raw=None):
        """
        Initialize an instance of the class DRKeyExt
        
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
        
        self.reserved = struct.unpack("!3s", payload[:3])[0]
        self.maxHops = struct.unpack("!B", payload[3:4])[0]
        self.crtHop = struct.unpack("!B", payload[4:5])[0]
        self.sessionID = struct.unpack("!16s", payload[5:21])[0]
        self.pubKey = struct.unpack("!294s", payload[21:315])[0]
        self.time = struct.unpack("!i", payload[315:319])[0]
        self.authTag = struct.unpack("!16s", payload[319:335])[0]
        self.auth = struct.unpack("!1207s", payload[335:1542])[0]
    
    @staticmethod
    def from_values(sessionID, pubKey, time, authTag, auth, maxHops):
        """
        Create an instance of the DRKeyExt class.

        :param sessionID: the DRKey session id
        :type sessionID: 16 B
        :param pubKey: the DRKey session public key
        :type pubKey: 294 B
        :param time: current time
        :type time: 4 B
        :param authTag: the authenticator tag for the session authenticator
        :type authTag: 16 B
        :param auth: session authenticator
        :type auth: 1207 B
        :param maxHops: nr of hops to process the extension
        :type maxHops: unsigned char

        :returns: DRKey extension.
        :rtype: :class:`DRKeyExt`
        """
        ext = DRKeyExt()
        ext.set_payload(b'a'*1542)
        ext.reserved = b"\x00" * 4
        ext.crtHop = -1
        ext.sessionID = sessionID
        ext.pubKey = pubKey
        ext.time = time
        ext.authTag = authTag
        ext.auth = auth
        ext.maxHops = maxHops
        return ext
           
    def pack(self):
        """
        Pack the extension header to bytes
        """
        self.crtHop += 1
        
        packing = []
        packing.append(struct.pack("!3s", self.reserved))
        packing.append(struct.pack("!B", self.maxHops))
        packing.append(struct.pack("!B", self.crtHop))
        packing.append(struct.pack("!16s", self.sessionID))
        packing.append(struct.pack("!294s", self.pubKey))
        packing.append(struct.pack("!i", self.time))
        packing.append(struct.pack("!16s", self.authTag))
        packing.append(struct.pack("!1207s", self.auth))
        
        self.payload = b"".join(packing)
        ExtensionHeader.set_payload(self, self.payload)

        return ExtensionHeader.pack(self)
    
    def __str__(self):
        
        ret_str = "[DRKey Ext - start]\n"
        
        ret_str += "  [next_hdr: %d, len: %d reserved: " % (self.next_hdr, len(self)) + str(self.reserved) +"]\n"
        ret_str += "  [maxHops: %d" % self.maxHops +"]\n"
        ret_str += "  [crtHop: %d" % self.crtHop +"]\n"
        ret_str += "  [SessionID: " + str(self.sessionID[:8]) + "]...\n"
        ret_str += "  [PubKey: " + str(self.pubKey[:8]) +"]...\n"
        ret_str += "  [Time: %d]" % (self.time) + "\n"
        ret_str += "  [AuthTag: " + str(self.authTag[:8]) + "]...\n"
        ret_str += "  [Auth: " + str(self.auth[:8]) + "]...\n"

        ret_str += "[DRKey Ext - end]"
        return ret_str
    
class DRKeyExtCont(ExtensionHeader):
    """
    DRKey header containing the keys generated at each hop. It can The
    source-generated values are in the DRKeyExt header. A packet that
    contains a DRKeyExt MUST contain at least one DRKeyExtCont header.
    This extension DOES NOT have its own handler, instead it is used
    by the drkey_handler to store the shared keys.
    
    0          8         16           32     40      48       56      64
    | next hdr | hdr len |  reserved                                  |     
    EncSharedKey1 (256 B = 32 lines) ..                               |  
    SignedSharedKey1 (64 B = 8 lines) ..                              |
    EncSharedKey2 (256 B = 32 lines) ..                               |  
    SignedSharedKey2 (64 B = 8 lines) ..                              |
    ...
    
    :param next hdr:
    :type next hdr: unsigned char
    :param hdr len:
    :type hdr len: unsigned char
    :param reserved: reserved bytes
    :type reserved: 6 B
    :param EncSharedKey_i
    :type EncSharedKey_i: 256 B
    :param SignedSharedKey_i
    :type SignedSharedKey_i: 64 B
    """

    TYPE = 133  # Extension header type
    MIN_LEN = 328 # One hop and preamble
    MAX_HOPS = 6 # Maximum number of hops on which the extension can store information
    HOP_OVERHEAD_ENC = 256 # 256 B encrypted shared key
    HOP_OVERHEAD_SIG = 64 # 64 B signature of encrypted shared key
    HOP_OVERHEAD = HOP_OVERHEAD_ENC + HOP_OVERHEAD_SIG
    
    
    def __init__(self, raw=None):
        """
        Initialize an instance of the class DRKeyExtCont
        
        :param raw:
        :type raw: 
        """
        
        ExtensionHeader.__init__(self)
        self.hopInfo=[]
        if raw is not None:
            self.parse(raw)
            self.parse_payload()
        
    def parse_payload(self):
        """
        Parse the payload to extract the session setup information
        """
        payload = self.payload
        
        self.reserved = struct.unpack("!6s", payload[:6])[0]
        payload = payload[6:]
        
        while payload:
            encKey = struct.unpack("!256s", payload[:256])[0]
            signedKey = struct.unpack("!64s", payload[256:320])[0]
            self.hopInfo.append((encKey, signedKey))
            payload = payload[320:]
    
    @staticmethod
    def from_values(nrHops):
        """
        Create an instance of the DRKeyExtCont class.

        :param nrHops: the number of hops
        :type nrHops: int

        :returns: DRKeyCont extension.
        :rtype: :class:`DRKeyExtCont`
        """
        ext = DRKeyExtCont()
        ext.set_payload(b'a'*(nrHops*ext.HOP_OVERHEAD+6))
        ext.reserved = b"\x00" * 6
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
        packing.append(struct.pack("!6s", self.reserved))
       
        for (encKey, sigKey) in self.hopInfo:
            tmp = struct.pack("!256s64s", encKey, sigKey)
            packing.append(tmp)
        
        self.payload = b"".join(packing)
        ExtensionHeader.set_payload(self, self.payload)
        
        return ExtensionHeader.pack(self)
    
    def __str__(self):
        
        ret_str = "[DRKey Ext CONT - start]\n"
        ret_str += "  [next_hdr: %d, len: %d reserved: " % (self.next_hdr, len(self)) + str(self.reserved) +"]\n"
        
        for (encKey, sigKey) in self.hopInfo:
            ret_str += "  [EncKey: " + str(encKey[:8]) + "]...\n"
            ret_str += "  [SigKey: " + str(sigKey[:8]) + "]...\n"
            
        ret_str += "[DRKey Ext CONT - end]"
        return ret_str    

class DRKeyExtResp(ExtensionHeader):
    """
    DRKey response header containing the keys generated at each hop,
    authenticated and encrypted by D. 
    
    0          8         16           32     40      48       56      64
    | next hdr | hdr len |  reserved                                  |     
    | nrHops   s| Auth (at least 1223 B = 153 lines) ..                |  
    AuthTag (16 B = 2 lines) ..                                       |
    
    :param next hdr:
    :type next hdr: unsigned char
    :param hdr len:
    :type hdr len: unsigned char
    :param reserved: reserved bytes
    :type reserved: 6 B
    :param nrHops:
    :type nrHops: unsigned char
    :param Auth:
    :type Auth: 1223 B + nrHops * 16 B
    :param AuthTag:
    :type AuthTag: 16 B
    """

    TYPE = 34  # Extension header type
    MIN_LEN = 1248
    HOP_OVERHEAD = 16
    
    def __init__(self, raw=None):
        """
        Initialize an instance of the class DRKeyExtCont
        
        :param raw:
        :type raw: 
        """
        
        ExtensionHeader.__init__(self)
        self.nrHops = 0
        if raw is not None:
            self.parse(raw)
            self.parse_payload()
        
    def parse_payload(self):
        """
        Parse the payload to extract the session setup information
        """
        payload = self.payload
        
        self.reserved = struct.unpack("!6s", payload[:6])[0]
        self.nrHops = struct.unpack("!B", payload[6:7])[0]
        authLen = 1223 + self.nrHops *  self.HOP_OVERHEAD
        self.auth = struct.unpack("!" + str(authLen) + "s", payload[7:authLen+7])[0]
        self.authTag = struct.unpack("!16s", payload[authLen+7:authLen+23])[0]
    
    @staticmethod
    def from_values(nrHops, auth, authTag):
        """
        Create an instance of the DRKeyExtResp class.

        :param nrHops: the number of hops
        :type nrHops: int

        :returns: DRKeyResp extension.
        :rtype: :class:`DRKeyExtResp`
        """
        ext = DRKeyExtResp()
        ext.set_payload(b'a'*(7 + 1223 + nrHops * ext.HOP_OVERHEAD + 16))
        ext.reserved = b"\x00" * 6
        ext.nrHops = nrHops
        ext.auth = auth
        ext.authTag = authTag
        return ext
          
    def pack(self):
        """
        Pack the extension header to bytes
        """
        packing = []
        authLen = 1223 + self.nrHops * self.HOP_OVERHEAD
        packing.append(struct.pack("!6s", self.reserved))
        packing.append(struct.pack("!B", self.nrHops))
        packing.append(struct.pack("!" + str(authLen) + "s", self.auth))
        packing.append(struct.pack("!16s", self.authTag))
        self.payload = b"".join(packing)
        ExtensionHeader.set_payload(self, self.payload)
        
        return ExtensionHeader.pack(self)
    
    def __str__(self):
        
        ret_str = "[DRKey Ext Response - start]\n"
        ret_str += "  [next_hdr: %d, len: %d reserved: " % (self.next_hdr, len(self)) + str(self.reserved) +"]\n"
        ret_str += "  [NrHops: %d" % (self.nrHops) + "]...\n"
        ret_str += "  [Auth: " + str(self.auth[:8]) + "]...\n"
        ret_str += "  [AuthTag: " + str(self.authTag[:8]) + "]...\n"
            
        ret_str += "[DRKey Ext Response - end]"
        return ret_str

def drkey_handler(**kwargs):
    """
    The handler for the DRKey extension
    """
    ext = kwargs['ext']
    conf = kwargs['conf']
    topo = kwargs['topo']
    pkt = kwargs['spkt']
    
    print(str(topo.ad_id)+' received: %s', pkt)
    
    if ext.crtHop >= ext.maxHops:
        return
    
    # Derive the PRF key from the AS master key
    nodeSecret = b"\x00" * 16
    cipher = AES.new(conf.master_ad_key, AES.MODE_CBC, nodeSecret)
    prfKey = cipher.encrypt(conf.master_ad_key)
    # Generate the key to be shared with the source
    cipher = AES.new(prfKey, AES.MODE_CBC, nodeSecret)
    sharedKey = cipher.encrypt(ext.sessionID)
    print("shared key at node ")
    print(topo.ad_id)
    print(sharedKey)
    # Encrypt the key with the public key of the session
    pubkey = RSA.importKey(ext.pubKey)
    cipher = PKCS1_OAEP.new(pubkey)
    encSharedKey = cipher.encrypt(sharedKey)
    print("len enc " + str(len(encSharedKey)))
    # Sign using ed25519 the shared key and the session id
    sigKeyFile = get_sig_key_file_path(topo.isd_id, topo.ad_id)
    signingKey = read_file(sigKeyFile)
    signingKey = base64.b64decode(signingKey)
    sigInput = bytearray(sharedKey)
    sigInput.extend(ext.sessionID)
    sigInput = bytes(sigInput) 
    sigSharedKey = sign(sigInput, signingKey)
    # Insert the encryped key and the signature in the packet
    ## Determine the index of the DRKeyExtCont header to update
    print("crtHop")
    print(ext.crtHop)
    extIndex = int(ext.crtHop / DRKeyExtCont.MAX_HOPS)
    extOffset = ext.crtHop % DRKeyExtCont.MAX_HOPS
    ## Extract the DRKeyExtCont from the packet
    idx = -1
    for crtExt in pkt.hdr.extension_hdrs:
        if crtExt.TYPE == DRKeyExtCont.TYPE:
            idx += 1
        if idx == extIndex:
            break
    crtExt.change_hop_key(extOffset, encSharedKey, sigSharedKey)

def drkeycont_handler(**kwargs):
    pass

def drkeyresp_handler(**kwargs):
    pass
  
            
        
        
        
        
        
        