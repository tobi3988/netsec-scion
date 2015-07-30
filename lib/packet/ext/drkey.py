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
    
    0          8         16         24         40        48      56      64
    | next hdr | hdr len |reserved  |privkeySize| crtHop |
    SessionID  (16 B = 2 lines) ...                      |
    PubKey (294 B = 36 lines, 6 B) ...                           
                                          | Time (4 B)                   |
    Auth (1232 B = 154 lines) ...                                        |       
    
    :param next hdr:
    :type next hdr: unsigned char
    :param hdr len:
    :type hdr len: unsigned char
    :param reserved: reserved bytes
    :type reserved: 1 B
    :param privKeySize: the size of the session private key
    :type privKeySize: unsigned short
    :param crtHop: the nr of the current hop
    :type crtHop: unsigned char
    :param SessionID:
    :type SessionID: 16 B
    :param PubKey: session public key
    :type PubKey: 294 B
    :cvar Time: current time
    :type Time: 4 B
    :cvar Auth: session authenticator
    :type Auth: 1232 B = 16 B sessionID + 16 B tag + priv key (1188 to 1194 B) + at least 6 B padding
    --------------- 1552 B = 194 header lines
    """

    TYPE = 33  # Extension header type
    MIN_LEN = 1552
    
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
        
        self.reserved = struct.unpack("!B", payload[:1])[0]
        self.privKeySize = struct.unpack("!H", payload[1:3])[0]
        self.crtHop = struct.unpack("!B", payload[3:4])[0]
        self.sessionID = bytes(struct.unpack("!16s", payload[4:20])[0])
        self.pubKey = bytes(struct.unpack("!294s", payload[20:314])[0])
        self.time = struct.unpack("!i", payload[314:318])[0]
        self.auth = bytes(struct.unpack("!1232s", payload[318:1550])[0])
        # remove the padding from auth
        lenAuth = 16 + 16 + self.privKeySize
        self.auth = self.auth[0:lenAuth]
    
    @staticmethod
    def from_values(sessionID, pubKey, time, auth, privKeySize):
        """
        Create an instance of the DRKeyExt class.

        :param sessionID: the DRKey session id
        :type sessionID: 16 B
        :param pubKey: the DRKey session public key
        :type pubKey: 294 B
        :param time: current time
        :type time: 4 B
        :param auth: session authenticator
        :type auth: at most 1232 B (can be smaller)
        :param privKeySize: the size of the session private key
        :type privKeySize: unsigned short

        :returns: DRKey extension.
        :rtype: :class:`DRKeyExt`
        """
        ext = DRKeyExt()
        ext.set_payload(b'a'*1550)
        ext.reserved = 0
        ext.privKeySize = privKeySize
        ext.crtHop = -1
        ext.sessionID = sessionID
        ext.pubKey = pubKey
        ext.time = time
        ext.auth = auth
       
        return ext
           
    def pack(self):
        """
        Pack the extension header to bytes
        """
        self.crtHop += 1
        
        packing = []
        packing.append(struct.pack("!B", self.reserved))
        packing.append(struct.pack("!H", self.privKeySize))
        packing.append(struct.pack("!B", self.crtHop))
        packing.append(struct.pack("!16s", self.sessionID))
        packing.append(struct.pack("!294s", self.pubKey))
        packing.append(struct.pack("!i", self.time))
        # pad auth to 1232 bytes
        authPadLen = 1232 - 16 - 16 - self.privKeySize
        aux = bytearray(self.auth)
        aux.extend(b"\x00" * authPadLen)
        self.auth = bytes(aux)
        packing.append(struct.pack("!1232s", self.auth))
        
        self.payload = b"".join(packing)
        ExtensionHeader.set_payload(self, self.payload)

        return ExtensionHeader.pack(self)
    
    def __str__(self):
        
        ret_str = "[DRKey Ext - start]\n"
        
        ret_str += "  [next_hdr: %d, len: %d reserved: " % (self.next_hdr, len(self)) + str(self.reserved) +"]\n"
        ret_str += "  [privKeySize: %d" % self.privKeySize +"]\n"
        ret_str += "  [crtHop: %d" % self.crtHop +"]\n"
        ret_str += "  [SessionID: " + str(self.sessionID[:8]) + "]...\n"
        ret_str += "  [PubKey: " + str(self.pubKey[:8]) +"]...\n"
        ret_str += "  [Time: %d]" % (self.time) + "\n"
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
        
        self.reserved = bytes(struct.unpack("!6s", payload[:6])[0])
        payload = payload[6:]
        
        while payload:
            encKey = bytes(struct.unpack("!256s", payload[:256])[0])
            signedKey = bytes(struct.unpack("!64s", payload[256:320])[0])
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
    | next hdr | hdr len |  reserved         |nrHops |    authLen     |     
    |            Auth (at least 1248 B = 156 lines) ..                |  
    
    :param next hdr:
    :type next hdr: unsigned char
    :param hdr len:
    :type hdr len: unsigned char
    :param reserved: reserved bytes
    :type reserved: 3 B
    :param nrHops:
    :type nrHops: unsigned char
    :param authLen: the length of the authenticator
    :ctype authLen: unsigned short
    :cvar Auth: session authenticator
    :type Auth: 1232 B + 16 B tag + nrHops * 16 B
    """

    TYPE = 34  # Extension header type
    MIN_LEN = 1256
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
        
        self.reserved = bytes(struct.unpack("!3s", payload[:3])[0])
        self.nrHops = struct.unpack("!B", payload[3:4])[0]
        self.authLen = struct.unpack("!H", payload[4:6])[0]
        paddedAuthLen = 1248 + self.nrHops *  self.HOP_OVERHEAD
        self.auth = bytes(struct.unpack("!" + str(paddedAuthLen) + "s", payload[6:paddedAuthLen+6])[0])
        self.auth = self.auth[:self.authLen]
    
    @staticmethod
    def from_values(nrHops, auth, authLen):
        """
        Create an instance of the DRKeyExtResp class.

        :param nrHops: the number of hops
        :type nrHops: int

        :returns: DRKeyResp extension.
        :rtype: :class:`DRKeyExtResp`
        """
        ext = DRKeyExtResp()
        ext.set_payload(b'a'*(3 + 1 + 2 + 1248 + nrHops * ext.HOP_OVERHEAD))
        ext.reserved = b"\x00" * 3
        ext.nrHops = nrHops
        ext.auth = auth
        ext.authLen = authLen
        return ext
          
    def pack(self):
        """
        Pack the extension header to bytes
        """
        packing = []
        packing.append(struct.pack("!3s", self.reserved))
        packing.append(struct.pack("!B", self.nrHops))
        packing.append(struct.pack("!H", self.authLen))
        paddedAuthLen = 1248 + self.nrHops * self.HOP_OVERHEAD
        authPadLen = paddedAuthLen - self.authLen 
        aux = bytearray(self.auth)
        aux.extend(b"\x00" * authPadLen)
        self.auth = bytes(aux)
        packing.append(struct.pack("!" + str(paddedAuthLen) + "s", self.auth))
        
        self.payload = b"".join(packing)
        ExtensionHeader.set_payload(self, self.payload)
        
        return ExtensionHeader.pack(self)
    
    def __str__(self):
        
        ret_str = "[DRKey Ext Response - start]\n"
        ret_str += "  [next_hdr: %d, len: %d reserved: " % (self.next_hdr, len(self)) + str(self.reserved) +"]\n"
        ret_str += "  [NrHops: %d" % (self.nrHops) + "]...\n"
        ret_str += "  [AuthLen: %d" % self.authLen +"]\n"
        ret_str += "  [Auth: " + str(self.auth[:8]) + "]...\n"

            
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
    logging = kwargs['logging']
    
    logging.info(str(topo.ad_id)+' received: %s', pkt)
    
    # Derive the PRF key from the AS master key
    nodeSecret = b"\x00" * 16
    cipher = AES.new(conf.master_ad_key, AES.MODE_CBC, nodeSecret)
    prfKey = cipher.encrypt(conf.master_ad_key)
    # Generate the key to be shared with the source
    cipher = AES.new(prfKey, AES.MODE_CBC, nodeSecret)
    sharedKey = cipher.encrypt(ext.sessionID)
    # Encrypt the key with the public key of the session
    pubkey = RSA.importKey(ext.pubKey)
    cipher = PKCS1_OAEP.new(pubkey)
    encSharedKey = cipher.encrypt(sharedKey)
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
    logging.info("shared key at node %d (pos %d): %s", topo.ad_id, extOffset + extIndex * DRKeyExtCont.MAX_HOPS, str(sharedKey))

def drkeycont_handler(**kwargs):
    pass

def drkeyresp_handler(**kwargs):
    pass
  
            
        
        
        
        
        
        