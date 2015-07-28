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
:mod:`cli_srv_ext_test` --- SCION client-server test with an extension
===========================================
"""
# Stdlib
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
import logging
import socket
import struct
import threading
import time
from base64 import b64decode, b64encode
from ipaddress import IPv4Address

# SCION
from endhost.sciond import SCIONDaemon
from lib.defines import SCION_BUFLEN, SCION_UDP_EH_DATA_PORT
from lib.crypto.symcrypto import sha3hash, authenticated_encrypt, authenticated_decrypt,\
    get_roundkey_cache
from lib.packet.ext.drkey import DRKeyExt, DRKeyExtCont, DRKeyExtResp
from lib.packet.ext_hdr import ExtensionHeader
from lib.packet.scion import SCIONPacket
from lib.packet.scion_addr import SCIONAddr

TOUT = 10  # How long wait for response.
CLI_ISD = 1
CLI_AD = 19
CLI_IP = "127.1.19.254"
SRV_ISD = 2
SRV_AD = 26
SRV_IP = "127.1.26.254"


def client():
    """
    Simple client
    """
    topo_file = ("../../topology/ISD%d/topologies/ISD:%d-AD:%d.json" %
                 (CLI_ISD, CLI_ISD, CLI_AD))
    # Start SCIONDaemon
    sd = SCIONDaemon.start(IPv4Address(CLI_IP), topo_file)
    print("CLI: Sending PATH request for (%d, %d)" % (SRV_ISD, SRV_AD))
    # Get paths to server through function call
    paths = sd.get_paths(SRV_ISD, SRV_AD)
    assert paths
    # Get a first path
    path = paths[0]
    # Create a SCION address to the destination
    dst = SCIONAddr.from_values(SRV_ISD, SRV_AD, IPv4Address(SRV_IP))
    # Set payload
    payload = b"request to server"
    # Create plain extension with payload b"test"
    e1 = ExtensionHeader()
    e1.set_payload(b'test')
    # Create a DRKey extension
    SDkey = b"\x03" * 16
    ### Create the session key pair
    sessionPrivateKey =  RSA.generate(2048)
    sessionPrivateKeyDER = sessionPrivateKey.exportKey('DER')
    sessionPublicKey = sessionPrivateKey.publickey()
    sessionPublicKeyDER = sessionPublicKey.exportKey('DER')
    sessionPublicKeyStr = b64encode(sessionPublicKeyDER).decode()
    ### Get the current time
    crtTime = int(time.time() * 1000) % 2**16
    ### Create the sessionID
    hashInputComp = []
    hashInputComp.append(sessionPublicKeyStr)
    hashInputComp.append(str(path))
    hashInputComp.append(str(crtTime))
    hashInput = "".join(hashInputComp)
    hashOutput = sha3hash(hashInput, 'SHA3-256')[:32]
    sessionID = bytes(bytearray.fromhex(hashOutput.decode()))
    ### Create the session authenticator
    expandedSDkey = get_roundkey_cache(SDkey)
    authInput = bytearray(sessionID)
    authInput.extend(sessionPrivateKeyDER)
    authInput = bytes(authInput)
    authEnc = authenticated_encrypt(expandedSDkey, authInput, b"")
    auth = authEnc[:1207] 
    authTag = authEnc[1207:1223]
    ### Create the DRKeyExt object
    nrHops = int(len(path.pack()) / 8)
    drkeyExt = DRKeyExt.from_values(sessionID, sessionPublicKeyDER, crtTime, authTag, auth, nrHops)
    print("S initiated a DRKey setup with ")
    print("sessionID")
    print(sessionID)
    print("session public key")
    print(sessionPublicKeyDER)
    print("time")
    print(crtTime)
    print("auth and tag")
    print(auth)
    print(authTag)
    # Create a DRKeyCont extension to store the keys generated at each node
    ### Compute how many extensions are needed
    nrExtensions = int(nrHops / DRKeyExtCont.MAX_HOPS)
    remainingHops = nrHops % DRKeyExtCont.MAX_HOPS
    drkeyExtCont = []
    for _ in range(0, nrExtensions):
        drkeyExtCont.append(DRKeyExtCont.from_values(DRKeyExtCont.MAX_HOPS))
    if remainingHops != 0:
        drkeyExtCont.append(DRKeyExtCont.from_values(remainingHops))
    # Create another plain extension
    e3 = ExtensionHeader()
    # Create a SCION packet with the extensions
    extensions = [e1, drkeyExt]
    extensions += drkeyExtCont
    extensions.append(e3)
    spkt = SCIONPacket.from_values(sd.addr, dst, payload, path,
                                   ext_hdrs=extensions)
    # Determine first hop (i.e., local address of border router)
    (next_hop, port) = sd.get_first_hop(spkt)
    print("CLI: Sending packet: %s\nFirst hop: %s:%s" % (spkt, next_hop, port))
    # Send packet to first hop (it is sent through SCIONDaemon)
    sd.send(spkt, next_hop, port)
    # Open a socket for incomming DATA traffic
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((CLI_IP, SCION_UDP_EH_DATA_PORT))
    # Waiting for a response
    raw, _ = sock.recvfrom(SCION_BUFLEN)
    print('\n\nCLI: Received response:\n%s' % SCIONPacket(raw))
    spkt = SCIONPacket(raw)
    for drkeyRespExt in spkt.hdr.extension_hdrs:
        if drkeyRespExt.TYPE == DRKeyExtResp.TYPE:
            break
    dec = authenticated_decrypt(expandedSDkey, drkeyRespExt.auth+drkeyRespExt.authTag, b"")
    keyOffset = 1223
    keys = []
    while keyOffset < len(dec) - 16:
        keys.append(dec[keyOffset:keyOffset+16])
        keyOffset += 16
    print(keys)
    print("CLI: leaving.")
    sock.close()
    sd.clean()


def server():
    """
    Simple server.
    """
    topo_file = ("../../topology/ISD%d/topologies/ISD:%d-AD:%d.json" %
                 (SRV_ISD, SRV_ISD, SRV_AD))
    # Start SCIONDaemon
    sd = SCIONDaemon.start(IPv4Address(SRV_IP), topo_file)
    # Open a socket for incomming DATA traffic
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((SRV_IP, SCION_UDP_EH_DATA_PORT))
    # Waiting for a request
    raw, _ = sock.recvfrom(SCION_BUFLEN)
    # Request received, instantiating SCION packet
    spkt = SCIONPacket(raw)
    print('SRV: received: %s', spkt)
    ## Check the session ID integrity
    for drkeyExt in spkt.hdr.extension_hdrs:
        if drkeyExt.TYPE == DRKeyExt.TYPE:
            break
    sessionPublicKeyStr = b64encode(drkeyExt.pubKey).decode()
    crtTime = drkeyExt.time
    path = spkt.hdr._path
    hashInputComp = []
    hashInputComp.append(sessionPublicKeyStr)
    hashInputComp.append(str(path))
    hashInputComp.append(str(crtTime))
    hashInput = "".join(hashInputComp)
    hashOutput = sha3hash(hashInput, 'SHA3-256')[:32]
    sessionID = bytes(bytearray.fromhex(hashOutput.decode()))
    if drkeyExt.sessionID != sessionID:
        print("Different session ID")
    
    ## Decrypt and authenticate auth
    SDkey = b"\x03" * 16
    expandedSDkey = get_roundkey_cache(SDkey)
    print(drkeyExt.auth+drkeyExt.authTag)
    dec = authenticated_decrypt(expandedSDkey, drkeyExt.auth+drkeyExt.authTag, b"")
    decSessionID = dec[:16]
    decPrivKey = dec[16:1207]
    if drkeyExt.sessionID != decSessionID:
        print("Different session ID 2")
    privkey = RSA.importKey(decPrivKey)
    cipher = PKCS1_OAEP.new(privkey)
    
    ## Decrypt the keys
    keys = []
    nrKeys = drkeyExt.maxHops
    for ext in spkt.hdr.extension_hdrs:
        if ext.TYPE == DRKeyExtCont.TYPE:
            for (encKey, sigKey) in ext.hopInfo:
                key = cipher.decrypt(encKey)
                # TODO check signature
                keys.append(key)
    
    if spkt.payload == b"request to server":
        print('SRV: request received, sending response.')
        # Create a drkey reply packet
        spkt.hdr.reverse()
        revPath = spkt.hdr._path
        nrHops = int(len(revPath.pack()) / 8)
        authInput = bytearray()
        authInput.extend(drkeyExt.auth)
        authInput.extend(drkeyExt.authTag)
        for key in keys:
            authInput.extend(key)
        authInput = bytes(authInput)
        authEnc = authenticated_encrypt(expandedSDkey, authInput, b"")
        authLen = 1223 + nrHops * DRKeyExtResp.HOP_OVERHEAD
        auth = authEnc[:authLen] 
        authTag = authEnc[authLen:authLen + 16]
        drkeyRespExt = DRKeyExtResp.from_values(nrHops, auth, authTag)
        extensions = [drkeyRespExt]
        payload = b"response"
        revspkt = SCIONPacket.from_values(spkt.hdr.src_addr, spkt.hdr.dst_addr, payload, revPath,
                                   ext_hdrs=extensions)
        
        # Determine first hop (i.e., local address of border router)
        (next_hop, port) = sd.get_first_hop(revspkt)
        # Send packet to first hop (it is sent through SCIONDaemon)
        print("CLI: Sending packet: %s\nFirst hop: %s:%s" % (revspkt, next_hop, port))
        sd.send(revspkt, next_hop, port)
    print("SRV: Leaving server.")
    sock.close()
    sd.clean()


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    # if len(sys.argv) == 3:
    #     isd, ad = sys.argv[1].split(',')
    #     sources = [(int(isd), int(ad))]
    #     isd, ad = sys.argv[2].split(',')
    #     destinations = [(int(isd), int(ad))]
    # TestSCIONDaemon().test(sources, destinations)
    threading.Thread(target=server).start()
    time.sleep(0.5)
    threading.Thread(target=client).start()
