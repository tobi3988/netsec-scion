"""
sciond.py

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

from infrastructure.scion_elem import SCIONElement
from lib.packet.path import PathCombinator
from lib.packet.scion import (SCIONPacket, get_type, PathRequest, PathRecords,
    PathInfo, PathInfoType as PIT)
from lib.packet.scion import PacketType as PT
from lib.path_db import PathDB
from lib.topology_parser import ElementType
from lib.util import update_dict
import logging
import threading


PATHS_NO = 5  # conf parameter?
WAIT_CYCLES = 3


class SCIONDaemon(SCIONElement):
    """
    The SCION Daemon used for retrieving and combining paths.
    """

    TIMEOUT = 5

    def __init__(self, addr, topo_file):
        SCIONElement.__init__(self, addr, topo_file)
        # TODO replace by pathstore instance
        self.up_paths = PathDB()
        self.down_paths = PathDB()
        self.core_paths = PathDB()
        self._waiting_targets = {PIT.UP: {},
                                 PIT.DOWN: {},
                                 PIT.CORE: {},
                                 PIT.UP_DOWN: {}}

    @classmethod
    def start(cls, addr, topo_file):
        """
        Initializes, starts, and returns a SCIONDaemon object.

        Example of usage:
        sd = SCIONDaemon.start(addr, topo_file)
        paths = sd.get_paths(isd_id, ad_id)
        ...
        """
        sd = cls(addr, topo_file)
        t = threading.Thread(target=sd.run)
        t.setDaemon(True)
        t.start()
        return sd

    def _request_paths(self, ptype, dst_isd, dst_ad, src_isd=None, src_ad=None):
        """
        Sends path request with certain type for (isd, ad).
        """
        if src_isd is None:
            src_isd = self.topology.isd_id
        if src_ad is None:
            src_ad = self.topology.ad_id

        # Create an event that we can wait on for the path reply.
        event = threading.Event()
        update_dict(self._waiting_targets[ptype], (dst_isd, dst_ad), [event])

        # Create and send out path request.
        info = PathInfo.from_values(ptype, src_isd, dst_isd, src_ad, dst_ad)
        path_request = PathRequest.from_values(self.addr, info)
        dst = self.topology.servers[ElementType.PATH_SERVER].addr
        self.send(path_request, dst)

        # Wait for path reply and clear us from the waiting list when we got it.
        cycle_cnt = 0
        while cycle_cnt < WAIT_CYCLES:
            event.wait(SCIONDaemon.TIMEOUT)
            # Check that we got all the requested paths.
            if ((ptype == PIT.UP and len(self.up_paths)) or
                (ptype == PIT.DOWN and
                 self.down_paths(dst_isd=dst_isd, dst_ad=dst_ad)) or
                (ptype == PIT.CORE and
                 self.core_paths(src_isd=src_isd, src_ad=src_ad,
                                 dst_isd=dst_isd, dst_ad=dst_ad)) or
                (ptype == PIT.UP_DOWN and (len(self.up_paths) and
                 self.down_paths(dst_isd=dst_isd, dst_ad=dst_ad)))):
                self._waiting_targets[ptype][(dst_isd, dst_ad)].remove(event)
                del self._waiting_targets[ptype][(dst_isd, dst_ad)]
                break
            event.clear()
            cycle_cnt += 1

    def get_paths(self, dst_isd, dst_ad):
        """
        Returns a list of paths.
        """
        full_paths = []
        down_paths = self.down_paths(dst_isd=dst_isd, dst_ad=dst_ad)
        # Fetch down-paths if necessary.
        if not down_paths:
            self._request_paths(PIT.UP_DOWN, dst_isd, dst_ad)
            down_paths = self.down_paths(dst_isd=dst_isd, dst_ad=dst_ad)
        if len(self.up_paths) and down_paths:
            full_paths = PathCombinator.build_shortcut_paths(self.up_paths(),
                                                             down_paths)
            if full_paths:
                return full_paths
            else:
                # No shortcut path could be built. Select an up and down path
                # and request a set of core-paths connecting them.
                # For now we just choose the first up-/down-path.
                # TODO: Atm an application can't choose the up-/down-path to be
                #       be used. Discuss with Pawel.
                src_isd = self.topology.isd_id
                src_core_ad = self.up_paths()[0].get_first_ad().ad_id
                dst_core_ad = down_paths[0].get_first_ad().ad_id
                core_paths = self.core_paths(src_isd=src_isd,
                                             src_ad=src_core_ad,
                                             dst_isd=dst_isd,
                                             dst_ad=dst_core_ad)
                if ((src_isd, src_core_ad) != (dst_isd, dst_core_ad) and
                    not core_paths):
                    self._request_paths(PIT.CORE, dst_isd, dst_core_ad,
                                        src_ad=src_core_ad)
                    core_paths = self.core_paths(src_isd=src_isd,
                                                 src_ad=src_core_ad,
                                                 dst_isd=dst_isd,
                                                 dst_ad=dst_core_ad)

                full_paths = PathCombinator.build_core_paths(self.up_paths()[0],
                                                             down_paths[0],
                                                             core_paths)

        return full_paths

    def handle_path_reply(self, packet):
        """
        Handles path reply from local path server.
        """
        path_reply = PathRecords(packet)
        info = path_reply.info
        for pcb in path_reply.pcbs:
            isd = pcb.get_isd()
            ad = pcb.get_last_ad().ad_id

            if ((self.topology.isd_id != isd or self.topology.ad_id != ad)
                and info.type in [PIT.DOWN, PIT.UP_DOWN]
                and info.dst_isd == isd and info.dst_ad == ad):
                self.down_paths.insert(pcb, info.src_isd, info.src_ad,
                                       info.dst_isd, info.dst_ad)
                logging.info("DownPath PATH added for (%d,%d)", isd, ad)
            elif ((self.topology.isd_id == isd and self.topology.ad_id == ad)
                and info.type in [PIT.UP, PIT.UP_DOWN]):
                self.up_paths.insert(pcb, isd, ad,
                                     pcb.get_isd(), pcb.get_first_ad().ad_id)
                logging.info("UP PATH to (%d, %d) added.", isd, ad)
            elif info.type == PIT.CORE:
                self.core_paths.insert(pcb, info.src_isd, info.src_ad,
                                       info.dst_isd, info.dst_ad)
            else:
                logging.warning("Incorrect path in Path Record")

        # Wake up sleeping get_paths().
        if (info.dst_isd, info.dst_ad) in self._waiting_targets[info.type]:
            for event in \
                self._waiting_targets[info.type][(info.dst_isd, info.dst_ad)]:
                event.set()

    def handle_request(self, packet, sender, from_local_socket=True):
        """
        Main routine to handle incoming SCION packets.
        """
        spkt = SCIONPacket(packet)
        ptype = get_type(spkt)

        if ptype == PT.PATH_REC:
            self.handle_path_reply(packet)
        else:
            logging.warning("Type %d not supported.", ptype)
