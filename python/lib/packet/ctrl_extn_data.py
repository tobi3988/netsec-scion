# External packages
import capnp  # noqa

import proto.ctrl_extn_capnp as P

from lib.packet.packet_base import Cerealizable


class CtrlExtnData(Cerealizable):
    Name = "CtrlExtnData"
    P_CLS = P.CtrlExtnData

    @classmethod
    def from_values(cls, type=b'test', data=b'test'):  # pragma: no cover
        return cls(cls.P_CLS.new_message(type=type, data=data))

class CtrlExtnDataList(Cerealizable):
    NAME = "CtrlExtnDataList"
    P_CLS = P.CtrlExtnDataList

    @classmethod
    def from_values(cls, items=[CtrlExtnData.from_values()]):  # pragma: no cover
        p = cls.P_CLS.new_message()
        ifs = p.init("items", len(items))
        for i, if_ in enumerate(items):
            ifs[i] = if_.p
        return cls(p)

    def items(self):
        return self.p.items
