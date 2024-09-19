def getmc(addr):
    import idaapi as hr

    class printer_t(hr.vd_printer_t):
        """Converts microcode output to an array of strings."""

        def __init__(self, *args):
            hr.vd_printer_t.__init__(self)
            self.mc = []

        def get_mc(self):
            return self.mc

        def _print(self, indent, line):
            self.mc.append(line)
            return 1

    mbr = hr.mba_ranges_t(hr.get_func(addr))
    mba_flags = hr.MBA_SHORT
    # mmat = hr.MMAT_GENERATED
    mmat = hr.MMAT_LVARS

    # gen mc
    hf = hr.hexrays_failure_t()
    ml = hr.mlist_t()
    mba = hr.gen_microcode(mbr, hf, ml, hr.DECOMP_WARNINGS, mmat)
    mba.build_graph()
    # print mc
    vp = printer_t()
    mba.set_mba_flags(mba_flags)
    mba._print(vp)
    flows = {}
    eas = {}
    for blk_i in range(mba.qty):
        blk = mba.get_mblock(blk_i)
        succs = []
        for b in blk.succs():
            succs.append(b.serial)
        flows[blk_i] = succs
        ins = blk.head
        ins_i = 0
        while ins:
            eas[(blk_i, ins_i)] = ins.ea
            if not ins.next:
                break
            ins = ins.next
            ins_i += 1


    return vp.mc, flows, eas


import re
import dataclasses
from dataclasses_json import dataclass_json

from typing import Optional, List


@dataclass_json
@dataclasses.dataclass
class MCOp:
    type: str
    value: str


@dataclass_json
@dataclasses.dataclass
class MCInsn:
    raw_line: str
    ea: int
    blk_i: int
    insn_i: int
    mnem: str
    ops: List[MCOp]


def parseOp_(opstr):
    m = re.match(r'^\x01 (#.*?)\x02$', opstr)
    if m:
        return MCOp(type='imm', value=m.groups()[0])
    m = re.match(r'^\x01\t(#.*?)\x02\t$', opstr)
    if m:
        return MCOp(type='imm', value=m.groups()[0])
    m = re.match(r'^\x01\x18(.*?)\x02\x18$', opstr) or \
        re.match(r'^(\x01".*?\x02"(|\x01\x04.*?\x02\x04))$', opstr)
    if m:
        return MCOp(type='reg', value=m.groups()[0])
    m = re.match(r'^(\x01\x07\$.*?\x02\x07.*?)$', opstr) or \
        re.match(r'^(\x01\x1a!.*?\x02\x1a.*?)$', opstr)
    if m:
        return MCOp(type='symbol', value=m.groups()[0])
    m = re.match(r'^\x01\x1c(@.*?)\x02\x1c$', opstr)
    if m:
        return MCOp(type='label', value=m.groups()[0])
    m = re.match(r'^\x01\t(\{.*?\})\x02\t$', opstr)
    if m:
        return MCOp(type='expression', value=m.groups()[0])

    return MCOp(type='unk', value=opstr)

def parseOp(opstr):
    ret = parseOp_(opstr)
    import idaapi
    ret.value = idaapi.tag_remove(ret.value)
    return ret

def parseInsn(l, eas=None):
    m = re.findall(r'^\x01\x13(?P<blk_i>\d+)\. *(?P<insn_i>\d+) *\x02\x13(?P<insn>.*?|)\n$', l)
    assert len(m) == 1
    blk_i, insn_i, insn = m[0]
    ret = MCInsn(raw_line=l, ea=0, blk_i=int(blk_i), insn_i=int(insn_i), mnem='', ops=[])
    if not insn:
        return ret

    if eas and (ret.blk_i, ret.insn_i) in eas:
        ret.ea = eas[(ret.blk_i, ret.insn_i)]

    m = re.findall(r'^\x01 *(?P<mnemonic>.*?)\x02 *(?P<operands>.*?)$', insn)
    assert len(m) == 1
    mnem, opline = m[0]
    ret.mnem = mnem

    m = re.split(r' *\x01\t,\x02\t ', opline)
    # ret.ops = m
    parsedOp = []
    for opstr in m:
        parsedOp.append(parseOp(opstr))
    ret.ops = parsedOp
    return ret


if __name__ == '__main__':
    # blk_ins = {}
    # for l in vp.mc:
    #    ins = parseInsn(l)
    #    if ins.blk_i not in blk_ins:
    #        blk_ins[ins.blk_i] = []
    #    blk_ins[ins.blk_i].append(ins)
    # print(blk_ins.to_json())
    inslines, flows, eas = getmc(here())
    inslist = [parseInsn(c, eas=eas) for c in inslines]
    with open('mc_export_test.json', 'w') as f:
        body = {
            'ins': MCInsn.schema().dump(inslist, many=True),
            'flows': flows,
        }

        import json

        json.dump(body, f, indent=2)