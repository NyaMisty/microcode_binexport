import dataclasses
import json
import os


os.environ['PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION'] = 'python'
import random
import time

from google.protobuf.json_format import MessageToDict
from binexport2_pb2 import BinExport2

EXEC_NAME = 'test1'

ret = BinExport2()

# dict_keys(['metaInformation', 'expression', 'operand', 'mnemonic', 'instruction', 'basicBlock', 'flowGraph', 'callGraph', 'stringTable', 'section', 'dataReference', 'module', 'comment'])
ret.meta_information.executable_name = EXEC_NAME
ret.meta_information.executable_id = ''.join(random.choice('0123456789abcdef') for _ in range(32))
ret.meta_information.architecture_name = 'ida-microcode'
ret.meta_information.timestamp = int(time.time())

from mcexport import MCInsn, MCOp
with open(r'D:\Workspaces\CTFWorkspace\changchengbei2024final\ics_cam\mc_export_test.json') as f:
    mc = json.load(f)
    inslist = MCInsn.schema().load(mc['ins'], many=True)
    flows = mc['flows']
    # inslist: list[MCInsn] = MCInsn.schema().loads(f.read(), many=True)

opDict = {dataclasses.astuple(op): -1 for ins in inslist for op in ins.ops}
for i, optuple in enumerate(opDict.keys()):
    expr = BinExport2.Expression()
    op = MCOp(*optuple)
    match op.type:
        case 'imm':
            expr.type = BinExport2.Expression.Type.IMMEDIATE_INT
            expr.symbol = op.value
        case 'reg':
            expr.type = BinExport2.Expression.Type.REGISTER
            expr.symbol = op.value
        case 'symbol':
            expr.type = BinExport2.Expression.Type.SYMBOL
            expr.symbol = op.value
        case 'label':
            expr.type = BinExport2.Expression.Type.SYMBOL
            expr.symbol = op.value
        case 'expression':
            expr.type = BinExport2.Expression.Type.SYMBOL
            expr.symbol = op.value
        case _:
            raise Exception('unknown op: %s' % op)
    ret.expression.append(expr)
    ret.operand.add(expression_index=[len(ret.expression) - 1])
    opDict[optuple] = i

mnemDict = {ins.mnem: -1 for ins in inslist}
for i, mnem in enumerate(mnemDict.keys()):
    ret.mnemonic.add(name=mnem)
    mnemDict[mnem] = i

for ins in inslist:
    ret.instruction.add(
        address=ins.blk_i << 16 | ins.insn_i,
        mnemonic_index=mnemDict[ins.mnem],
        operand_index=[opDict[dataclasses.astuple(op)] for op in ins.ops],
        raw_bytes=b'',
    )

blk_ins = {}
for i, ins in enumerate(inslist):
    if ins.blk_i not in blk_ins:
        blk_ins[ins.blk_i] = []
    blk_ins[ins.blk_i].append(i)

for blk_i, blkinslist in blk_ins.items():
    bb = BinExport2.BasicBlock()
    bb.instruction_index.add(begin_index=min(0xffffffff, *blkinslist), end_index=max(0, *blkinslist) + 1)
    ret.basic_block.append(bb)

fg =  BinExport2.FlowGraph()
fg.entry_basic_block_index = 0
for blk_i, succs in flows.items():
    blk_i = int(blk_i)
    fg.basic_block_index.append(blk_i)
    match len(succs):
        case 0:
            pass
        case 1:
            fg.edge.add(
                source_basic_block_index=blk_i,
                target_basic_block_index=succs[0],
            )
        case 2:
            fg.edge.add(
                source_basic_block_index=blk_i,
                target_basic_block_index=succs[0],
                type=BinExport2.FlowGraph.Edge.Type.CONDITION_FALSE
            )
            fg.edge.add(
                source_basic_block_index=blk_i,
                target_basic_block_index=succs[1],
                type=BinExport2.FlowGraph.Edge.Type.CONDITION_TRUE
            )
        case _:
            for succ in succs:
                fg.edge.add(
                    source_basic_block_index=blk_i,
                    target_basic_block_index=succs[1],
                    type=BinExport2.FlowGraph.Edge.Type.SWITCH
                )

ret.flow_graph.append(fg)

cg = BinExport2.CallGraph()
vertex = BinExport2.CallGraph.Vertex()
vertex.address = ret.instruction[0].address
cg.vertex.append(vertex)
ret.call_graph.MergeFrom(cg)

print(ret)
with open('testmc.binexport', 'wb') as f:
    f.write(ret.SerializeToString())
# print(MCOp(*next(iter(opDict.keys()))))
# print(mnemDict, opDict)
