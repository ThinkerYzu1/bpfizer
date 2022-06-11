def more_often_than(insn1, insn2):
    return False

def merge_replaced_registers(data_flow, insns_flow):
    '''
data_flow: [(as_operand_INSN1, as_operand_INSN2, as_operand_INSN3, ...), ...]
insns_flow: [(next_INSN1, next_INSN2), ....]
'''
    assert(len(data_flow) == len(insns_flow))
    assignments = list(range(len(data_flow)))
    for i, dout in enumerate(data_flow):
        if len(dout) == 1 and dout[0] > i:
            op_insn = dout[0]
            if assignments[op_insn] == op_insn or more_often_than(i, assignments[op_insn]):
                assignments[op_insn] = assignments[i]
                pass
            pass
        pass

    remap = {v: i for i, v in enumerate(sorted(list(set(assignments)))) }
    reassignments = [remap[v] for v in assignments]

    return reassignments
