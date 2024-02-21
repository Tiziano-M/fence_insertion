import angr


registers = [{"name": "ProcState_C", "type": "imm1"}, {"name": "ProcState_N", "type": "imm1"}, {"name": "ProcState_V", "type": "imm1"}, 
             {"name": "ProcState_Z", "type": "imm1"}, {"name": "SP_EL0", "type": "imm64"}, {"name": "R1", "type": "imm64"}, 
             {"name": "R2", "type": "imm64"}, {"name": "R3", "type": "imm64"}, {"name": "R4", "type": "imm64"}, {"name": "R5", "type": "imm64"}, 
             {"name": "R6", "type": "imm64"}, {"name": "R7", "type": "imm64"}, {"name": "R8", "type": "imm64"}, {"name": "R9", "type": "imm64"}, 
             {"name": "R10", "type": "imm64"}, {"name": "R11", "type": "imm64"}, {"name": "R12", "type": "imm64"}, {"name": "R13", "type": "imm64"}, 
             {"name": "R14", "type": "imm64"}, {"name": "R15", "type": "imm64"}, {"name": "R16", "type": "imm64"}, {"name": "R17", "type": "imm64"}, 
             {"name": "R18", "type": "imm64"}, {"name": "R19", "type": "imm64"}, {"name": "R20", "type": "imm64"}, {"name": "R21", "type": "imm64"}, 
             {"name": "R22", "type": "imm64"}, {"name": "R23", "type": "imm64"}, {"name": "R24", "type": "imm64"}, {"name": "R25", "type": "imm64"}, 
             {"name": "R26", "type": "imm64"}, {"name": "R27", "type": "imm64"}, {"name": "R28", "type": "imm64"}, {"name": "R29", "type": "imm64"}, 
             {"name": "R30", "type": "imm64"}, {"name": "R31", "type": "imm64"}, {"name": "ip", "type": "imm64"}]

# https://github.com/kth-step/EmbExp-Logs/blob/master/lib/experiment.py
def _proc_input_state(inp, statename):
		def value_parse_rec(d, convkey = False):
			d_ = {}
			for k in d:
				v = d[k]
				if convkey and k != "default":
					k = (int(k, 16) if type(k) == str else k)
				if isinstance(v, dict):
					v_ = value_parse_rec(v, True)
				else:
					v_ = int(v, 16) if type(v) == str else v
				d_[k] = v_
			return d_

		if not statename in inp.keys():
			return None
		return value_parse_rec(inp[statename])

def get_input_state(in_data, statename):
	  return _proc_input_state(in_data, statename)


def init_trace(jsonout, run_id):
    jsonout[run_id] = {"states" : []}
    return jsonout

def save_trace(jsonout, run_id, state_id, state, regs, all_regs, insn):
    dict_state = {}
    dict_state["state_id"] = state_id
    dict_state["instruction"] = insn.render()[0]
    dict_state["instr_address"] = insn.addr
    dict_state["registers"] = save_regs(state, regs, all_regs)
    dict_state["memory"] = save_mem(state)
    dict_state["observations"] = save_obs(state)
    dict_state["operands"] = save_operands(state, insn) if insn is not None else []
    jsonout[run_id]["states"].append(dict_state.copy())
    return jsonout

def save_regs(state, regs, all_regs):
    if all_regs:
        regs = registers

    list_regs = []
    for reg in regs:
        reg_n = reg["name"]
        try:
            val = getattr(state.regs, reg_n)
            if val.symbolic:
                reg_v = (0, val.size())
            else:
                assert val.size() == val.args[1]
                reg_v = (val.args[0], val.args[1])
            list_regs.append((reg_n, reg_v))
        except Exception:
            if all_regs:
                if reg["type"] == "imm64":
                    sz = 64
                elif reg["type"] == "imm1":
                    sz = 8
                else:
                    raise Exception(f"Unexpected register type {reg}")
                list_regs.append((reg["name"], ((0, sz))))
            else:
                raise Exception(f"Register {reg_n} not found in the state")
    return list_regs

def save_mem(state):
    default_mem = {}
    #default_mem = {0: {"value": [1, 64], "size": 64}, 80: {"value": [2, 64], "size": 64}}
    return default_mem

def save_obs(state):    
    list_obs = []
    for (_,_,obs_list,_) in state.observations.list_obs:
        for obs in obs_list:
            if obs.symbolic:
                raise Exception(f"Observation value not as expected: {obs}")
            else:
                assert obs.size() == obs.args[1]
                obs_v = (obs.args[0], obs.args[1])
            list_obs.append(obs_v)
    return list_obs

def save_operands(state, insn):
    def set_reg_op_from_state(state, operands):
        roperands = []
        for reg in operands:
            try:
                if reg[0] == "x":
                    reg_num = reg[1:]
                    regname = "R" + reg_num
                elif reg == "sp":
                    regname = "SP_EL0"
                elif reg.startswith("ProcState_") and (reg[-1] in ["C", "N", "V", "Z"]):
                    regname = reg
                else:
                    raise Exception("Unknown register ", reg)

                val = getattr(state.regs, regname)
                if val.symbolic:
                    roperands.append((regname, (0, val.size())))
                else:
                    assert val.size() == val.args[1]
                    roperands.append((regname, (val.args[0], val.args[1])))
            except Exception:
                raise Exception(f"Error with register {reg_name} in state {state}")
        return roperands

    def extract_reg_operands(insn, operands):
        for operand in insn.operands:
            if isinstance(operand, angr.analyses.disassembly.RegisterOperand):
                if isinstance(operand.register, angr.analyses.disassembly.Register):
                    operands.add(operand.register.reg)
            elif isinstance(operand, angr.analyses.disassembly.MemoryOperand):
                for val_op in operand.values:
                    if isinstance(val_op, angr.analyses.disassembly.Register):
                        operands.add(val_op.reg)
            elif isinstance(operand, angr.analyses.disassembly.ConstantOperand):
                continue
            else:
                raise Exception("Unknown operand: ", operand)
        return operands

    operands = extract_reg_operands(insn, set())
    if insn.insn.update_flags:
        operands.update(["ProcState_C", "ProcState_N", "ProcState_V", "ProcState_Z"])
    return set_reg_op_from_state(state, operands)

def rosette_input(json_out, exp_id, exp_res):
    if exp_res == True:
        exp_ty = "p"
    elif exp_res == False:
        exp_ty = "c"
    else:
        raise Exception(f"Unexpected experiment result: {exp_res}")

    filename = "input.rkt"
    text_run1 = rosette_input_text(json_out[0]["states"], 0, exp_id, exp_ty)
    text_run2 = rosette_input_text(json_out[1]["states"], 1, exp_id, exp_ty)
    with open(filename, "w") as f:   
        f.write(text_run1 + text_run2)

def rosette_input_text(states, run_id, exp_id, exp_ty):
    state_ids = []
    text = ""
    for state in states:
        state_id_txt = f"{exp_ty}{exp_id}-r{run_id}_{state['state_id']}"
        indentation = ''.join([' ' for _ in range(len(f"(define {state_id_txt} "))])

        text += "\n"
        text += instruction_text(state["instruction"], indentation)
        text += f"(define {state_id_txt} (make-run\t ; Registers\n"
        text += regs_text(state["registers"], indentation)
        text += mem_text(state["memory"], indentation)
        text += iaddr_text(state["instr_address"], indentation)
        text += operands_text(state["operands"], indentation)
        #text += obs_text(state["observations"], indentation)
        text += "))\n"
        state_ids.append(state_id_txt)
    state_ids_txt = " ".join(state_id for state_id in state_ids)
    text += f"\n(define {exp_ty}{exp_id}-r{run_id} (list {state_ids_txt}))\n\n"
    return text

def instruction_text(instr_json, indentation):
    return f"; Instruction: {instr_json}\n"

def regs_text(regs_json, indentation):
    regs = f"{indentation}(vector-immutable\n"
    for reg in regs_json:
        regs += f"{indentation}   (REG (bv {reg[1][0]} (bitvector {reg[1][1]})))\t; Register: {reg[0]}\n"
    return f"\t{regs}{indentation}   )\n\n"

def mem_text(mem_json, indentation):
    mem = f"{indentation}; Memory\n"
    mem += f"{indentation}  (vector-immutable\n"
    if mem_json == {}:
        mem += f"{indentation}  '()\n"
    else:
        for (addr, val) in mem_json.items():
            mem += f"{indentation}   (MEM (bv {addr} (bitvector {val['size']})) (bv {val['value'][0]} (bitvector {val['value'][1]})))\n"
    return f"\t{mem}{indentation}   )\n\n"

def iaddr_text(iaddr_json, indentation):
    iaddr = f"{indentation}; Instruction Address\n"
    iaddr += f"{indentation}  (bv {iaddr_json} (bitvector 64))\n"
    return f"\t{iaddr}\n"

def obs_text(obs_json, indentation):
    obss = f"{indentation}; Obs\n"
    obss += f"{indentation}  (vector-immutable\n"
    for obs in obs_json:
        obss += f"{indentation}   (bv {obs[0]} (bitvector {obs[1]}))\n"
    return f"\t{obss}{indentation}   )\n"

def operands_text(operands_json, indentation):
    opss = f"{indentation}; Operands\n"
    opss += f"{indentation}  (vector-immutable\n"
    if operands_json == []:
        opss += f"{indentation}  '()\n"
    else:
        for ops in operands_json:
            opss += f"{indentation}   (bv {ops[1][0]} (bitvector {ops[1][1]}))\t; Operand: {ops[0]}\n"
    return f"\t{opss}{indentation}   )\n"

