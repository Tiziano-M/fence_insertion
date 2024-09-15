import angr


REGISTERS = [{"name": "ProcState_C", "type": "imm1"}, {"name": "ProcState_N", "type": "imm1"}, {"name": "ProcState_V", "type": "imm1"}, 
             {"name": "ProcState_Z", "type": "imm1"}, {"name": "SP_EL0", "type": "imm64"}, {"name": "R0", "type": "imm64"}, {"name": "R1", "type": "imm64"}, 
             {"name": "R2", "type": "imm64"}, {"name": "R3", "type": "imm64"}, {"name": "R4", "type": "imm64"}, {"name": "R5", "type": "imm64"}, 
             {"name": "R6", "type": "imm64"}, {"name": "R7", "type": "imm64"}, {"name": "R8", "type": "imm64"}, {"name": "R9", "type": "imm64"}, 
             {"name": "R10", "type": "imm64"}, {"name": "R11", "type": "imm64"}, {"name": "R12", "type": "imm64"}, {"name": "R13", "type": "imm64"}, 
             {"name": "R14", "type": "imm64"}, {"name": "R15", "type": "imm64"}, {"name": "R16", "type": "imm64"}, {"name": "R17", "type": "imm64"}, 
             {"name": "R18", "type": "imm64"}, {"name": "R19", "type": "imm64"}, {"name": "R20", "type": "imm64"}, {"name": "R21", "type": "imm64"}, 
             {"name": "R22", "type": "imm64"}, {"name": "R23", "type": "imm64"}, {"name": "R24", "type": "imm64"}, {"name": "R25", "type": "imm64"}, 
             {"name": "R26", "type": "imm64"}, {"name": "R27", "type": "imm64"}, {"name": "R28", "type": "imm64"}, {"name": "R29", "type": "imm64"}, 
             {"name": "R30", "type": "imm64"}, {"name": "ip", "type": "imm64"}]
REGISTER_TYPES = {
        "imm64": 64,
        "imm32": 32,
        "imm16": 16,
        "imm8": 8,
        "imm1": 8
    }

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


class TraceExporter:
    EMPTY_REGISTERS = [(reg["name"], (0, REGISTER_TYPES[reg["type"]])) for reg in REGISTERS]
    EMPTY_OPERANDS = [(0, 64)] * 6

    def __init__(self,
                 regs,
                 extract_operands,
                 obs_operand_id,
                 traces_json=None,
                 obs_json=None,
                 ctrace=None,
                 all_p = False
                 ):
        self.regs = regs + [{"name": "ip", 'type': 'imm64'}] if regs is not None else REGISTERS
        self.all_regs = False if regs is not None else True
        self.traces_json = traces_json if traces_json is not None else {}
        self.obs_json = obs_json if obs_json is not None else {}
        self.state_id = None
        self.extract_operands = extract_operands
        self.obs_operand_id = obs_operand_id
        self._cache_ctrace = ctrace
        self.all_p = all_p

    def init_trace(self, run_id):
        self.traces_json[run_id] = {"states" : []}
        self.state_id = 0

    def save_trace(self, run_id, state, insn):
        dict_state = {}
        dict_state["state_id"] = self.state_id
        dict_state["instruction"] = insn.render()[0]
        dict_state["instr_address"] = insn.addr
        dict_state["registers"] = self.save_regs(state)
        dict_state["memory"] = self.save_mem(state)

        #dict_state["observations"] = self.save_obs(state)
        #dict_state["operands"] = self.save_operands(state, insn) if insn is not None else []
        dict_state["operands"] = [] #self.save_obs_operands(state) if self.extract_operands else []

        self.traces_json[run_id]["states"].append(dict_state.copy())
        self.state_id += 1

    def add_operands_to_trace(self, run_id, state):
        ops = self.save_obs_operands(state)
        self.traces_json[run_id]["states"][-1]["operands"].extend(ops)

    def save_regs(self, state):
        list_regs = []
        for reg in self.regs:
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
                if self.all_regs:
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

    def save_mem(self, state):
        default_mem = {}
        #default_mem = {0: {"value": [1, 64], "size": 64}, 80: {"value": [2, 64], "size": 64}}
        return default_mem

    def save_obs(self, run_id, state):
        self.obs_json[run_id] = []
        for (obs_id,obs_cond,obs_list,_) in state.observations.list_obs:
            obsjson = {}
            obsjson["obs_id"] = obs_id
            obsjson["obs_cond"] = state.solver.eval(obs_cond)
            obsjson["obs_list"] = []
            for obs in obs_list:
                if obs.symbolic:
                    obs_v = (state.solver.eval(obs), obs.size())
                else:
                    assert obs.size() == obs.args[1]
                    obs_v = (obs.args[0], obs.args[1])
                obsjson["obs_list"].append(obs_v)
            self.obs_json[run_id].append(obsjson)
        return self.obs_json[run_id]

    def save_obs_operands(self, state):
        if self.obs_operand_id is None:
            raise Exception("Operand id is not set")

        list_obs = []
        for (obs_id,_,obs_list,_) in state.observations.list_obs:
            if obs_id == self.obs_operand_id:
                for obs in obs_list:
                    if obs.symbolic:
                        if self.extract_operands:
                            obs_v = (state.solver.eval(obs), obs.size())
                        else:
                            raise Exception(f"Observation value not as expected: {obs}")
                    else:
                        assert obs.size() == obs.args[1]
                        obs_v = (obs.args[0], obs.args[1])
                    list_obs.append(obs_v)
        state.observations.list_obs.clear()
        return list_obs

    def save_operands(self, state, insn):
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

    def compare_obs(self, obs_base_id):
        obslist1 = self.obs_json[0]
        obslist2 = self.obs_json[1]

        if len(obslist1) != len(obslist2):
            return False

        for obs1,obs2 in zip(obslist1, obslist2):
            if obs1["obs_id"] == obs_base_id and obs2["obs_id"] == obs_base_id:
                assert obs1["obs_cond"] == 1 and obs2["obs_cond"] == 1
                assert len(obs1["obs_list"]) == len(obs2["obs_list"])
                for obss1,obss2 in zip(obs1["obs_list"], obs2["obs_list"]):
                    #print(obss1,obss2)
                    assert obss1[1] == obss2[1]
                    if obss1[0] != obss2[0]:
                        return False
        return True


    def cache_ctrace(self, states_run0, states_run1, exp_typ, do_check=True):
        if self._cache_ctrace is None:
            assert exp_typ == "c"
            self._cache_ctrace = []
            for state in states_run0:
                self._cache_ctrace.append(
                  (state["state_id"], state["instr_address"]))

            if do_check:
                for (i, state) in enumerate(states_run1):
                    iaddr_run1 = state["instr_address"]
                    if iaddr_run1 != self._cache_ctrace[i][1]:
                        raise Exception(f"{iaddr_run1} does not macth with {self._cache_ctrace[i][1]}")

    def trim_trace(self, states):
        if self._cache_ctrace is not None:
            trim_states = []
            for (i, state) in enumerate(states):
                preg_ip = state["registers"][-1]
                assert preg_ip[0] == "ip"
                if preg_ip[1][0] == self._cache_ctrace[i]:
                    trim_states.append(state)
                else:
                    for n in range(i, len(self._cache_ctrace)):
                        trim_states.append({"state_id": n,
                                            "instruction": "empty state",
                                            "instr_address": 0, # no matter
                                            "registers": TraceExporter.EMPTY_REGISTERS,
                                            "memory": {},
                                            "operands": TraceExporter.EMPTY_OPERANDS})
                    return trim_states
            return None
        else:
            raise Exception("No trace cached")

    def align_trace(self, states):
        def empty_state(sid, saddr):
            return {"state_id": sid,
                    "instruction": "empty state",
                    "instr_address": saddr, # no matter, just for a check
                    "registers": TraceExporter.EMPTY_REGISTERS,
                    "memory": {},
                    "operands": TraceExporter.EMPTY_OPERANDS}


        if self._cache_ctrace is not None:

            if ((len(states) == len(self._cache_ctrace)) and
               (all(s["instr_address"] == ca for (s,(_,ca)) in zip(states,self._cache_ctrace)))):
                 return None

            aligned_states = []
            states_iter = iter(states)
            pstate = next(states_iter)
            for (cstate_id, ciaddr) in self._cache_ctrace:
                if pstate is None:
                    aligned_states.append(empty_state(f"{cstate_id}e", ciaddr))
                    continue

                piaddr = pstate["instr_address"]
                if piaddr > ciaddr:
                    aligned_states.append(empty_state(f"{cstate_id}e", ciaddr))
                    continue

                try:
                    #print(piaddr, ciaddr)
                    while piaddr < ciaddr:
                        #print(f"I: {piaddr}-> skip")
                        pstate = next(states_iter)
                        piaddr = pstate["instr_address"]

                    try:
                        if piaddr == ciaddr:
                            aligned_states.append(pstate)
                            pstate = next(states_iter)
                        else:
                            aligned_states.append(empty_state(f"{cstate_id}e", ciaddr))
                    except StopIteration:
                        pstate = None
                except StopIteration:
                    pstate = None
                    if cstate_id == len(self._cache_ctrace)-1:
                        aligned_states.append(empty_state(f"{cstate_id}e", ciaddr))

            assert len(aligned_states) == len(self._cache_ctrace)
            assert all(aligned_states[i]["instr_address"] == self._cache_ctrace[i][1] for i in range(len(self._cache_ctrace)))
            return aligned_states
        else:
            raise Exception("No trace cached")

    def rosette_input(self, exp_id, exp_res, exp_filename):
        if not self.traces_json:
            raise Exception("traces json empty")

        if exp_res == "true":
            exp_typ = "p"
        elif exp_res == "false":
            exp_typ = "c"
        else:
            raise Exception(f"Unexpected experiment result: {exp_res}")
        (states_run0, states_run1) = (self.traces_json[0]["states"], self.traces_json[1]["states"])
        if self.all_p:
            self.cache_ctrace(states_run0, states_run1, exp_typ)

        text_run1 = self.rosette_input_text(states_run0, 0, exp_id, exp_typ)
        text_run2 = self.rosette_input_text(states_run1, 1, exp_id, exp_typ)
        with open(exp_filename, "w") as f:
            f.write(text_run1 + text_run2)

    def rosette_input_text(self, states, run_id, exp_id, exp_typ):
        if self.all_p and exp_typ == "p":
            trimmed_states = self.align_trace(states)
            if trimmed_states is not None:
                #print(f"exp ID trimmed: {exp_id}")
                states = trimmed_states

        state_ids = []
        text = ""
        for state in states:
            state_id_txt = f"{exp_typ}{exp_id}-r{run_id}_{state['state_id']}"
            indentation = ''.join([' ' for _ in range(len(f"(define {state_id_txt} "))])

            text += "\n"
            text += self.instruction_text(state["instruction"], indentation)
            text += f"(define {state_id_txt} (make-run\t ; Registers\n"
            text += self.regs_text(state["registers"], indentation)
            text += self.mem_text(state["memory"], indentation)
            text += self.iaddr_text(state["instr_address"], indentation)
            text += self.obs_operands_text(state["operands"], indentation)
            #text += self.obs_text(state["observations"], indentation)
            text += "))\n"
            state_ids.append(state_id_txt)
        state_ids_txt = " ".join(state_id for state_id in state_ids)
        text += f"\n(define {exp_typ}{exp_id}-r{run_id} (list {state_ids_txt}))\n\n"
        return text

    def instruction_text(self, instr_json, indentation):
        return f"; Instruction: {instr_json}\n"

    def regs_text(self, regs_json, indentation):
        regs = f"{indentation}(vector-immutable\n"
        reg_type = "REG" if self.all_regs else "REGn"
        for reg in regs_json:
            regs += f"{indentation}   ({reg_type} (bv {reg[1][0]} (bitvector {reg[1][1]})))\t; Register: {reg[0]}\n"
        return f"\t{regs}{indentation}   )\n\n"

    def mem_text(self, mem_json, indentation):
        mem = f"{indentation}; Memory\n"
        mem += f"{indentation}  (vector-immutable\n"
        for (addr, val) in mem_json.items():
            mem += f"{indentation}   (MEM (bv {addr} (bitvector {val['size']})) (bv {val['value'][0]} (bitvector {val['value'][1]})))\n"
        return f"\t{mem}{indentation}   )\n\n"

    def iaddr_text(self, iaddr_json, indentation):
        iaddr = f"{indentation}; Instruction Address\n"
        iaddr += f"{indentation}  (bv {iaddr_json} (bitvector 64))\n"
        return f"\t{iaddr}\n"

    def obs_text(self, obs_json, indentation):
        obss = f"{indentation}; Obs\n"
        obss += f"{indentation}  (vector-immutable\n"
        for obs in obs_json:
            obss += f"{indentation}   (bv {obs[0]} (bitvector {obs[1]}))\n"
        return f"\t{obss}{indentation}   )\n"

    def operands_text(self, operands_json, indentation):
        opss = f"{indentation}; Operands\n"
        opss += f"{indentation}  (vector-immutable\n"
        for ops in operands_json:
            opss += f"{indentation}   (OPERAND (bv {ops[1][0]} (bitvector {ops[1][1]})))\t; Operand: {ops[0]}\n"
        return f"\t{opss}{indentation}   )\n"

    def obs_operands_text(self, operands_json, indentation):
        opss = f"{indentation}; Operands\n"
        opss += f"{indentation}  (vector-immutable\n"
        for ops in operands_json:
            opss += f"{indentation}   (OPERAND (bv {ops[0]} (bitvector {ops[1]})))\n"
        return f"\t{opss}{indentation}   )\n"

