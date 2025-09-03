import angr
import json


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
FLAG_REGS = {"ProcState_C", "ProcState_N", "ProcState_V", "ProcState_Z"}

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



class TraceCollector:

    def __init__(self):
        self.collected_traces = []

    def add_trace(self, trace_exporter, exp_id, exp_res):

        exp_typ = trace_exporter.get_trace_type(exp_res)

        states_run0, states_run1 = trace_exporter.process_and_get_states(exp_typ)
        trace_exporter.traces_json[0]["states"] = states_run0
        trace_exporter.traces_json[1]["states"] = states_run1

        wrapped_data = {
            "id" : exp_id, 
            "result" : exp_res, 
            "traces" : trace_exporter.traces_json
            }

        self.collected_traces.append(wrapped_data)

    def export_to_file(self, filename):
        with open(filename, "w") as json_file:
            json.dump(self.collected_traces, json_file, indent=4)


class TraceExporter:

    def __init__(self,
                 regs,
                 extract_operands,
                 obs_operand_id,
                 obs_post_operand_id,
                 traces_json=None,
                 obs_json=None,
                 ctrace=None,
                 all_p = False,
                 use_com = False,
                 bitwidth = 64
                 ):

        if regs is not None:
            self.regs = regs + [{"name": "ip", "type": "imm64"}]
            self.all_regs = False
        else:
            self.regs = REGISTERS
            self.all_regs = True

        self.traces_json = traces_json if traces_json is not None else {}
        self.obs_json = obs_json if obs_json is not None else {}
        self.state_id = None
        self.extract_operands = extract_operands
        self.obs_operand_id = obs_operand_id
        self.obs_post_operand_id = obs_post_operand_id
        self._cache_ctrace = ctrace
        self.all_p = all_p
        self.use_com = use_com
        self.bitwidth = bitwidth
        self.empty_registers = [(reg["name"], (0, REGISTER_TYPES[reg["type"]])) for reg in REGISTERS]
        self.empty_operands = [(0, self.bitwidth)] * 6
        self.empty_post_operands = [(0, self.bitwidth)] * 2

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
        dict_state["operands"] = []
        dict_state["post_operands"] = []

        self.traces_json[run_id]["states"].append(dict_state)
        self.state_id += 1

    def add_operands_to_trace(self, run_id, state):
        ops = self.save_obs_operands(state, self.obs_operand_id)
        self.traces_json[run_id]["states"][-1]["operands"].extend(ops)

        if self.use_com and self.obs_post_operand_id is not None:
            post_ops = self.save_obs_operands(state, self.obs_post_operand_id)
            self.traces_json[run_id]["states"][-1]["post_operands"].extend(post_ops)

        state.observations.list_obs.clear()
        return

    def save_regs(self, state):
        list_regs = []
        for reg in self.regs:
            reg_n = reg["name"]
            try:
                val = getattr(state.regs, reg_n)
                if val.symbolic:
                    raise Exception(f"Register value not as expected: {val}")
                else:
                    assert val.size() == val.args[1]
                    reg_v = (val.args[0], val.args[1])
                list_regs.append((reg_n, reg_v))
            except Exception:
                if self.all_regs:
                    list_regs.append((reg["name"], ((0, REGISTER_TYPES[reg["type"]]))))
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
                    raise Exception(f"Observation value not as expected: {obs}")
                else:
                    assert obs.size() == obs.args[1]
                    obs_v = (obs.args[0], obs.args[1])
                obsjson["obs_list"].append(obs_v)
            self.obs_json[run_id].append(obsjson)
        return self.obs_json[run_id]

    def save_obs_operands(self, state, obs_operand_id):
        list_obs = []
        for (obs_id,_,obs_list,_) in state.observations.list_obs:
            if obs_id == obs_operand_id:
                for obs in obs_list:
                    if obs.symbolic:
                        raise Exception(f"Observation value not as expected: {obs}")
                    else:
                        assert obs.size() == obs.args[1]
                        obs_v = (obs.args[0], obs.args[1])
                    list_obs.append(obs_v)
        return list_obs


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

    def empty_state(self, sid, saddr):
        state = { "state_id": sid,
                  "instruction": "empty state",
                  "instr_address": saddr, # no matter, just for a check
                  "registers": self.empty_registers,
                  "memory": {},
                  "operands": self.empty_operands
                }

        if self.use_com:
            state["post_operands"] = self.empty_post_operands

        return state

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
                        trim_states.append(self.empty_state(n, 0))
                    return trim_states
            return None
        else:
            raise Exception("No trace cached")

    def align_trace(self, states):
        if self._cache_ctrace is None:
            raise Exception("No trace cached")

        if ((len(states) == len(self._cache_ctrace)) and
           (all(s["instr_address"] == ca for (s,(_,ca)) in zip(states,self._cache_ctrace)))):
            return None

        aligned_states = []
        states_iter = iter(states)
        pstate = next(states_iter)
        for (cstate_id, ciaddr) in self._cache_ctrace:
            if pstate is None:
                aligned_states.append(self.empty_state(f"{cstate_id}e", ciaddr))
                continue

            piaddr = pstate["instr_address"]
            if piaddr > ciaddr:
                aligned_states.append(self.empty_state(f"{cstate_id}e", ciaddr))
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
                        aligned_states.append(self.empty_state(f"{cstate_id}e", ciaddr))
                except StopIteration:
                    pstate = None
            except StopIteration:
                pstate = None
                if cstate_id == len(self._cache_ctrace)-1:
                    aligned_states.append(self.empty_state(f"{cstate_id}e", ciaddr))

        assert len(aligned_states) == len(self._cache_ctrace)
        assert all(aligned_states[i]["instr_address"] == self._cache_ctrace[i][1] for i in range(len(self._cache_ctrace)))
        return aligned_states


    def process_and_get_states(self, exp_typ):
        if not self.traces_json or len(self.traces_json) < 2:
            raise ValueError("traces JSON must contain at least two runs")

        states_run0 = self.traces_json[0]["states"]
        states_run1 = self.traces_json[1]["states"]

        if self.all_p:
            self.cache_ctrace(states_run0, states_run1, exp_typ)

            if exp_typ == "p":
                aligned_states0 = self.align_trace(states_run0)
                aligned_states1 = self.align_trace(states_run1)

                if aligned_states0 is not None:
                    states_run0 = aligned_states0
                if aligned_states1 is not None:
                    states_run1 = aligned_states1

        return states_run0, states_run1

    @staticmethod
    def get_trace_type(exp_res):
        if exp_res == "true":
            return "p"
        elif exp_res == "false":
            return "c"
        else:
            raise ValueError(f"Unexpected experiment result: {exp_res}")

    def rosette_input(self, exp_id, exp_res, exp_filename):
        exp_typ = self.get_trace_type(exp_res)

        states_run0, states_run1 = self.process_and_get_states(exp_typ)

        text_run1 = self.rosette_input_text(states_run0, 0, exp_id, exp_typ)
        text_run2 = self.rosette_input_text(states_run1, 1, exp_id, exp_typ)

        with open(exp_filename, "w") as f:
            f.write(text_run1 + text_run2)

    def rosette_input_text(self, states, run_id, exp_id, exp_typ):
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

            if self.use_com:
                text += self.obs_post_operands_text(state["post_operands"], indentation)
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
        for (name, (val, sz)) in regs_json:
            if not name in FLAG_REGS:
                assert sz == self.bitwidth
            regs += f"{indentation}   ({reg_type} (bv {val} (bitvector {self.bitwidth})))\t; Register: {name}\n"
        return f"\t{regs}{indentation}   )\n\n"

    def mem_text(self, mem_json, indentation):
        mem = f"{indentation}; Memory\n"
        mem += f"{indentation}  (vector-immutable\n"
        for (addr, val) in mem_json.items():
            mem += f"{indentation}   (MEM (bv {addr} (bitvector {val['size']})) (bv {val['value'][0]} (bitvector {val['value'][1]})))\n"
        return f"\t{mem}{indentation}   )\n\n"

    def iaddr_text(self, iaddr_json, indentation):
        iaddr = f"{indentation}; Instruction Address\n"
        iaddr += f"{indentation}  (bv {iaddr_json} (bitvector {self.bitwidth}))\n"
        return f"\t{iaddr}\n"

    def obs_text(self, obs_json, indentation):
        obss = f"{indentation}; Obs\n"
        obss += f"{indentation}  (vector-immutable\n"
        for (val, sz) in obs_json:
            assert sz == self.bitwidth
            obss += f"{indentation}   (bv {val} (bitvector {self.bitwidth}))\n"
        return f"\t{obss}{indentation}   )\n"

    def operands_text(self, operands_json, indentation):
        opss = f"{indentation}; Operands\n"
        opss += f"{indentation}  (vector-immutable\n"
        for (name, (val, sz)) in operands_json:
            assert sz == self.bitwidth
            opss += f"{indentation}   (OPERAND (bv {val} (bitvector {self.bitwidth})))\t; Operand: {name}\n"
        return f"\t{opss}{indentation}   )\n"

    def obs_operands_text(self, operands_json, indentation):
        opss = f"{indentation}; Operands\n"
        opss += f"{indentation}  (vector-immutable\n"
        for (val, sz) in operands_json:
            assert sz == self.bitwidth
            opss += f"{indentation}   (OPERAND (bv {val} (bitvector {self.bitwidth})))\n"
        return f"\t{opss}{indentation}   )\n\n"

    def obs_post_operands_text(self, post_operands_json, indentation):
        opss = f"{indentation}; Post-Operands\n"
        opss += f"{indentation}  (vector-immutable\n"
        for (val, sz) in post_operands_json:
            assert sz == self.bitwidth
            opss += f"{indentation}   (POST-OPERAND (bv {val} (bitvector {self.bitwidth})))\n"
        return f"\t{opss}{indentation}   )\n"

