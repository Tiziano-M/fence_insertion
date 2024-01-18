import angr

  

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

def save_trace(jsonout, run_id, state_id, state, regs):
    dict_state = {}
    dict_state["state_id"] = state_id
    dict_state["registers"] = save_regs(state, regs)
    dict_state["memory"] = save_mem(state)
    dict_state["observations"] = save_obs(state)
    jsonout[run_id]["states"].append(dict_state.copy())
    return jsonout

def save_regs(state, regs):
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
            raise Exception(f"Register {reg_n} not found in the state")
    return list_regs

def save_mem(state):
    default_mem = 0
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

def rosette_input(json_out):
    filename = "input.rkt"
    text_run1 = rosette_input_text(json_out[0]["states"], 0)
    text_run2 = rosette_input_text(json_out[1]["states"], 1)
    with open(filename, "w") as f:   
        f.write(text_run1 + text_run2)

def rosette_input_text(states, run_id):
    state_ids = []
    text = ""
    for state in states:
        state_id_txt = f"r{run_id}_{state['state_id']}"
        text += f"\n(define {state_id_txt} (make-run\t ; Registers\n"
        indentation = ''.join([' ' for _ in range(len(f"(define {state_id_txt} "))])
        text += regs_text(state["registers"], indentation)
        #text += mem_text(state["memory"], indentation)
        text += obs_text(state["observations"], indentation)
        text += ")\n"
        state_ids.append(state_id_txt)
    state_ids_txt = " ".join(state_id for state_id in state_ids)
    text += f"\n(define r{run_id} (list {state_ids_txt}))\n\n"
    return text

def regs_text(regs_json, indentation):
    regs = f"{indentation}(list\n"
    for reg in regs_json:
        regs += f"{indentation}   (REG (cons {reg[0]} (bv {reg[1][0]} (bitvector {reg[1][1]}))))\n"
    return f"\t{regs}{indentation}   )\n\n"

def mem_text(mem_json, indentation):
    pass

def obs_text(obs_json, indentation):
    obss = f"{indentation}; Obs\n"
    obss += f"{indentation}  (list\n"
    for obs in obs_json:
        obss += f"{indentation}   (bv {obs[0]} (bitvector {obs[1]})\n"
    return f"\t{obss}{indentation}   )\n\n"

