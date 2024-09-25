import sys
import argparse
import json
import multiprocessing

import angr
import bir_angr.bir
import claripy
from bir_angr.utils.own_claripy_printer import own_bv_str
from bir_angr.utils.data_section_parser import *
from bir_angr.bir.concretization_strategy_bir import *
from bir_angr.local_loop_seer_bir import LocalLoopSeerBIR
from bir_angr.shadow_object import ShadowObject
from bir_angr.trace_exporter import get_input_state, TraceExporter, REGISTERS
from bir_angr.default_filler_memory import *

parser = argparse.ArgumentParser()
parser.add_argument("entryfilename", help="Json entry point", type=str)
parser.add_argument("-ba", "--base_addr", help="The address to place the data in memory (default 0)", default=0, type=int)
parser.add_argument('-es', "--error_states", help="Print error states", default=False, action='store_true')
parser.add_argument('-do', "--debug_out", help="Print a more verbose version of the symbolic execution output", default=False, action='store_true')
parser.add_argument('-di', "--dump_irsb", help="Print VEX blocks", default=False, action='store_true')
parser.add_argument('-n', "--num_steps", help="Number of steps", default=None, type=int)
parser.add_argument('-dc', "--data_constraints", help="Add data section constraints to states ", default=False, action='store_true')
parser.add_argument('-ce', "--conc_execution", help="Execute a program from two initial states", default=False, action='store_true')
parser.add_argument('-et', "--extract_traces", help="Extract traces", default=False, action='store_true')
parser.add_argument('-eop', "--extract_operands", help="Extract operands", default=False, action='store_true')
parser.add_argument('-cobs', "--compare_obs", help="Compare observations", default=False, action='store_true')
parser.add_argument('-cobs_s', "--compare_obs_short", help="Compare observations and stop at the first true", default=False, action='store_true')
args = parser.parse_args()



def change_simplification():
    from bir_angr.utils.simplification_manager_bir import SimplificationManagerBIR
    claripy.simplifications.simpleton = SimplificationManagerBIR()


def set_mem_and_regs(state, input_data):
    def set_mem(state, mem_map):
        def_val = mem_map.pop("default")
        if def_val != 0:
            state.options.remove(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
            state.options.add(DEFVAL_FILL_UNCONSTRAINED_MEMORY)
            assert 0 <= def_val <= 255
            state.memory._defval = def_val

        if len(mem_map) != 0:
            for (addr,val) in mem_map.items():
                state.mem[addr].uint8_t = val

    #print(dir(state.regs))
    for (k, v) in input_data.items():
        if k[0] == "x":
            reg_num = k[1:]
            try:
                setattr(state.regs, "R" + reg_num, v)
            except Exception:
                raise Exception(f"Register {'R' + reg_num} not found in the state")
        elif k == "sp":
            try:
                state.regs.SP_EL0 = v
            except Exception:
                raise Exception(f"Register SP_EL0 not found in the state")
        elif k.startswith("ProcState_") and (k[-1] in ["C", "N", "V", "Z"]):
            try:
                setattr(state.regs, k, v)
            except Exception:
                raise Exception(f"Register {k} not found in the state")
        elif k == "mem":
            set_mem(state, v)
        else:
            raise Exception("Unknown input data", k)


def conc_exec(proj, input_state, regs, entry_addr, exit_addrs, insns, trace_exporter):
    input_state_data, input_state_id = input_state
    if not hex(entry_addr).startswith("0x4"):
        raise Exception("Unexpected entry address: ", entry_addr)
    addr_start_hex = hex(entry_addr)[:3]

    state = proj.factory.entry_state(addr=entry_addr,
                                     remove_options=angr.options.simplification,
                                     plugins={"memory": DefaultMemoryFiller(cle_memory_backer=proj.loader, memory_id='mem')})

    set_state_options(state)
    set_mem_and_regs(state, input_state_data)

    state.inspect.b('reg_write', when=angr.BP_AFTER, action=observe)
    # is this needed?
    state.inspect.b('mem_read', when=angr.BP_AFTER, action=mem_read_after)
    state.inspect.b('exit', condition=(lambda state: any(state.addr==exit for exit in exit_addrs)), action=find_exit)
    add_bir_concretization_strategy(state, proj.loader.all_objects, None, [])

    simgr = proj.factory.simulation_manager(state)

    if args.extract_traces:
        trace_exporter.init_trace(input_state_id)
    while len(simgr.active) > 0:
        if args.extract_traces and len(simgr.active) == 1:
            current_state = simgr.active[0]

            if hex(current_state.addr).startswith(addr_start_hex):
                insn = next((i for i in insns if i.addr == current_state.addr), None)
                if insn is None:
                    break

                trace_exporter.save_trace(input_state_id, current_state, insn)

        elif len(simgr.active) > 1:
            raise Exception("Unexpected states: ", simgr)

        # move forward
        simgr.step(n=args.num_steps, avoid=exit_addrs)

        if args.extract_operands:
            # Note: this code works since COPY_STATES is disabled and the same current state is always updated after stepping
            addr_history = current_state.history.bbl_addrs.hardcopy
            insn_addr = next((addr for addr in reversed(addr_history) if hex(addr).startswith(addr_start_hex)), None)
            insn = next((i for i in insns if i.addr == insn_addr), None)
            if insn is None:
                raise Exception(f"Instruction not found: {hex(insn_addr)}")

            trace_exporter.add_operands_to_trace(input_state_id, current_state)

    if args.compare_obs:
        if len(simgr.active) == 0 and len(simgr.deadended) == 1:
            trace_exporter.save_obs(input_state_id, simgr.deadended[0])
    #print(json.dumps(trace_exporter.traces_json, indent=4))
    return


def observe(state):
    if isinstance(state.inspect.reg_write_offset, claripy.ast.BV):
        if (state.inspect.reg_write_offset.args[0] == 8): # 'obs' reg
            #print(f"Observation: {state.inspect.reg_write_expr}")
            state.observations.accumulate.append(state.inspect.reg_write_expr)

        elif (state.inspect.reg_write_offset.args[0] == 24): # 'idx_obs' reg
            #print("Saving Observation")

            obss = state.observations.accumulate.list_obs.copy()
            cond_obs = state.regs.cond_obs[0]
            idx_cond_obss = (state.regs.idx_obs.args[0], cond_obs, obss, None)
            state.observations.append(idx_cond_obss)
            state.observations.accumulate.list_obs.clear()
            #state.regs.cond_obs = 0


def disassemble_prog(binary):
    from angr.analyses import Disassembly
    from angr.analyses.disassembly import Instruction

    p = angr.Project(binary, load_options={'auto_load_libs': False})
    disasm = p.analyses[Disassembly].prep()(ranges=[(p.loader.main_object.min_addr, p.loader.main_object.max_addr+1)])
    insns = [r for r in disasm.raw_result if isinstance(r, Instruction)]
    return insns


def extract_data_constraints(binfile, dump_data=False, dump_constraints=False):
    dsp = DataSectionParser(binfile)
    if dump_data:
        print()
        print(json.dumps(dsp.data_map, indent=4))
    if dump_constraints:
        print(*dsp.data_constraints, sep="\n")
    return dsp.data_constraints


def find_loops(proj):
    from angr.analyses.cfg import cfg_fast
    cfg_fast.VEX_IRSB_MAX_SIZE = sys.maxsize

    #regions=[(proj.loader.main_object.min_addr,4197800+0x4)]
    cfg = proj.analyses.CFGFast(normalize=True, resolve_indirect_jumps=False)
    #cfg = proj.analyses.CFGEmulated(keep_state=True, resolve_indirect_jumps=False, normalize=True)
    loop_finder = proj.analyses.LoopFinder()

    return (cfg, loop_finder.loops)


def set_registers(all_regs, birprog):
    if args.conc_execution and all_regs:
        bir_angr.bir.arch_bir.config_regs(REGISTERS)
        regs = None
    else:
        # extracts the registers from the input program and sets them in the register list of the architecture
        regs = bir_angr.bir.arch_bir.get_register_list(birprog)
    return regs


def init_regs(state, regs):
    for reg in regs:
        if reg["type"] == "imm64":
            sz = 64
        elif reg["type"] == "imm32":
            sz = 32
        elif reg["type"] == "imm16":
            sz = 16
        elif reg["type"] == "imm8":
            sz = 8
        elif reg["type"] == "imm1":
            sz = 1
        setattr(state.regs, reg["name"], claripy.BVS(reg["name"], sz))


def set_state_options(state):
    state.options.add(angr.options.LAZY_SOLVES) # Don't check satisfiability until absolutely necessary
    if args.conc_execution:
        state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
        state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
        state.options.remove(angr.options.COPY_STATES)
    else:
        state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
        state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)

    # try to avoid nondeterministic behavior
    state.options.remove(angr.options.COMPOSITE_SOLVER)
    state.options.add(angr.options.CACHELESS_SOLVER)
    #state.options.add(angr.options.DOWNSIZE_Z3)
    #state.options.add(angr.options.CONSTRAINT_TRACKING_IN_SOLVER)
    #print(state.options.tally())


def find_exit(state):
	#print("\n EXIT")
	#print(hex(state.addr))
	#print(state.inspect.exit_jumpkind)
	if not state.inspect.exit_jumpkind == 'Ijk_Sys_syscall':
		state.inspect.exit_jumpkind = 'Ijk_Exit'
	state.inspect.exit_jumpkind = 'Ijk_Exit'


def debug_addr(state):
    print()
    print("debug_addr")
    print(state)
    #print(state.mem[(state.regs.SP_EL0+96)].uint64_t)


def check_collision_with_concretization(mem_addr, track_concretization_values):
    if isinstance(mem_addr, int) or mem_addr.op=="BVV":
        for expr in track_concretization_values:
            if mem_addr.args[0] == expr.args[1].args[0]:
                raise ConcretizationException("collision of memory read at %s." % mem_addr, [expr])


def mem_write_before(state):
    check_collision_with_concretization(state.inspect.mem_write_address, state.concretizations.track_values)


def mem_read_after_approx(state):
    #print("\nREAD APPROX")
    #print(state.inspect.mem_read_address)
    #print(state.inspect.mem_read_expr)

    mem_addr_arg = state.inspect.mem_read_address.__repr__(inner=True)
    for expr, val in track_concretization_values:
        if mem_addr_arg == hex(val):
            raise ValueError(expr, val)

    mem_expr_arg = state.inspect.mem_read_expr.__repr__(inner=True)
    if state.inspect.mem_read_expr.symbolic and mem_expr_arg.count("mem_"):
        mem_addr = state.inspect.mem_read_address
        mem_val = state.inspect.mem_read_expr
        mem_var = claripy.BVS(f"MEM[{mem_addr}]", state.inspect.mem_read_expr.length)
        mem_expr = mem_var == mem_val
        state.add_constraints(mem_expr)
        state.inspect.mem_read_expr = mem_var
    #print(state.inspect.mem_read_expr)


def mem_read_after(state):
    #print("\nREAD")
    #print("IP:", state.ip)
    #print(state.inspect.mem_read_address)
    #print(state.inspect.mem_read_expr)
    #check_collision_with_concretization(state.inspect.mem_read_address, state.concretizations.track_values)


    if state.inspect.mem_read_expr.symbolic and state.inspect.mem_read_expr.uninitialized:
        mem_addr = own_bv_str(state.inspect.mem_read_address)
        mem_ast_set = set()

        if state.inspect.mem_read_expr.op == "BVS" and state.inspect.mem_read_expr.args[0].startswith("mem_"):
            mem_ast_set.add(state.inspect.mem_read_expr)
        else:
            iterator_ast = state.inspect.mem_read_expr.children_asts()
            while True:
                try:
                    subast = iterator_ast.__next__()
                except StopIteration:
                    break
                else:
                    if subast.op == "BVS" and subast.args[0].startswith("mem_"):
                        mem_ast_set.add(subast)

        for mem_ast in mem_ast_set:
            if not mem_ast.cache_key in state.concretizations.replacements:
                mem_var = claripy.BVS(f"MEM[{mem_addr}]_0_{mem_ast.length}", mem_ast.length, explicit_name=True)
                state.concretizations.replacements[mem_ast.cache_key] = mem_var
                mem_expr_constraint = mem_var == mem_ast
                state.add_constraints(mem_expr_constraint)
                # adds the non-repetition constraint in the concretization strategy
                if state.inspect.mem_read_address.op == "BVV":
                    state.memory.read_strategies[0]._repeat_constraints.extend(
                        [paddr.args[0] != state.inspect.mem_read_address for paddr in state.concretizations.track_values]
                    )

        state.inspect.mem_read_expr = state.inspect.mem_read_expr.replace_dict(state.concretizations.replacements)

    #print(state.inspect.mem_read_expr)
    #print()


def add_bir_concretization_strategy(state, loader_objects, new_choices, extra_concretization_constraints):
    state.memory.read_strategies.clear()
    state.memory.write_strategies.clear()
    repeat_expr = claripy.BVS("REPEAT", 64)
    addr_ranges = [(o.min_addr, o.max_addr) for o in loader_objects]

    bir_concr_strategy = SimConcretizationStrategyBIR(addr_ranges=addr_ranges, repeat_expr=repeat_expr, recent_track_values=new_choices)
    state.memory.read_strategies.insert(0, bir_concr_strategy)
    state.memory.write_strategies.insert(0, bir_concr_strategy)


def print_results(simgr_states, errored_states, assert_addr, fail_assert_states, extra_concretization_constraints, dump_json=True):
    def get_addr(s):
        try:
            if s.addr == assert_addr:
                addr = "Assert failed"
            else:
                addr = hex(s.addr)
        except:
            addr = own_bv_str(s.regs.ip)
            #addr = (s.regs.ip).__repr__(inner=True)
        return addr

    print()
    print("I - RESULT final states:")

    output = []
    dict_state = {}
    for name, final_states in simgr_states:
        print("-"*80)
        print(len(final_states), name)
        for state in final_states:
            state_addr = get_addr(state)
            print("="*80)
            print("STATE:", state, f"------> {state_addr}" if state_addr=="Assert failed" else "")

            # is a listing of the basic block addresses executed by the state.
            list_addrs = state.history.bbl_addrs.hardcopy
            # converts addresses from decimal to hex
            list_addrs = list(map(lambda value: hex(value) if value != assert_addr else "Assert failed", list_addrs))
            list_constraints = [own_bv_str(c) for c in filtering_constraints(state.solver.constraints, state.concretizations.track_values)]
            list_obs = [(idx, own_bv_str(cond), [own_bv_str(obs) for obs in obss]) for (idx, cond, obss, is_shadow) in state.observations.list_obs]
            if args.debug_out:
                print("\t- Path:", ''.join("\n\t\t{0}".format(addr) for addr in list_addrs))
                print("\t- Guards:", ''.join("\n\t\t{0}".format(str(g)) for g in state.history.jump_guards.hardcopy))
                print("\t- State Constraints:", ''.join("\n\t\t\t{0}".format(str(sc)) for sc in state.solver.constraints))
                print("\t- Satisfiable:", ''.join("\n\t\t\t{0}".format(state.satisfiable())))
                print("\t- Concretizations:", ''.join("\n\t\t\t{0}".format(str(val)) for val in state.concretizations.track_values))
                print("\t- Symbolic values:", ''.join("\n\t\t\t{0} => {1}".format(str(k),str(v)) for k,v in state.concretizations.replacements.items()))
                print("\t- Path Constraints:\t", ''.join("\n\t\t\t{0}".format(c) for c in list_constraints))
                print("\t- Observations:\t\t", ''.join("\n\t\t\t{0}".format(o) for o in list_obs))
                print("="*80)

            # append to dictionary for json output
            if state_addr == "Assert failed":
                continue
            elif name == "pruned":
                continue
            #elif not state.satisfiable():
            #    continue
            else:
                dict_state["addr"] = state_addr
                dict_state["path"] = list_addrs
                dict_state["constraints"] = list_constraints
                dict_state["observations"] = list_obs
                output.append(dict_state.copy())
    print("-"*80)
    print(f"{len(fail_assert_states)} Failed Assertion States at {hex(assert_addr)}.")
    if args.error_states:
        print("-"*80)
        print(f"{len(errored_states)} ERRORED STATES:")
        print(*errored_states, sep="\n")
    if dump_json:
        # in the end, prints the json output
        json_object = json.dumps(output, indent=4)
        print(("="*10) + " JSON START " + ("="*10))
        print(json_object)



def run():
    # handles some zeroexts unsupported by bir
    if True: change_simplification()

    with open(args.entryfilename, "r") as entry_json:
        entry = json.load(entry_json)

    # binary program to be loaded into memory
    binfile = entry["bin"]
    # sends the bir program in json format to the lifter
    birprogjson = entry["birprogram"]
    entry_addr = entry["entry"]
    exit_addrs = entry["exits"]

    data_constraints = None
    if args.data_constraints and not args.compare_obs_short: # FIXME: temporary fix
        data_constraints = extract_data_constraints(binfile)

    all_regs = True
    # sets them in the register list of the architecture
    regs = set_registers(all_regs, birprogjson)

    # initializes the angr project
    proj = angr.Project(binfile, main_opts={'backend': 'bir'}, load_options={'auto_load_libs': False})

    # shadow memory space object
    _shadow_object = ShadowObject(proj.loader)
    proj.loader._internal_load(_shadow_object)

    # sets addresses for assertion and observations in the kernel region
    extern_addr = proj.loader.kernel_object.min_addr+0x14
    # sets addresses for shadow instructions in an external region
    shadow_addr = _shadow_object.min_addr - proj.loader.main_object.min_addr
    bir_angr.bir.lift_bir.set_extern_val(extern_addr, shadow_addr, args.dump_irsb, birprogjson)

    if args.conc_execution:
        exps = entry["experiments"]
        insns = None
        if args.extract_traces:
            insns = disassemble_prog(binfile)
        if args.extract_operands and (not args.extract_traces):
            raise Exception("trace exporter disabled, operands cannot be exported")
        if args.compare_obs_short and (not args.compare_obs):
            raise Exception("compare_obs must be enabled to use compare_obs_short")

        target_obsoperandid = "2"
        obs_operand_id = int(next((k for (k,v) in entry["obsrefmap"].items() if v["obsid"] == target_obsoperandid), None))

        if args.compare_obs:
            count_obs_eq = {True: [], False: []}
            obs_base_id = int(next((k for (k,v) in entry["obsrefmap"].items() if v["obsid"] == "0"), None))

        texporter = TraceExporter(regs=entry.get("registers", None),
                                  extract_operands=args.extract_operands,
                                  obs_operand_id=obs_operand_id,
                                  all_p = True)
        for exp in exps:
            (input1, input2) = (get_input_state(exp, "input_1"), get_input_state(exp, "input_2"))
            assert (input1 and input2) is not None

            texporter.obs_json = {}
            texporter.traces_json = {}
            conc_exec(proj, (input1, 0), regs, entry_addr, exit_addrs, insns, texporter)
            conc_exec(proj, (input2, 1), regs, entry_addr, exit_addrs, insns, texporter)
            if args.extract_traces:
                if False: print(json.dumps(texporter.traces_json, indent=4))
                texporter.rosette_input(exp["id"], exp["result"], exp["filename"])

            if args.compare_obs:
                if False: print(json.dumps(texporter.obs_json, indent=4))
                res = texporter.compare_obs(obs_base_id)
                count_obs_eq[res].append(exp["id"])
                if res is True and args.compare_obs_short:
                    break
        if args.compare_obs:
            print(count_obs_eq)
        return

    # sets the initial state and registers
    state = proj.factory.entry_state(addr=entry_addr, remove_options=angr.options.simplification)
    init_regs(state, regs)
    set_state_options(state)

    # breakpoint for observations instead of system calls
    state.inspect.b('reg_write', when=angr.BP_AFTER, action=observe)
    # breakpoint that hooks the 'mem_read' event to change the resulting symbolic values
    state.inspect.b('mem_read', when=angr.BP_AFTER, action=mem_read_after)
    #proj.hook(extern_addr, debug_addr)
    #state.inspect.b('mem_write', when=angr.BP_BEFORE, action=mem_write_before)
    #state.inspect.b('exit', condition=(lambda state: any(state.addr==exit for exit in exit_addrs)), action=find_exit)

    #cfg, loops = find_loops(proj)

    # gets the system call addresses to be ignored into loop cutting
    n_syscalls = len(proj.simos.syscall_library.syscall_number_mapping['BIR'])
    syscall_addrs = [proj.loader.kernel_object.min_addr + (i*4) for i in range(n_syscalls)]

    extra_concretization_constraints = []
    new_concretizations = None
    print("I - angr Symbolic Execution")

    # adds a concretization strategy with some constraints for a bir program
    add_bir_concretization_strategy(state, proj.loader.all_objects, new_concretizations, extra_concretization_constraints)
    #state.concretizations.replacements.clear()

    # executes the symbolic execution and prints the results
    simgr = proj.factory.simulation_manager(state)

    # loop handling based on cfg
    #if len(loops) > 0:
    #    simgr.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg, functions=None, loops=loops, bound=1))
    #simgr.use_technique(LocalLoopSeerBIR(bound=1, syscall_addrs=syscall_addrs))

    while True:
        try:
            simgr.explore(n=args.num_steps, avoid=exit_addrs)
            #simgr.run(n=args.num_steps, until=(lambda s: not any(s.addr != exit for s in simgr.active for exit in exit_addrs)))
            simgr.move(from_stash='deadended', to_stash='assertionfailed', filter_func=lambda s: s.addr == extern_addr)
            simgr_states = [(name, ls) for name, ls in simgr._stashes.items() if len(ls) != 0 and name != 'errored' and name != 'assertionfailed']

            if data_constraints:
                for st in simgr.avoid:
                    st.add_constraints(*data_constraints)
            print_results(simgr_states, simgr.errored, extern_addr, simgr.assertionfailed, extra_concretization_constraints)
        except ConcretizationException as e:
            new_concretizations = e.new_solutions
            jg_constraints = [c for c in e.failed_state.history.jump_guards.hardcopy if not (c != e.failed_state.solver.true).is_false()]
            #print(*jg_constraints, sep='\n')
            
            for sa in simgr.active:
                if e.failed_state.history.bbl_addrs.hardcopy == sa.history.bbl_addrs.hardcopy + [sa.ip.args[0]]:
                    failed_state = sa
                    simgr.active.remove(failed_state)
                    # TODO: make sure it is the one that fails, is this enough?
                    if jg_constraints != []:
                        # constraints in failed_state.solver.constraints can be split,
                        # better to use failed_state.history.jump_guards.hardcopy to compare
                        assert any(jc.structurally_match(fc) for jc in jg_constraints for fc in failed_state.history.jump_guards.hardcopy)

            initial_state = state.copy()
            initial_state.add_constraints(*jg_constraints)
            initial_state.concretizations.extend(new_concretizations)
            simgr.active.append(initial_state)
            print(e)
            print("Restarting symbolic execution with new concretizations...\n")
        else:
            break



def main():
    thread = multiprocessing.Process(target=run)
    thread.start()
    thread.join(1200)
    if thread.is_alive():
        thread.terminate()
        print("angr symbolic execution timed out!")




if __name__ == '__main__':
    main()

