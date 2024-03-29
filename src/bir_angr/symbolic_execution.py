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

parser = argparse.ArgumentParser()
parser.add_argument("entryfilename", help="Json entry point", type=str)
parser.add_argument("-ba", "--base_addr", help="The address to place the data in memory (default 0)", default=0, type=int)
parser.add_argument('-es', "--error_states", help="Print error states", default=False, action='store_true')
parser.add_argument('-do', "--debug_out", help="Print a more verbose version of the symbolic execution output", default=False, action='store_true')
parser.add_argument('-di', "--dump_irsb", help="Print VEX blocks", default=False, action='store_true')
parser.add_argument('-n', "--num_steps", help="Number of steps", default=None, type=int)
parser.add_argument('-dc', "--data_constraints", help="Add data section constraints to states ", default=False, action='store_true')
args = parser.parse_args()



def change_simplification():
    from bir_angr.utils.simplification_manager_bir import SimplificationManagerBIR
    claripy.simplifications.simpleton = SimplificationManagerBIR()


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


def set_registers(birprog):
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
            sz = 8
        setattr(state.regs, reg["name"], claripy.BVS(reg["name"], sz))
        

def set_state_options(state):
    state.options.add(angr.options.LAZY_SOLVES) # Don't check satisfiability until absolutely necessary
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
    if args.data_constraints:
        data_constraints = extract_data_constraints(binfile)

    # extracts the registers from the input program and sets them in the register list of the architecture
    regs = set_registers(birprogjson)

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

    # sets the initial state and registers
    state = proj.factory.entry_state(addr=entry_addr, remove_options=angr.options.simplification)
    init_regs(state, regs)
    set_state_options(state)

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
                        assert any(jc.structurally_match(fc) for jc in jg_constraints for fc in failed_state.solver.constraints)

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

