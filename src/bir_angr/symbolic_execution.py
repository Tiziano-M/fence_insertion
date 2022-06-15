import sys
import argparse
import json

import angr
import bir_angr.bir
import claripy
from bir_angr.utils.own_claripy_printer import own_bv_str
from bir_angr.bir.concretization_strategy_bir import SimConcretizationStrategyBIR, ConcretizationException
import itertools

parser = argparse.ArgumentParser()
parser.add_argument("entryfilename", help="Json entry point", type=str)
parser.add_argument("-ba", "--base_addr", help="The address to place the data in memory (default 0)", default=0, type=int)
parser.add_argument('-es', "--error_states", help="Print error states", default=False, action='store_true')
parser.add_argument('-do', "--debug_out", help="Print a more verbose version of the symbolic execution output", default=False, action='store_true')
parser.add_argument('-di', "--dump_irsb", help="Print VEX blocks", default=False, action='store_true')
parser.add_argument('-n', "--num_steps", help="Number of steps", default=None, type=int)
args = parser.parse_args()


# maps memory read values for replacement
replacements = {}





def change_simplification():
    from bir_angr.utils.simplification_manager_bir import SimplificationManagerBIR
    claripy.simplifications.simpleton = SimplificationManagerBIR()


def set_cfg(proj):
    from angr.analyses.cfg import cfg_fast
    cfg_fast.VEX_IRSB_MAX_SIZE = sys.maxsize

    #regions=[(proj.loader.main_object.min_addr,4197800+0x4)]
    cfg = proj.analyses.CFGFast(normalize=True, function_starts=[proj.loader.main_object.min_addr])
    return cfg


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
        

def add_state_options(state):
    state.options.add(angr.options.LAZY_SOLVES) # Don't check satisfiability until absolutely necessary
    state.options.add(angr.options.CONSERVATIVE_READ_STRATEGY)
    state.options.add(angr.options.CONSERVATIVE_WRITE_STRATEGY)
    state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
    state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
    #state.options.add(angr.options.CONSTRAINT_TRACKING_IN_SOLVER)
    #print(state.options.tally())


def check_collision_with_concretization(mem_addr, track_concretization_values):
    if isinstance(mem_addr, int) or mem_addr.op=="BVV":
        for expr in track_concretization_values:
            if mem_addr.args[0] == expr.args[1].args[0]:
                raise ConcretizationException("collision of memory read at %s." % mem_addr, [expr])


def mem_write_before(state):
    check_collision_with_concretization(state.inspect.mem_write_address, state.memory.read_strategies[0].track_values)


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
    #print(state.inspect.mem_read_address)
    #print(state.inspect.mem_read_expr)
    #check_collision_with_concretization(state.inspect.mem_read_address, state.memory.read_strategies[0].track_values)


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
            if not mem_ast.cache_key in replacements:
                mem_var = claripy.BVS(f"MEM[{mem_addr}]_0_{mem_ast.length}", mem_ast.length, explicit_name=True)
                replacements[mem_ast.cache_key] = mem_var
                mem_expr_constraint = mem_var == mem_ast
                state.add_constraints(mem_expr_constraint)
                # adds the non-repetition constraint in the concretization strategy
                if state.inspect.mem_read_address.op == "BVV":
                    state.memory.read_strategies[0]._repeat_constraints.append(
                        state.memory.read_strategies[0]._repeat_expr != state.inspect.mem_read_address
                    )

        state.inspect.mem_read_expr = state.inspect.mem_read_expr.replace_dict(replacements)

    #print(state.inspect.mem_read_expr)
    #print()


def add_bir_concretization_strategy(state, prog_min_addr, prog_max_addr, extra_concretization_constraints):
    state.memory.read_strategies.clear()
    state.memory.write_strategies.clear()


    # excludes these solutions when doing the concretisation
    negated_previous_concretizations = [claripy.Not(claripy.And(*clist)) for clist in extra_concretization_constraints if not clist==[]]
    repeat_expr = claripy.BVS("REPEAT", 64)
    bir_concr_strategy = SimConcretizationStrategyBIR(prog_min_addr=prog_min_addr, prog_max_addr=prog_max_addr, repeat_expr=repeat_expr, negated_previous_choices=negated_previous_concretizations)
    state.memory.read_strategies.insert(0, bir_concr_strategy)
    state.memory.write_strategies.insert(0, bir_concr_strategy)


def print_results(simgr_states, errored_states, assert_addr, extra_concretization_constraints, dump_json=True):
    def get_path_constraints(state_constraints, track_concretization_values):
        path_constraints_first_filtering = [
            const for const in state_constraints
                if not all(x in str(const) for x in ["MEM", "==", "mem_"])
        ]
        path_constraints_second_filtering = [
            const for const in path_constraints_first_filtering
                if not any(const.structurally_match(e) for e in track_concretization_values)
        ]
        list_constraints = [own_bv_str(const) for const in path_constraints_second_filtering]
        return list_constraints

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
            list_constraints = get_path_constraints(state.solver.constraints, state.memory.read_strategies[0].track_values)
            list_obs = [(idx, own_bv_str(cond), [own_bv_str(obs) for obs in obss]) for (idx, cond, obss, is_shadow) in state.observations.list_obs]
            if args.debug_out:
                print("\t- Path:", ''.join("\n\t\t{0}".format(addr) for addr in list_addrs))
                print("\t- Guards:", ''.join("\n\t\t{0}".format(str(g)) for g in state.history.jump_guards.hardcopy))
                print("\t- State Constraints:", ''.join("\n\t\t\t{0}".format(str(sc)) for sc in state.solver.constraints))
                print("\t- Path Constraints:\t", ''.join("\n\t\t\t{0}".format(c) for c in list_constraints))
                print("\t- Observations:\t\t", ''.join("\n\t\t\t{0}".format(o) for o in list_obs))
                print("="*80)

            # append to dictionary for json output
            if state_addr == "Assert failed":
                continue
            else:
                dict_state["addr"] = state_addr
                dict_state["path"] = list_addrs
                dict_state["constraints"] = list_constraints
                dict_state["observations"] = list_obs
                output.append(dict_state.copy())
    if args.error_states:
        print("-"*80)
        print("ERRORED STATES:")
        print(errored_states)
    if dump_json:
        # in the end, prints the json output
        json_object = json.dumps(output, indent=4)
        print(("="*10) + " JSON START " + ("="*10))
        print(json_object)



def main():
    with open(args.entryfilename, "r") as entry_json:
        entry = json.load(entry_json)

    # binary program to be loaded into memory
    binfile = entry["bin"]
    # sends the bir program in json format to the lifter
    birprogjson = entry["birprogram"]
    entry_addr = entry["entry"]
    exit_addrs = entry["exits"]

    # extracts the registers from the input program and sets them in the register list of the architecture
    regs = set_registers(birprogjson)

    # initializes the angr project
    proj = angr.Project(binfile, main_opts={'backend': 'bir'})

    # sets addresses for assertion and observations in an external region
    extern_addr = proj.loader.kernel_object.min_addr+0x14
    bir_angr.bir.lift_bir.set_extern_val(extern_addr, args.dump_irsb, birprogjson)

    # sets the initial state and registers
    state = proj.factory.entry_state(addr=entry_addr, remove_options=angr.options.simplification)
    init_regs(state, regs)
    add_state_options(state)

    # breakpoint that hooks the 'mem_read' event to change the resulting symbolic values
    state.inspect.b('mem_read', when=angr.BP_AFTER, action=mem_read_after)
    #state.inspect.b('mem_write', when=angr.BP_BEFORE, action=mem_write_before)

    cfg = set_cfg(proj)
    loop_finder = proj.analyses.LoopFinder()

    extra_concretization_constraints = []
    while True:
        print("I - Angr Symbolic Execution")

        # adds a concretization strategy with some constraints for a bir program
        add_bir_concretization_strategy(state, proj.loader.min_addr, proj.loader.max_addr, extra_concretization_constraints)
        replacements.clear()

        try:
            # executes the symbolic execution and prints the results
            simgr = proj.factory.simulation_manager(state)
            if len(loop_finder.loops) > 0:
                simgr.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg, functions=None, bound=1))

            simgr.explore(n=args.num_steps, avoid=exit_addrs)
            simgr_states = [(name, ls) for name, ls in simgr._stashes.items() if len(ls) != 0 and name != 'errored']
            print_results(simgr_states, simgr.errored, extern_addr, extra_concretization_constraints)
        except ConcretizationException as e:
            extra_concretization_constraints.append((e.previous_values))
            print(e)
            print("A new constraint will be added.\n")
            claripy.ast.base.var_counter = itertools.count()
        else:
            break





if __name__ == '__main__':
    main()

