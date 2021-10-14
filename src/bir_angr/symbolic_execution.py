import argparse
import json

import angr
import bir_angr.bir
import claripy
from bir_angr.bir.concretization_strategy_bir import SimConcretizationStrategyBIR


parser = argparse.ArgumentParser()
parser.add_argument("program", help="BIR program path name", type=str)
parser.add_argument("-ba", "--base_addr", help="The address to place the data in memory (default 0)", default=0, type=int)
args = parser.parse_args()

global track_concretization_values
track_concretization_values = list()


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


def address_concretization_after(state):
    if state.inspect.address_concretization_result is not None:
        value = (state.inspect.address_concretization_expr, state.inspect.address_concretization_result[0])
        track_concretization_values.append(value)


def mem_write_after(state):
    mem_expr_arg = state.inspect.mem_write_address.__repr__(inner=True)
    for expr, val in track_concretization_values:
        if mem_expr_arg == hex(val):
            raise ValueError(expr, val)


def mem_read_after(state):
    #print("\nREAD")
    #print(state.inspect.mem_read_address)
    #print(state.inspect.mem_read_expr)
    mem_expr_arg = state.inspect.mem_read_expr.__repr__(inner=True)

    for expr, val in track_concretization_values:
        if mem_expr_arg == hex(val):
            raise ValueError(expr, val)

    if state.inspect.mem_read_expr.symbolic and mem_expr_arg.count("mem_"):
        mem_addr = state.inspect.mem_read_address
        mem_val = state.inspect.mem_read_expr
        mem_var = claripy.BVS(f"MEM[{mem_addr}]", state.inspect.mem_read_expr.length)
        mem_expr = mem_var == mem_val
        state.add_constraints(mem_expr)
        state.inspect.mem_read_expr = mem_var
    #print(state.inspect.mem_read_expr)


def add_bir_concretization_strategy(state, min_addr):
    state.memory.read_strategies.clear()
    state.memory.write_strategies.clear()

    repeat_expr = claripy.BVS("REPEAT", 64)
    bir_concr_strategy = SimConcretizationStrategyBIR(min_addr, repeat_expr)
    state.memory.read_strategies.insert(0, bir_concr_strategy)
    state.memory.write_strategies.insert(0, bir_concr_strategy)


def print_results(final_states, errored_states, assert_addr, dump_json=True):
    print("\n\n")
    print(f"RESULT: {len(final_states)} final states")

    output = []
    dict_state = {}
    for state in final_states:
        print("="*80)
        print("STATE:", state, "------> Assert failed" if state.addr == assert_addr else "")
        # is a listing of the basic block addresses executed by the state.
        list_addrs = state.history.bbl_addrs.hardcopy
        # converts addresses from decimal to hex
        list_addrs = list(map(lambda value: hex(value) if value != assert_addr else "Assert failed", list_addrs))
        list_guards = [str(guard) for guard in state.history.jump_guards.hardcopy]
        list_obs = [(idx, [str(obs) for obs in obss]) for idx, obss in state.observations.list_obs]
        list_constraints = [str(const) for const in state.solver.constraints]
        print("\t- Path:\t\t", list_addrs)
        print("\t- Guards:\t", list_guards)
        print("\t- Path Constraints:\t\t", list_constraints)
        print("\t- Observations:\t", list_obs)
        print("="*80)

        # append to dictionary for json output
        if state.addr == assert_addr:
            state_addr = "Assert failed"
        else:
            state_addr = hex(state.addr)
        dict_state["addr"] = state_addr
        dict_state["path"] = list_addrs
        dict_state["guards"] = list_guards
        dict_state["constraints"] = list_constraints
        dict_state["observations"] = list_obs
        output.append(dict_state.copy())
    if False:
        print("="*80)
        print(errored_states)
    if dump_json:
        # in the end, prints the json output
        json_object = json.dumps(output, indent=4)
        print(("="*10) + " JSON START " + ("="*10))
        print(json_object)



def main():
    # extracts the registers from the input program and sets them in the register list of the architecture
    regs = set_registers(args.program)

    # initializes the angr project
    proj = angr.Project(args.program, main_opts={'base_addr': args.base_addr})

    # sets addresses for assertion and observations in an external region
    extern_addr = proj.loader.kernel_object.min_addr+0x5
    bir_angr.bir.lift_bir.set_extern_addr(extern_addr)

    # sets the initial state and registers
    state = proj.factory.entry_state(addr=args.base_addr)
    init_regs(state, regs)
    add_state_options(state)

    # breakpoint that hooks the 'mem_read' event to change the resulting symbolic values
    state.inspect.b('mem_read', when=angr.BP_AFTER, action=mem_read_after)
    state.inspect.b('mem_write', when=angr.BP_AFTER, action=mem_write_after)
    state.inspect.b('address_concretization', when=angr.BP_AFTER, action=address_concretization_after)

    # adds a concretization strategy with some constraints for a bir program
    add_bir_concretization_strategy(state, proj.loader.max_addr)

    concretization_constraints = []
    while True:
        for expr, val in concretization_constraints:
            constarint = claripy.Not(expr == val)
            state.add_constraints(constarint)
        track_concretization_values.clear()
        try:
            # executes the symbolic execution and prints the results
            simgr = proj.factory.simulation_manager(state)
            simgr.explore()
            print_results(simgr.deadended, simgr.errored, extern_addr)
        except ValueError as e:
            concretization_constraints.append(e.args)
            print("EXCEPTION CONCRETIZATION COLLISION: ", e)
        else:
            break





if __name__ == '__main__':
    main()

