import argparse

import angr
import bir
import claripy
from bir.lift_bir import cleanup_cache_lifting


parser = argparse.ArgumentParser()
parser.add_argument("program", help="BIR program path name", type=str)
parser.add_argument("-ba", "--base_addr", help="The address to place the data in memory (default 0)", default=0, type=int)
args = parser.parse_args()



def init_regs(state):
    state.regs.R0 = claripy.BVS("R0", 64)
    state.regs.R1 = claripy.BVS("R1", 64)
    state.regs.R2 = claripy.BVS("R2", 64)
    state.regs.R3 = claripy.BVS("R3", 64)
    state.regs.R4 = claripy.BVS("R4", 64)
    state.regs.R5 = claripy.BVS("R5", 64)
    state.regs.R6 = claripy.BVS("R6", 64)
    state.regs.R7 = claripy.BVS("R7", 64)
    state.regs.R8 = claripy.BVS("R8", 64)
    state.regs.R9 = claripy.BVS("R9", 64)
    state.regs.R10 = claripy.BVS("R10", 64)
    state.regs.R11 = claripy.BVS("R11", 64)
    state.regs.R12 = claripy.BVS("R12", 64)
    state.regs.R13 = claripy.BVS("R13", 64)
    state.regs.R14 = claripy.BVS("R14", 64)
    state.regs.R15 = claripy.BVS("R15", 64)
    state.regs.R16 = claripy.BVS("R16", 64)
    state.regs.R17 = claripy.BVS("R17", 64)
    state.regs.R18 = claripy.BVS("R18", 64)
    state.regs.R19 = claripy.BVS("R19", 64)
    state.regs.R20 = claripy.BVS("R20", 64)
    state.regs.R21 = claripy.BVS("R21", 64)
    state.regs.R22 = claripy.BVS("R22", 64)
    state.regs.R23 = claripy.BVS("R23", 64)
    state.regs.R24 = claripy.BVS("R24", 64)
    state.regs.R25 = claripy.BVS("R25", 64)
    state.regs.R26 = claripy.BVS("R26", 64)
    state.regs.R27 = claripy.BVS("R27", 64)
    state.regs.R28 = claripy.BVS("R28", 64)
    state.regs.R29 = claripy.BVS("R29", 64)
    state.regs.R30 = claripy.BVS("R30", 64)
    state.regs.R31 = claripy.BVS("R31", 64)
    state.regs.SP_EL0 = claripy.BVS("SP_EL0", 64)
    state.regs.SP_EL1 = claripy.BVS("SP_EL1", 64)
    state.regs.SP_EL2 = claripy.BVS("SP_EL2", 64)
    state.regs.SP_EL3 = claripy.BVS("SP_EL3", 64)
    state.regs.ProcState_C = claripy.BVS("ProcState_C", 8)
    state.regs.ProcState_E = claripy.BVS("ProcState_E", 8)
    state.regs.ProcState_N = claripy.BVS("ProcState_N", 8)
    state.regs.ProcState_V = claripy.BVS("ProcState_V", 8)
    state.regs.ProcState_Z = claripy.BVS("ProcState_Z", 8)
        

def add_state_options(state):
    state.options.add(angr.options.CONSERVATIVE_READ_STRATEGY)
    state.options.add(angr.options.CONSERVATIVE_WRITE_STRATEGY)


def print_results(final_states):
    print("\n\n")
    print(f"RESULT: {len(final_states)} final states")
    for state in final_states:
        print("="*80)
        print("STATE:", state)
        # is a listing of the basic block addresses executed by the state.
        list_addrs = state.history.bbl_addrs.hardcopy
        # converts addresses from decimal to hex
        list_addrs = list(map(lambda value: hex(value), list_addrs))
        list_guards = state.history.jump_guards.hardcopy
        list_obs = state.observations.get_list_obs()
        print("\t- Path:\t\t", list_addrs)
        print("\t- Guards:\t", list_guards)
        print("\t- Observations:\t", list_obs)
        print("="*80)


def main():
    # initializes the angr project
    proj = angr.Project(args.program, main_opts={'base_addr': args.base_addr})

    # sets the initial state and registers
    state = proj.factory.entry_state(addr=args.base_addr)
    init_regs(state)
    add_state_options(state)

    # executes the symbolic execution and prints the results
    simgr = proj.factory.simulation_manager(state)
    simgr.explore()
    print_results(simgr.deadended)



if __name__ == '__main__':
    main()

