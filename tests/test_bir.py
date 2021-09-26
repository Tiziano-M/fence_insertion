import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), "../src/bir_angr"))


import bir
import angr
import claripy



def test():
    birprog = "examples/json/test3.bir"
    bir.arch_bir.get_register_list(birprog)
    proj = angr.Project(birprog, main_opts={'backend': 'bir'})

    state = proj.factory.entry_state()
    simgr = proj.factory.simulation_manager(state)
    simgr.explore()


def test2():
    birprog = "examples/json/test2.bir"
    bir.arch_bir.get_register_list(birprog)
    proj = angr.Project(birprog, main_opts={'backend': 'bir', 'base_addr': 3489667176})

    state = proj.factory.entry_state(addr=3489667176)
    simgr = proj.factory.simulation_manager(state)
    simgr.explore()


def test3():
    birprog = "examples/json/test3.bir"
    bir.arch_bir.get_register_list(birprog)
    proj = angr.Project(birprog, main_opts={'backend': 'bir'})

    state = proj.factory.entry_state()
    state.regs.R3 = claripy.BVS("R3", 64)
    state.regs.R8 = claripy.BVS("R8", 64)
    state.regs.ProcState_Z = claripy.BVS("ProcState_Z", 8)
    simgr = proj.factory.simulation_manager(state)
    simgr.explore()
    print(simgr.deadended)
    print(simgr.deadended[0].regs.R9)
    print(simgr.deadended[1].regs.R10)


def test_simos():
    birprog = "examples/json/test_obs5.bir"
    bir.arch_bir.get_register_list(birprog)
    proj = angr.Project(birprog)
    
    state = proj.factory.entry_state()
    state.regs.R21 = claripy.BVS("R21", 64)
    state.regs.R10 = claripy.BVS("R10", 64)
    state.regs.R13 = claripy.BVS("R13", 64)
    state.regs.R18 = claripy.BVS("R18", 64)
    #state.regs.R11 = claripy.BVS("R11", 64)
    #state.regs.R19 = claripy.BVS("R19", 64)
    #state.regs.R26 = claripy.BVS("R26", 64)
    simgr = proj.factory.simulation_manager(state)
    simgr.explore()
    print(simgr.deadended)
    print(simgr.deadended[0].observations.get_list_obs())
    print(simgr.deadended[1].observations.get_list_obs())
    return simgr


def test_assert():
    birprog = "examples/json/test_assert.bir"
    bir.arch_bir.get_register_list(birprog)
    proj = angr.Project(birprog)

    state = proj.factory.entry_state()
    #state.inspect.b('address_concretization')
    state.options.add(angr.options.CONSERVATIVE_READ_STRATEGY)
    state.options.add(angr.options.CONSERVATIVE_WRITE_STRATEGY)
    state.regs.R22 = 0
    #state.regs.R23 = 0

    simgr = proj.factory.simulation_manager(state)
    simgr.explore()
    #simgr.move(from_stash='deadended', to_stash='failure', filter_func=lambda s: True if s.addr == 0x400 else False)
    print(simgr.errored)
    return simgr


def test_cfg():
    from angr.analyses.cfg import cfg_fast
    cfg_fast.VEX_IRSB_MAX_SIZE = 2000000

    birprog = "examples/json/example_tutorial.bir"
    bir.arch_bir.get_register_list(birprog)
    proj = angr.Project(birprog)

    state = proj.factory.entry_state()
    state.options.add(angr.options.LAZY_SOLVES)
    state.options.add(angr.options.CONSERVATIVE_READ_STRATEGY)
    state.options.add(angr.options.CONSERVATIVE_WRITE_STRATEGY)

    cfg = proj.analyses.CFGFast(normalize=True)

    simgr = proj.factory.simulation_manager(state)
    simgr.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg, functions=None, bound=5)) # bound=0 if I don't want repeated final state
    
    simgr.explore()
    print(simgr.deadended)
    print(simgr.errored)


def test_ite():
    birprog = "examples/json/test_ite.bir"
    bir.arch_bir.get_register_list(birprog)
    proj = angr.Project(birprog, main_opts={'base_addr': 3489667764})

    state = proj.factory.entry_state(addr=3489667764)
    state.regs.R0 = claripy.BVS("R0", 64)

    simgr = proj.factory.simulation_manager(state)
    simgr.explore()
    print(simgr.deadended)
    print(simgr.deadended[0].regs.R0)


def test_track_actions():
    birprog = "examples/json/test_store3.bir"
    bir.arch_bir.get_register_list(birprog)
    proj = angr.Project(birprog)

    state = proj.factory.entry_state()
    # options to track memory access operations in the history of actions
    state.options.add(angr.options.TRACK_REGISTER_ACTIONS)
    state.options.add(angr.options.TRACK_MEMORY_ACTIONS)

    simgr = proj.factory.simulation_manager(state)
    simgr.explore()

    print("\n\nACTIONS:")
    for action in simgr.deadended[0].history.actions.hardcopy:
        print(action)




def main():
    test()


if __name__ == '__main__':
    main()
