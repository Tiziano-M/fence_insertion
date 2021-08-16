import angr
import bir
import claripy


def test():
    proj = angr.Project("examples/json/test3.bir", main_opts={'backend': 'bir'})

    state = proj.factory.entry_state()
    simgr = proj.factory.simulation_manager(state)
    simgr.explore()


def test2():
    proj = angr.Project("examples/json/test2.bir", main_opts={'backend': 'bir', 'base_addr': 3489667176})

    state = proj.factory.entry_state(addr=3489667176)
    simgr = proj.factory.simulation_manager(state)
    simgr.explore()


def test3():
    proj = angr.Project("examples/json/test3.bir", main_opts={'backend': 'bir'})

    state = proj.factory.entry_state()
    state.regs.R3 = claripy.BVS("R3", 64)
    state.regs.R8 = claripy.BVS("R8", 64)
    state.regs.ProcState_Z = claripy.BVS("ProcState_Z", 8)
    simgr = proj.factory.simulation_manager(state)
    simgr.explore()
    print(simgr.deadended)
    print(simgr.deadended[0].regs.R9)
    print(simgr.deadended[1].regs.R10)


def test_unicorn():
    from angr.engines.unicorn import SimEngineUnicorn
    proj = angr.Project("examples/test.bir", main_opts={'backend': 'bir'}, engine=SimEngineUnicorn)


def test_simos():
    proj = angr.Project("examples/json/test_obs5.bir")
    
    state = proj.factory.entry_state()
    state.regs.R21 = claripy.BVS("R21", 64)
    state.regs.R10 = claripy.BVS("R10", 64)
    state.regs.R18 = claripy.BVS("R18", 64)
    state.regs.R11 = claripy.BVS("R11", 64)
    state.regs.R19 = claripy.BVS("R19", 64)
    state.regs.R26 = claripy.BVS("R26", 64)
    simgr = proj.factory.simulation_manager(state)
    simgr.explore()
    print(simgr.deadended)
    print(simgr.deadended[0].observations.get_list_obs())
    print(simgr.deadended[1].observations.get_list_obs())
    return simgr


def test_assert():
    proj = angr.Project("examples/test_assert.bir")

    state = proj.factory.entry_state()
    state.options.add(angr.options.CONSERVATIVE_READ_STRATEGY)
    state.options.add(angr.options.CONSERVATIVE_WRITE_STRATEGY)
    state.regs.R22 = 0
    #state.regs.R23 = 0

    simgr = proj.factory.simulation_manager(state)
    simgr.explore()
    #simgr.move(from_stash='deadended', to_stash='failure', filter_func=lambda s: True if s.addr == 0x400 else False)
    return simgr


def main():
    test()


if __name__ == '__main__':
    main()
