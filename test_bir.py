import angr
import angr_platforms.bir
import claripy


def test():
    proj = angr.Project("examples/bir_program.bir", main_opts={'backend': 'bir'})

    state = proj.factory.entry_state()
    simgr = proj.factory.simulation_manager(state)
    simgr.explore()


def test2():
    proj = angr.Project("examples/test2.bir", main_opts={'backend': 'bir', 'base_addr': 3489667176})

    state = proj.factory.entry_state(addr=3489667176)
    simgr = proj.factory.simulation_manager(state)
    simgr.explore()


def test3():
    proj = angr.Project("examples/test3.bir", main_opts={'backend': 'bir'})

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
    proj = angr.Project("examples/test_obs5.bir")
    
    state = proj.factory.entry_state()
    state.regs.R21 = claripy.BVS("R21", 64)
    state.regs.R10 = claripy.BVS("R10", 64)
    state.regs.R18 = claripy.BVS("R18", 64)
    simgr = proj.factory.simulation_manager(state)
    simgr.explore()
    print(simgr.deadended[0].regs.R13)
    #print(simgr.deadended[0].memory.load(0x4000, 8))
    print(simgr.deadended)
    print(simgr.deadended[0].globals['obs'])
    print(simgr.deadended[1].globals['obs'])
    return simgr



def main():
    test_simos()


if __name__ == '__main__':
    main()
