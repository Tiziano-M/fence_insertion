import angr
import angr_platforms.bir


def test():
    proj = angr.Project("examples/test.bir", main_opts={'backend': 'bir'})

    state = proj.factory.entry_state()
    simgr = proj.factory.simulation_manager(state)
    #simgr._stashes
    #simgr._errored
    #simgr.deadended
    simgr.explore()


def test_unicorn():
    from angr.engines.unicorn import SimEngineUnicorn
    proj = angr.Project("examples/test.bir", main_opts={'backend': 'bir'}, engine=SimEngineUnicorn)

    #add different code for unicron
    #state = proj.factory.entry_state()
    #simgr = proj.factory.simulation_manager(state)
    #simgr.explore()



def main():
    test()
    #test_unicorn()


if __name__ == '__main__':
    main()
