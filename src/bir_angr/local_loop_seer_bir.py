from angr.exploration_techniques import LocalLoopSeer


class LocalLoopSeerBIR(LocalLoopSeer):
    """
    LocalLoopSeer monitors exploration and maintains all loop-related data without relying on a control flow graph.
    """

    def __init__(self, bound=None, bound_reached=None, discard_stash='spinning', **kwargs):
        super(LocalLoopSeerBIR, self).__init__(bound, bound_reached, discard_stash)
        self.syscall_addrs = kwargs.pop('syscall_addrs', None)


    def successors(self, simgr, state, **kwargs):
        succs = simgr.successors(state, **kwargs)

        for succ_state in succs.successors:
            # Processing a currently running loop

            if succ_state._ip.symbolic:
                continue
            elif any(succ_state.addr==sysaddr for sysaddr in self.syscall_addrs):
            	continue
            succ_addr = succ_state.addr

            # If we have set a bound for symbolic/concrete loops we want to handle it here
            if self.bound is not None:
                counts = succ_state.history.bbl_addrs.count(succ_addr)
                if counts > self.bound:
                    if self.bound_reached is not None:
                        # We want to pass self to modify the LocalLoopSeer state if needed
                        # Users can modify succ_state in the handler to implement their own logic
                        # or edit the state of LocalLoopSeer.
                        self.bound_reached(self, succ_state)
                    else:
                        # Remove the state from the successors object
                        # This state is going to be filtered by the self.filter function
                        self.cut_succs.append(succ_state)
        return succs
