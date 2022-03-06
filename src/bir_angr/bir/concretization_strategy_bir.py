from angr.concretization_strategies.norepeats import SimConcretizationStrategyNorepeats
from angr.errors import SimUnsatError
import claripy



class SimConcretizationStrategyBIR(SimConcretizationStrategyNorepeats):


    def __init__(self, prog_min_addr, prog_max_addr, repeat_expr, repeat_constraints=None, recent_track_values=None, **kwargs):
        super(SimConcretizationStrategyBIR, self).__init__(repeat_expr=repeat_expr, repeat_constraints=repeat_constraints, **kwargs)
        self.track_values = [] if recent_track_values is None else recent_track_values
        self._prog_min_addr = prog_min_addr
        self._prog_max_addr = prog_max_addr


    def _concretize(self, memory, addr, **kwargs):
        for e in self.track_values:
            # recovers the value already concretized
            if addr.cache_key == e.args[0].cache_key:
                c = e.args[1].args[0]
                break
        else:
            if addr.length != self._repeat_expr.length:
                addr.length = 64

            if self._prog_min_addr > 0:
                # avoids the location where the program is loaded based on proj.loader
                addr_constraint = claripy.Or(claripy.UGT(addr, self._prog_max_addr), claripy.ULT(addr, self._prog_min_addr))
            else:
                addr_constraint = claripy.UGT(addr, self._prog_max_addr)
            # concretize in the middle
            addr_constraint2 = claripy.And(claripy.UGT(addr, 0x40000000), claripy.ULT(addr, 0xbffffffffffffffe))


            child_constraints = tuple(self._repeat_constraints) + (addr == self._repeat_expr,)
            extra_constraints = kwargs.pop('extra_constraints', None)
            if extra_constraints is not None:
                child_constraints += tuple(extra_constraints)

            child_constraints += (addr_constraint, addr_constraint2)
            #print(memory.state.solver.unsat_core(extra_constraints=child_constraints))
            try:
                c = self._any(memory, addr, extra_constraints=child_constraints, **kwargs)
            except SimUnsatError:
                # check if the reason is because the solution has already been taken from another address
                c = self._any(memory, addr, extra_constraints=(addr_constraint, addr_constraint2), **kwargs)
                for val in self.track_values:
                    if c == val.args[1].args[0]:
                        raise ConcretizationException("collision of %s with" % addr, val.args[0], val.args[1])
                raise SystemExit('the address %s cannot be concretized.' % addr)
            self._repeat_constraints.append(self._repeat_expr != c)
            self.track_values.append(addr==c)
        return [ c ]




class ConcretizationException(Exception):
    '''
    Raised when there is a concretization collision.
    The symbolic value {addr} will not be concretized in this specific solution {val}.
    '''

    def __init__(self, message, addr, val, *args):
        super().__init__(message, *args)
        self.message = message
        self.addr = addr
        self.val = val


    def __str__(self):
        return 'ConcretizationException: %s %s concretized to %s.' % (self.message, self.addr, self.val)

