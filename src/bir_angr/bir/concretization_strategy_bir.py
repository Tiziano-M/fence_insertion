from angr.concretization_strategies.norepeats import SimConcretizationStrategyNorepeats
from angr.errors import SimUnsatError
import claripy



class SimConcretizationStrategyBIR(SimConcretizationStrategyNorepeats):


    def __init__(self,
                 prog_min_addr,
                 prog_max_addr,
                 repeat_expr,
                 repeat_constraints=None,
                 recent_track_values=None,
                 negated_previous_choices=None,
                 **kwargs):
        super(SimConcretizationStrategyBIR, self).__init__(repeat_expr=repeat_expr, repeat_constraints=repeat_constraints, **kwargs)
        self.track_values = [] if recent_track_values is None else recent_track_values
        self._prog_min_addr = prog_min_addr
        self._prog_max_addr = prog_max_addr
        self._negated_previous_choices = [] if negated_previous_choices is None else negated_previous_choices


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

            if self._negated_previous_choices:
                child_constraints += tuple(self._negated_previous_choices)
            child_constraints += (addr_constraint, addr_constraint2)
            #print(memory.state.solver.unsat_core(extra_constraints=child_constraints))
            try:
                c = self._any(memory, addr, extra_constraints=child_constraints, **kwargs)
            except SimUnsatError:
                #unsat_constraints = memory.state.solver.unsat_core(extra_constraints=child_constraints)
                print("\nIP:", memory.state.ip)
                print("\nConstraints:", *memory.state.solver.constraints, sep='\n')
                print("\nExtra Constraints:", *child_constraints, sep='\n')
                print()
                # these choices will be excluded in the next iteration
                raise ConcretizationException("the address %s cannot be concretized." % addr, self.track_values)
            self._repeat_constraints.append(self._repeat_expr != c)
            self.track_values.append(addr==c)
        return [ c ]




class ConcretizationException(Exception):
    '''
    Raised when there is a concretization failure.
    '''

    def __init__(self, message, previous_values, *args):
        super().__init__(message, *args)
        self.message = message
        self.previous_values = previous_values


    def __str__(self):
        return 'ConcretizationException: %s\nThese solutions will be excluded in the next iteration:\n%s' % (self.message, self.previous_values)

