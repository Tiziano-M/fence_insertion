from angr.concretization_strategies.norepeats import SimConcretizationStrategyNorepeats
from angr.errors import SimUnsatError
import claripy

class SimConcretizationStrategyBIR(SimConcretizationStrategyNorepeats):


    def __init__(self, min_addr, repeat_expr, repeat_constraints=None, **kwargs):
        super(SimConcretizationStrategyBIR, self).__init__(repeat_expr=repeat_expr, repeat_constraints=repeat_constraints, **kwargs)
        self._min_addr = min_addr


    def _concretize(self, memory, addr):
        if addr.length != self._repeat_expr.length:
            addr.length = 64

        # avoids the location where the program is loaded based on proj.loader.max_addr
        addr_constraint = [ claripy.UGT(addr, self._min_addr) ]

        try:
            c = self._any(
                memory, addr,
                extra_constraints = self._repeat_constraints + [ addr == self._repeat_expr ] + addr_constraint
            )
        except SimUnsatError as e:
            c = self._any(
                memory, addr,
                extra_constraints = addr_constraint
            )
        self._repeat_constraints.append(self._repeat_expr != c)
        return [ c ]
