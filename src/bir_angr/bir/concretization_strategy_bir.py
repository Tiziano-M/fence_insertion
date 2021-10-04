from angr.concretization_strategies.norepeats import SimConcretizationStrategyNorepeats
import claripy

class SimConcretizationStrategyBIR(SimConcretizationStrategyNorepeats):


    def __init__(self, min_addr, lower_mem_bound, repeat_expr, repeat_constraints=None, **kwargs):
        super(SimConcretizationStrategyBIR, self).__init__(repeat_expr=repeat_expr, repeat_constraints=repeat_constraints, **kwargs)
        self._min_addr = min_addr
        self._lower_mem_bound = lower_mem_bound


    def _concretize(self, memory, addr):
        # avoids the location where the program is loaded based on proj.loader.max_addr
        addr_constraint1 = [ claripy.UGT(addr, self._min_addr) ]
        # range of memory where to concretize
        addr_constraint2 = [ claripy.And(claripy.UGT(addr, self._lower_mem_bound), claripy.ULT(addr, self._max(memory, addr))) ]

        if addr.length != self._repeat_expr.length:
            size = self._repeat_expr.length - addr.length
            addr = addr.zero_extend(size)
        #print(addr)
        #print(self._repeat_constraints + [ addr == self._repeat_expr ] + addr_constraint1 + addr_constraint2)

        c = self._any(
            memory, addr,
            extra_constraints = self._repeat_constraints + [ addr == self._repeat_expr ] + addr_constraint1 + addr_constraint2
        )
        self._repeat_constraints.append(self._repeat_expr != c)
        return [ c ]
