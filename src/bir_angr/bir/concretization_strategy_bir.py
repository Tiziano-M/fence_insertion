from angr.concretization_strategies import SimConcretizationStrategy
from angr.errors import SimUnsatError, SimStateError
import claripy

import logging
from angr.state_plugins.plugin import SimStatePlugin

l = logging.getLogger(name=__name__)


def filtering_constraints(list_constraints, track_concretization_values):
    '''
    Removes concretization constraints from solver constraints.
    '''
    first_filtering = [
        c for c in list_constraints
            if not all(x in str(c) for x in ["MEM", "==", "mem_"])
    ]
    second_filtering = [
        c for c in first_filtering
            if not any(c.structurally_match(e) for e in track_concretization_values)
    ]
    return second_filtering



class SimConcretizationStrategyBIR(SimConcretizationStrategy):


    def __init__(self,
                 addr_ranges,
                 repeat_expr,
                 repeat_constraints=None,
                 recent_track_values=None,
                 prog_range_constraints = None,
                 **kwargs):
        super(SimConcretizationStrategyBIR, self).__init__(**kwargs)
        #self.track_values = [] if recent_track_values is None else recent_track_values
        self._repeat_expr = repeat_expr
        self._repeat_constraints = [] if repeat_constraints is None else repeat_constraints
        self._addr_ranges = addr_ranges
        self._prog_range_constraints = [] if prog_range_constraints is None else prog_range_constraints


    def _concretize(self, memory, addr, **kwargs):
        for e in memory.state.concretizations.track_values:
            # recovers the value already concretized
            if addr.cache_key == e.args[0].cache_key:
                c = e.args[1].args[0]
                break
        else:
            #if addr.length != self._repeat_expr.length:
            #    addr.length = 64

            # avoids the location where the program is loaded based on proj.loader:
            # program range
            prog_max_addr, prog_min_addr = self._addr_ranges[0][1], self._addr_ranges[0][0]
            addr_constraint1 = claripy.Or(claripy.UGT(addr, prog_max_addr), claripy.ULT(addr, prog_min_addr))
            # range of other objects
            max_addr, min_addr = self._addr_ranges[-1][1], self._addr_ranges[1][0]
            addr_constraint2 = claripy.Or(claripy.UGT(addr, max_addr), claripy.ULT(addr, min_addr))

            # concretize in the middle
            #addr_constraint2 = claripy.And(claripy.UGT(addr, 0x10000), claripy.ULT(addr, 0xdffffffffffffffe))

            if (len(list(addr.variables)) == 1):
                self._repeat_constraints.extend([addr!=previous_addr.args[0]
                                                  for previous_addr in memory.state.concretizations.track_values
                                                  if not memory.state.concretizations.track_values==[] 
                                                  and not list(addr.variables)[0]==list(previous_addr.args[0].variables)[0]])
            else:
                wmsg = ''.join("\n\t\t\t{0}".format(str(val)) for val in memory.state.concretizations.track_values)
                logging.warning(f"SimConcretizationStrategyBIR - address with multiple variables:\n{addr}\nConcretizations:{wmsg}")
                self._repeat_constraints.extend([addr!=previous_addr.args[0]
                                                  for previous_addr in memory.state.concretizations.track_values
                                                  if not memory.state.concretizations.track_values==[]])

            child_constraints = tuple(self._repeat_constraints) + (addr_constraint1, addr_constraint2)
            extra_constraints = kwargs.pop('extra_constraints', None)
            if extra_constraints is not None:
                child_constraints += tuple(extra_constraints)

            #print(memory.state.solver.unsat_core(extra_constraints=child_constraints))
            try:
                c = self._any(memory, addr, extra_constraints=child_constraints, **kwargs)
                self._prog_range_constraints.append(addr_constraint1)
            except SimUnsatError:
                child_constraints = tuple(self._repeat_constraints) + (addr_constraint2,)
                try:
                    c = self._any(memory, addr, extra_constraints=child_constraints, **kwargs)
                except SimUnsatError:
                
                    #self.print_debug_output(memory.state, child_constraints)
                    #print("\nConstraints:", *memory.state.solver.constraints, sep="\n")
                    #print("\nExtra Constraints:", *child_constraints, sep="\n")
                    
                    list_constraints = filtering_constraints(memory.state.solver.constraints, memory.state.concretizations.track_values)
                    memory.state.solver.reload_solver(constraints=list_constraints)

                    if memory.state.solver.satisfiable():
                        exprs = [e.args[0] for e in memory.state.concretizations.track_values]
                        exprs.append(addr)

                        #addrs_constraint1 = [claripy.Or(claripy.UGT(exp,self._prog_max_addr), claripy.ULT(exp,self._prog_min_addr)) for exp in exprs]
                        addrs_constraint2 = [claripy.Or(claripy.UGT(exp,max_addr), claripy.ULT(exp,min_addr)) for exp in exprs]
                        
                        try:
                            # QUERY 1 ###############################################
                            extra_c = tuple(self._repeat_constraints)+tuple(self._prog_range_constraints)+tuple(addrs_constraint2)
                            solutions = memory.state.solver._solver.batch_eval(exprs, 1, extra_constraints=extra_c, **kwargs)[0]
                        except claripy.errors.UnsatError:
                            try:
                                # QUERY 2 ###############################################
                                extra_c2 = tuple(self._repeat_constraints) + tuple(addrs_constraint2)
                                solutions = memory.state.solver._solver.batch_eval(exprs, 1, extra_constraints=extra_c2, **kwargs)[0]
                            except claripy.errors.UnsatError:
                                try:
                                    # QUERY 3 ###############################################
                                    extra_c3 = tuple(self._repeat_constraints)
                                    solutions = memory.state.solver._solver.batch_eval(exprs, 1, extra_constraints=extra_c3, **kwargs)[0]
                                except claripy.errors.UnsatError:
                                    print("\nthe address %s cannot be concretized." % addr)
                                    print("\nPATH UNFEASIBLE\n\n")
                                    #unsat_constraints = self.get_unsat_constraints(memory.state.solver.constraints, extra_c)
                                    #check_constraints = [rc for rc in self._repeat_constraints if any(rc.cache_key==uc.cache_key for uc in unsat_constraints)]
                                    #assert (len(check_constraints) > 0)
                                    logging.warning("SimConcretizationStrategyBIR - PATH UNFEASIBLE due to norepeat constraints.")
                                    raise SimStateError("PATH UNFEASIBLE due to norepeat constraints.")

                                    '''
                                    print("\nQUERIES FAILED\n\n")
                                    unsat_constraints = self.get_unsat_constraints(memory.state.solver.constraints, extra_c2)
                                    assert (len(unsat_constraints) >= 2)
                                    extra_c4 = [ec for ec in extra_c2 if not any(ec.cache_key==uc.cache_key for uc in unsat_constraints)]
                                    while True:
                                        try:
                                            # QUERY 4 ###############################################
                                            solutions = memory.state.solver._solver.batch_eval(exprs, 1, extra_constraints=extra_c4, **kwargs)[0]
                                            break
                                        except claripy.errors.UnsatError:
                                            unsat_constraints = self.get_unsat_constraints(memory.state.solver.constraints, extra_c4)
                                            extra_c4 = [ec for ec in extra_c4 if not any(ec.cache_key==uc.cache_key for uc in unsat_constraints)]
                                            if len(unsat_constraints) < 2:
                                                raise SimStateError("ConcretizationException: no solution found.")
                                                break
                                    '''
                    else:
                        #print("\nstate pruned\n")
                        #self.get_unsat_constraints(memory.state.solver.constraints, child_constraints)
                        raise SimStateError("%s: state pruned." % memory.state)
                        #raise claripy.errors.UnsatError



                    assert (len(exprs)==len(solutions))
                    new_choices = [e==v for e, v in zip(exprs, solutions)]

                    assert (len(new_choices)==len(exprs)==len(solutions))
                    assert (exprs[k]==new_choices[k].args[0] for k in range(len(exprs)))
                    assert (solutions[k]==new_choices[k].args[1].args[0] for k in range(len(solutions)))
                    
                    #vals = list(map(lambda v: hex(v), solutions))
                    #print("\nNEW CHOICES:", *zip(exprs,vals,new_choices), sep="\n")

                    assert (memory.state.solver.satisfiable(extra_constraints=(tuple(self._repeat_constraints)+tuple(new_choices))))
                    raise ConcretizationException("the address %s cannot be concretized." % addr, new_choices, memory.state)
            memory.state.concretizations.append(addr==c)
        return [ c ]

    def get_unsat_constraints(self, state_constraints, extra_constraints):
        s = claripy.Solver(track=True)
        s.add(state_constraints)
        s.add(list(set(extra_constraints)))
        unsat_constraints = s.unsat_core()
        print("UNSAT Constraints:", *unsat_constraints, sep='\n')
        s_check = claripy.Solver()
        s_check.add(unsat_constraints)
        if s_check.satisfiable():
            print("\n*************** ATTENTION! THE UNSAT_CORE IS WRONG! ***************\n")
        else:
            return unsat_constraints

    def print_debug_output(self, state, child_constraints):
        import subprocess
        path = list(map(lambda value: hex(value), state.history.bbl_addrs.hardcopy))
        print("Path:", ''.join("\n\t{0}".format(addr) for addr in path))

        ip = format(state.addr, 'x')
        print("\nIP:", ip)

        filenamebinary = '/home/tiziano/scamv/HolBA/src/tools/angr/python/dafilenames/aes.da'
        out = subprocess.check_output(f"grep -A 10 -B 10 '{ip}:' {filenamebinary} -r", shell=True)
        print(out.decode())
        print()
        print("Satisfiable constraints of the path:", state.solver.satisfiable())
        #self.get_unsat_constraints(state.solver.constraints, child_constraints)
        print()



class ConcretizationException(Exception):
    '''
    Raised when there is a concretization failure.
    '''

    def __init__(self, message, new_solutions, failed_state, *args):
        super().__init__(message, *args)
        self.message = message
        self.new_solutions = new_solutions
        self.failed_state = failed_state

    def __str__(self):
        return 'ConcretizationException: %s\nNew solutions:\n%s\n' % (self.message, "\n".join(str(s) for s in self.new_solutions))



class SimStateTrackConcretizations(SimStatePlugin):
    def __init__(self, backer=None, map_mem_dict=None):
        super(SimStateTrackConcretizations, self).__init__()
        self._backer = backer if backer is not None else []
        # maps memory read values for replacement
        self._replacements = map_mem_dict if map_mem_dict is not None else {}

    def set_state(self, state):
         super(SimStateTrackConcretizations, self).set_state(state)

    def append(self, c):
        self._backer.append(c)

    def extend(self, l):
        self._backer.extend(l)

    def clear(self):
        self._backer.clear()

    @property
    def track_values(self):
        return self._backer

    @property
    def replacements(self):
        return self._replacements

    def __getitem__(self, k):
        return self._replacements[k]

    def __setitem__(self, k, v):
        self._replacements[k] = v

    def __delitem__(self, k):
        del self._replacements[k]

    def __contains__(self, k):
        return k in self._replacements

    def keys(self):
        return self._replacements.keys()

    def values(self):
        return self._replacements.values()

    def items(self):
        return self._replacements.items()

    def get(self, k, alt=None):
        return self._replacements.get(k, alt)

    def pop(self, k, alt=None):
        return self._replacements.pop(k, alt)

    def dict_clear(self):
        return self._replacements.clear()

    @SimStatePlugin.memo
    def copy(self, memo):   # pylint: disable=unused-argument
        return SimStateTrackConcretizations(list(self._backer), dict(self._replacements))

from angr.sim_state import SimState
SimState.register_default('concretizations', SimStateTrackConcretizations)
