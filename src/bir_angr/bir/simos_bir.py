from angr.simos import SimUserland, register_simos
from angr.calling_conventions import SimStackArg, SimRegArg, SimCC, register_syscall_cc, register_default_cc, SimCCUnknown
from angr import SimProcedure
from angr.procedures import SIM_PROCEDURES as P, SIM_LIBRARIES as L
from angr.procedures.definitions import SimSyscallLibrary

from .arch_bir import ArchBIR





class Accumulate(SimProcedure):
    """
    Keeps the observations of an Observe statement.
    """
    num_args = 1
    NUM_ARGS = 1

    def run(self, obs):
        ''' print("\nObservation:", obs, "\n") '''
        self.state.observations.accumulate.append(obs)
        #print(self.state.observations.accumulate.list_obs)



class Observation(SimProcedure):
    """
    Stores the observations by fetching them into the accumulator and then resets it.
    """
    num_args = 2
    NUM_ARGS = 2

    def run(self, obs, idx):
        obss = self.state.observations.accumulate.list_obs.copy()
        cond_obs = self.state.regs.cond_obs[0]
        idx_cond_obss = (idx.ast.args[0], cond_obs, obss, None)
        self.state.observations.append(idx_cond_obss)
        self.state.observations.accumulate.list_obs.clear()
        #print(self.state.observations.accumulate.list_obs)
        #print(self.state.observations.list_obs)
        self.state.regs.cond_obs = 0



class StartShadowBranch(SimProcedure):

    num_args = 0
    NUM_ARGS = 0

    def run(self):
        shadow_state = self.state.copy()
        shadow_state.observations.accumulate.list_obs.clear()
        shadow_state.observations.list_obs.clear()
        n_constraints = len(shadow_state.solver.constraints)

        self.successors.add_successor(shadow_state,
                                      shadow_state.regs.ip_at_syscall,
                                      shadow_state.solver.true, 'Ijk_Boring')


        while True:
            succ = shadow_state.step()
            #print(hex(succ.addr))
            if len(succ.successors) > 0:
                # Note: is it enough? (e.g. conditional branch), otherwise we can write an Exploration Technique
                shadow_state = succ.successors[-1]
            else:
                break

        #print("ORIGINAL STATE", self.state, self.state.ip, self.state.regs.ip_at_syscall)
        #print("SHADOW STATE", shadow_state, shadow_state.ip, shadow_state.regs.ip_at_syscall)


        self.state.solver.constraints.extend(shadow_state.solver.constraints[n_constraints:])
        self.state.observations.list_obs.extend((i,c,o,"shadow") for (i,c,o,s) in shadow_state.observations.list_obs)

        self.jump(shadow_state.regs.ip_at_syscall)
        succ = self.state.step()
        #print(hex(self.state.addr))



class EndShadowBranch(SimProcedure):

    num_args = 0
    NUM_ARGS = 0

    def run(self):
        self.exit(None)










P['bir'] = {}
P['bir']['observation'] = Observation
P['bir']['accumulate'] = Accumulate
P['bir']['start_shadow_branch'] = StartShadowBranch
P['bir']['end_shadow_branch'] = EndShadowBranch

syscall_lib = SimSyscallLibrary()
syscall_lib.set_library_names('bir')
syscall_lib.add_all_from_dict(P['bir'])
syscall_lib.add_number_mapping_from_dict('BIR', {0: 'observation', 
                                                 1: 'accumulate', 
                                                 2: 'start_shadow_branch', 
                                                 3: 'end_shadow_branch'})



class SimBIR(SimUserland):
    # Syscalls are for lamers
    SYSCALL_TABLE = {}

    def __init__(self, project, **kwargs):
        super(SimBIR, self).__init__(project, syscall_library=L['bir'], name="BIR", **kwargs)

    def state_blank(self, data_region_size=0x8000, **kwargs): # pylint:disable=arguments-differ
        state = super(SimBIR, self).state_blank(**kwargs)  # pylint:disable=invalid-name
        return state

    def state_entry(self, **kwargs):
        state = super(SimBIR, self).state_entry(**kwargs)
        return state


class SimBIRSyscall(SimCC):
    ARG_REGS = ['obs', 'idx_obs'] # A list of all the registers used for integral args to be passed in procedures
    RETURN_ADDR = SimRegArg('ip_at_syscall', 8)
    #RETURN_VAL = SimRegArg('obs', 8)
    ARCH = ArchBIR

    @staticmethod
    def _match(arch, args, sp_delta):   # pylint: disable=unused-argument
        # doesn't appear anywhere but syscalls
        return False

    @staticmethod
    def syscall_num(state):
        return state.regs.syscall_num


register_simos('BIR', SimBIR)
register_syscall_cc('BIR', 'BIR', SimBIRSyscall) # if the "second parameter" is set to 'default' you will get some warnings
register_default_cc('BIR', SimCCUnknown)
