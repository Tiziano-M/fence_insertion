from angr.simos import SimUserland, register_simos
from angr.calling_conventions import SimStackArg, SimRegArg, SimCC, register_syscall_cc, register_default_cc
from angr import SimProcedure
from angr.procedures import SIM_PROCEDURES as P, SIM_LIBRARIES as L
from angr.procedures.definitions import SimSyscallLibrary

from arch_bir import ArchBIR



class Observation(SimProcedure):

    num_args = 1
    NUM_ARGS = 1

    def run(self, obs):
        print("\nObservation:", obs, "\n")
        #self.state.obs_list.append(obs)
        #self.jump(0x3) 



P['bir'] = {}
P['bir']['observation'] = Observation

syscall_lib = SimSyscallLibrary()
syscall_lib.set_library_names('bir')
syscall_lib.add_all_from_dict(P['bir'])
syscall_lib.add_number_mapping_from_dict('BIR', {0 : 'observation'})


class SimCCBIR(SimCC):
    ARG_REGS = ['obs']
    FP_ARG_REGS = [ ]
    STACKARG_SP_DIFF = 0
    RETURN_ADDR = SimRegArg('ip', 8)
    RETURN_VAL = SimRegArg('obs', 8)
    ARCH = ArchBIR


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
    ARG_REGS = ['obs']
    RETURN_ADDR = SimRegArg('ip', 8)
    RETURN_VAL = SimRegArg('obs', 8)
    ARCH = ArchBIR

    @staticmethod
    def _match(arch, args, sp_delta):   # pylint: disable=unused-argument
        # doesn't appear anywhere but syscalls
        return False

    @staticmethod
    def syscall_num(state):
        return state.regs.ip_at_syscall


register_simos('BIR', SimBIR)
register_syscall_cc('BIR', 'default', SimBIRSyscall)
register_default_cc('BIR', SimCCBIR)
