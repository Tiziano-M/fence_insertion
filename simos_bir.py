from angr.simos import SimUserland, register_simos
from angr.calling_conventions import SimStackArg, SimRegArg, SimCC, register_syscall_cc, register_default_cc, SimCC

from arch_bir import ArchBIR


class SimCCBIR(SimCC):
    ARG_REGS = [ ]
    FP_ARG_REGS = [ ]
    STACKARG_SP_DIFF = 0
    RETURN_ADDR = SimStackArg(0, 8)
    RETURN_VAL = SimRegArg('ip', 8)
    ARCH = ArchBIR


class SimBIR(SimUserland):
    # Syscalls are for lamers
    SYSCALL_TABLE = {}

    def __init__(self, *args, **kwargs):
        super(SimBIR, self).__init__(*args, name="BIR", **kwargs)

    def state_blank(self, data_region_size=0x8000, **kwargs): # pylint:disable=arguments-differ
        state = super(SimBIR, self).state_blank(**kwargs)  # pylint:disable=invalid-name
        return state

    def state_entry(self, **kwargs):
        state = super(SimBIR, self).state_entry(**kwargs)
        return state


class SimBIRSyscall(SimCC):
    ARG_REGS = [ ]
    # RETURN_VAL = ""
    ARCH = ArchBIR

    @staticmethod
    def _match(arch, args, sp_delta):   # pylint: disable=unused-argument
        # doesn't appear anywhere but syscalls
        return False

    @staticmethod
    def syscall_num(state):
        return state.regs.inout

register_simos('BIR', SimBIR)
register_syscall_cc('BIR', 'default', SimBIRSyscall)
register_default_cc('BIR', SimCCBIR)
