from archinfo.arch import Arch, Register, Endness
from archinfo.arch import register_arch


class ArchBIR(Arch):

    memory_endness = Endness.LE
    bits = 64
    vex_arch = None
    name = "BIR"
    instruction_alignment = 1
    ip_offset = 0


    default_symbolic_registers = []

    def __init__(self, endness=Endness.LE):
        # forces little endian
        super().__init__(Endness.LE)

    register_list = [
        Register(name="R0", size=8, vex_offset=0),
        Register(name="R1", size=8, vex_offset=8),
        Register(name="R2", size=8, vex_offset=16),
        Register(name="R3", size=8, vex_offset=24),
        Register(name="R4", size=8, vex_offset=32),
        Register(name="R5", size=8, vex_offset=40),
        Register(name="R6", size=8, vex_offset=48),
        Register(name="R7", size=8, vex_offset=56),
        Register(name="R8", size=8, vex_offset=64),
        Register(name="R9", size=8, vex_offset=72),
        Register(name="R10", size=8, vex_offset=80),
        Register(name="SP_EL0", size=8, vex_offset=88),
        Register(name="ptr", size=8, vex_offset=96),
        Register(name="inout", size=1, vex_offset=104),
        Register(name="ip_at_syscall", size=8, vex_offset=112),
    ]


register_arch(['bir'], 64, 'any', ArchBIR)
