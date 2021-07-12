from archinfo.arch import Arch, Register, Endness
from archinfo.arch import register_arch


class ArchBIR(Arch):

    memory_endness = Endness.LE
    bits = 64
    vex_arch = None
    name = "BIR"
    instruction_alignment = 1
    ip_offset = 0
    instruction_endness = "Iend_LE"


    default_symbolic_registers = []

    def __init__(self, endness=Endness.LE):
        super(ArchBIR, self).__init__(Endness.LE)

    register_list = [
        Register(name="ip", size=8, alias_names=('pc'), vex_offset=0),
        Register(name="R0", size=8, vex_offset=8),
        Register(name="R1", size=8, vex_offset=16),
        Register(name="R2", size=8, vex_offset=24),
        Register(name="R3", size=8, vex_offset=32),
        Register(name="R4", size=8, vex_offset=40),
        Register(name="R5", size=8, vex_offset=48),
        Register(name="R6", size=8, vex_offset=56),
        Register(name="R7", size=8, vex_offset=64),
        Register(name="R8", size=8, vex_offset=72),
        Register(name="R9", size=8, vex_offset=80),
        Register(name="R10", size=8, vex_offset=88),
        Register(name="R11", size=8, vex_offset=96),
        Register(name="R12", size=8, vex_offset=104),
        Register(name="R13", size=8, vex_offset=112),
        Register(name="R14", size=8, vex_offset=120),
        Register(name="R15", size=8, vex_offset=128),
        Register(name="R16", size=8, vex_offset=136),
        Register(name="R17", size=8, vex_offset=144),
        Register(name="R18", size=8, vex_offset=152),
        Register(name="R19", size=8, vex_offset=160),
        Register(name="R20", size=8, vex_offset=168),
        Register(name="R21", size=8, vex_offset=176),
        Register(name="R22", size=8, vex_offset=184),
        Register(name="R23", size=8, vex_offset=192),
        Register(name="R24", size=8, vex_offset=200),
        Register(name="R25", size=8, vex_offset=208),
        Register(name="R26", size=8, vex_offset=216),
        Register(name="R27", size=8, vex_offset=224),
        Register(name="R28", size=8, vex_offset=232),
        Register(name="R29", size=8, vex_offset=240),
        Register(name="R30", size=8, vex_offset=248),
        Register(name="R31", size=8, vex_offset=256),
        Register(name="SP_EL0", size=8, vex_offset=264),
        Register(name="SP_EL1", size=8, vex_offset=272),
        Register(name="SP_EL2", size=8, vex_offset=280),
        Register(name="SP_EL3", size=8, vex_offset=288),
        Register(name="ProcState_C", size=1, vex_offset=289),
        Register(name="ProcState_E", size=1, vex_offset=290),
        Register(name="ProcState_N", size=1, vex_offset=291),
        Register(name="ProcState_V", size=1, vex_offset=292),
        Register(name="ProcState_Z", size=1, vex_offset=293),
        Register(name="obs", size=8, vex_offset=301),
        Register(name="ip_at_syscall", size=8, vex_offset=309),
        Register(name="syscall_num", size=8, vex_offset=317)
    ]


register_arch(['bir'], 64, 'any', ArchBIR)
