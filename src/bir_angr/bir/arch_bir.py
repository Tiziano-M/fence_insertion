from archinfo.arch import Arch, Register, Endness
from archinfo.arch import register_arch
import json


def regs_extraction_from_json(birprogjson):
    regs = []

    def extracting(j):
        if isinstance(j, dict):
            if "var" in j:
                reg = j["var"]
                if reg["name"] != "MEM" and "*" not in reg["name"]:
                    regs.append(reg)

            for (k,v) in j.items():
                if k != "var":
                    extracting(v)

        elif isinstance(j, list):
            for i in j:
                extracting(i)

    extracting(birprogjson)
    return regs

def regs_extraction_from_birprog(birprogjson):
    return regs_extraction_from_json(birprogjson)

def config_regs(regs):
    type_to_size = {
        "imm64": 8,
        "imm32": 4,
        "imm16": 2,
        "imm8": 1,
        "imm1": 1,
    }

    vex_offset = 40
    for reg in regs:
        reg_typ = reg["type"]
        try:
            sz = type_to_size[reg_typ]
        except KeyError:
            raise ValueError(f"Unknown register type: {reg_typ}")
        vex_offset = vex_offset + 8
        ArchBIR.register_list.append(Register(name=reg["name"], size=sz, vex_offset=vex_offset))

def get_unique_regs(regs):
    return sorted(
        # removes dupilcates using hashed tuples
        [dict(t) for t in {tuple(sorted(d.items())) for d in regs}],
        key=lambda k: k['name']
    )

def config_registers(birprog, def_regs):
    # extracts the registers from the input program and sets them in the register list of the architecture
    regs = regs_extraction_from_birprog(birprog)
    regs = get_unique_regs(def_regs + regs)
    config_regs(regs)
    return regs


class ArchBIR(Arch):

    memory_endness = Endness.LE
    bits = 64
    vex_arch = None
    name = "BIR"
    instruction_alignment = 1
    ip_offset = 0
    instruction_endness = "Iend_LE"
    linux_name = 'aarch64'
    triplet = 'aarch64-linux-gnueabihf'


    default_symbolic_registers = []

    def __init__(self, endness=Endness.LE):
        super(ArchBIR, self).__init__(Endness.LE)

    register_list = [
        Register(name="ip", size=8, alias_names=('pc'), vex_offset=0),
        Register(name="obs", size=8, vex_offset=8),
        Register(name="cond_obs", size=1, vex_offset=16),
        Register(name="idx_obs", size=8, vex_offset=24),
        Register(name="ip_at_syscall", size=8, vex_offset=32),
        Register(name="syscall_num", size=8, vex_offset=40)
    ]


register_arch(['bir'], 64, 'any', ArchBIR)
