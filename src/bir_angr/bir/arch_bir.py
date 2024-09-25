from archinfo.arch import Arch, Register, Endness
from archinfo.arch import register_arch
import json


def regs_extraction_from_json(birprog, regs):
    try:
        if isinstance(birprog, list):
            for dic in birprog:
                if isinstance(dic, dict):
                    for key,value in dic.items():
                        if key == "var":
                            reg = dic.get(key)
                            if reg["name"] != "MEM" and "*" not in reg["name"]:
                                regs.append(reg)
                        else:
                            regs_extraction_from_json(value, regs)
        elif isinstance(birprog, dict):
            for key,value in birprog.items():
                if key == "var":
                    reg = birprog.get(key)
                    if reg["name"] != "MEM" and "*" not in reg["name"]:
                        regs.append(reg)
                else:
                    regs_extraction_from_json(value, regs)
    except:
        raise Exception("Error of bir program in json format")
    return regs

def config_regs(regs):
    vex_offset = 40
    for reg in regs:
        reg_typ = reg["type"]
        if reg_typ == "imm64":
            sz = 8
        elif reg_typ == "imm32":
            sz = 4
        elif reg_typ == "imm16":
            sz = 2
        elif reg_typ == "imm8":
            sz = 1
        elif reg_typ == "imm1":
            sz = 1
        else:
            raise Exception(f"Unknown register type: {reg_typ}")
        vex_offset = vex_offset + 8
        ArchBIR.register_list.append(Register(name=reg["name"], size=sz, vex_offset=vex_offset))

def get_register_list(birprog):
    with open(birprog, "r") as json_file:
        birprogjson = json.load(json_file)
    # gets all BVAR in the json BIR program
    regs = regs_extraction_from_json(birprogjson, [])
    # removes dupilcates using hashed tuples
    regs = [dict(t) for t in {tuple(sorted(d.items())) for d in regs}]
    # reorders the list
    regs = sorted(regs, key=lambda k: k['name'])
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
