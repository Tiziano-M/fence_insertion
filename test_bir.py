import archinfo
from arch_bir import ArchBIR
from parse_bir import ParserBIR
from lift_bir import LifterBIR


bir_input = open("examples/bir_program.bir", "r")
lifter = LifterBIR(arch=archinfo.arch_from_id('bir'), addr=2)
bir_program = ParserBIR(bir_input)
blocks = bir_program.parse()
irsb_list = list()
for block in blocks:
    lifter._lift(data=block)
    lifter.irsb.pp()
    irsb_list.append(lifter.irsb)
