#######################################################
######## other tests in pyvex/tests/test.py
#######################################################

import archinfo
import pyvex
from arch_bir import ArchBIR
from parse_bir import ParserBIR
from lift_bir import LifterBIR


bir_input = open("examples/test.bir", "rb")
bir_input = bir_input.read()


def test1():
    lifter = LifterBIR(arch=archinfo.arch_from_id('bir'), addr=0)
    lifter._lift(data=bir_input)
    lifter = LifterBIR(arch=archinfo.arch_from_id('bir'), addr=4)
    lifter._lift(data=bir_input)
    lifter = LifterBIR(arch=archinfo.arch_from_id('bir'), addr=8)
    lifter._lift(data=bir_input)


def test_two_irsb():
    irsb1 = pyvex.IRSB(data=bir_input, mem_addr=0, arch=archinfo.arch_from_id('bir'))
    irsb2 = pyvex.IRSB(data=bir_input, mem_addr=4, arch=archinfo.arch_from_id('bir'))


# broken
def test2():
    import angr
    import __init__
    proj = angr.Project("examples/test.bir", main_opts={'backend': 'bir'})
    irsb = proj.factory.block(proj.entry)
    irsb.vex.pp()
    #irsb = proj.factory.block(proj.entry, size = 400).vex



def main():
    test1()
    #test_two_irsb()


if __name__ == '__main__':
    main()
