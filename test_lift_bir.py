#######################################################
######## other tests in pyvex/tests/test.py
#######################################################

import logging
import archinfo
import pyvex
from bir.arch_bir import *
from bir.parse_bir import ParserBIR
from bir.lift_bir import LifterBIR


get_register_list("examples/json/test3.bir")
bir_input = open("examples/json/test3.bir", "rb")
bir_input = bir_input.read()


def test1():
    lifter = LifterBIR(arch=archinfo.arch_from_id('bir'), addr=0)
    lifter._lift(data=bir_input)
    lifter = LifterBIR(arch=archinfo.arch_from_id('bir'), addr=4)
    lifter._lift(data=bir_input)
    lifter = LifterBIR(arch=archinfo.arch_from_id('bir'), addr=8)
    lifter._lift(data=bir_input)


def test2():
    import angr
    proj = angr.Project("examples/json/test3.bir")
    irsb = proj.factory.block(addr=0)
    irsb.vex.pp()
    #irsb = proj.factory.block(proj.entry, size = 400).vex


def test3():
    irsb1 = pyvex.IRSB(data=bir_input, mem_addr=0, arch=archinfo.arch_from_id('bir'))
    irsb2 = pyvex.IRSB(data=bir_input, mem_addr=4, arch=archinfo.arch_from_id('bir'))




def main():
    logging.getLogger('pyvex').setLevel(logging.DEBUG)
    logging.basicConfig()
    test1()


if __name__ == '__main__':
    main()
