from arch_bir import ArchBIR
import instrs_bir as instrs
from parser_bir import ParserBIR
from BIR_Instruction import BIR_Instruction

from pyvex.lifting import register, Lifter
from pyvex.lifting.util.vex_helper import *
from pyvex.errors import LiftingException
import archinfo
import logging

l = logging.getLogger(__name__)

import angr
import pyvex
from angr.engines import SimEngine, SimSuccessors#, SimEngineVEX, SimEngineProcedure, SimEngineUnicorn
from angr.engines.vex import HeavyVEXMixin, TrackActionsMixin, SimInspectMixin, HeavyResilienceMixin, SuperFastpathMixin


class LifterBIR(Lifter):
	

    def parse(self, data):
        bir_program = ParserBIR(data)
        blocks = bir_program.parse()
        return blocks
    

    def lift(self, disassemble=False, dump_irsb=False):
        #blocks = self.parse(self.data)
        #irsb_c = IRSBCustomizer(self.irsb)

        try:
            bir_Instruction = BIR_Instruction(arch=archinfo.arch_from_id('bir'), addr=0)

            irsb_c = IRSBCustomizer(self.irsb)
            irsb_c.imark(block.label, bir_Instruction.bytewidth, 0)
            for statements in block.statements:
                bir_Instruction.map_statements(statements, irsb_c)
            bir_Instruction.map_statements(block.last_statement, irsb_c)
        except:
            raise LiftingException('Could not decode any instructions')
        if dump_irsb:
            self.irsb.pp()
        return self.irsb
        


register(LifterBIR, 'BIR')



if __name__ == '__main__':
    #sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    logging.getLogger('pyvex').setLevel(logging.DEBUG)
    logging.basicConfig()


    bir_input = open("examples/bir_program.txt", "r")
    lifter = LifterBIR(arch=archinfo.arch_from_id('bir'), addr=2)
    bir_program = ParserBIR(bir_input)
    blocks = bir_program.parse()
    irsb_list = list()
    for block in blocks:
        lifter._lift(data=block)
        lifter.irsb.pp()
        irsb_list.append(lifter.irsb)


    test = HeavyVEXMixin(project=None)
    print(test)

	
