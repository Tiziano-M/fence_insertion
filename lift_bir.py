import archinfo
import instrs_bir as instrs
from BIR_Instruction import BIR_Instruction

from pyvex.lifting import register, Lifter
from pyvex.lifting.util.vex_helper import *
from pyvex.errors import LiftingException
import logging

l = logging.getLogger(__name__)



class LifterBIR(Lifter):
	    


    def lift(self, dump_irsb=False):
            	
        try:
            block = self.data
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


	
