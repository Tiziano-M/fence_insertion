import sys
import archinfo
from parse_bir import ParserBIR
import instrs_bir as instrs
from BIR_Instruction import BIR_Instruction

from pyvex.lifting import register, Lifter
from pyvex.lifting.util.vex_helper import *
from pyvex.errors import LiftingException
from angr.engines.vex import lifter
import logging

l = logging.getLogger(__name__)



class LifterBIR(Lifter):
    lifter.VEX_IRSB_MAX_SIZE = 10000

    cache_data = None

    def get_data(data):
        if LifterBIR.cache_data is None:
            LifterBIR.cache_data = data
        return LifterBIR.cache_data


    def parse(self):
        data = "".join(chr(i) for i in LifterBIR.get_data(self.data))
        #print(data)
        #print(self.addr)
        parser = ParserBIR(data)
        blocks = parser.parse()
        return blocks


    def lift(self, dump_irsb=True):

        try:
            blocks = self.parse()
            bir_Instruction = BIR_Instruction(arch=archinfo.arch_from_id('bir'), addr=0)

            try:
                block = next(b for b in blocks if b.label == self.addr)
            except:
                block=None

            if block is None:
                irsb_c = IRSBCustomizer(self.irsb)
                irsb_c.imark(self.addr, 1, 0)
                irsb_c.irsb.jumpkind = JumpKind.Exit
            else:
                irsb_c = IRSBCustomizer(self.irsb)
                irsb_c.imark(block.label, 1, 0)
                for statements in block.statements:
                    bir_Instruction.map_statements(statements, irsb_c)
                bir_Instruction.map_statements(block.last_statement, irsb_c)

                #if not any(block.label == int(str(irsb_c.irsb.next), 16) for block in blocks):
                #    self.irsb.jumpkind = JumpKind.Exit
        except:
            print(sys.exc_info()[0])
            raise LiftingException('Could not decode any instructions')
        if dump_irsb:
            self.irsb.pp()
            #print(self.irsb.size)
        return self.irsb
        



register(LifterBIR, 'BIR')


	
