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



class LifterBIR(Lifter):
	

    def parse(self, data):
        bir_program = ParserBIR(data)
        blocks = bir_program.parse()
        return blocks
    

    def lift(self, disassemble=False, dump_irsb=False):
        blocks = self.parse(self.data)
        irsb_c = IRSBCustomizer(self.irsb)

        try:
            bir_Instruction = BIR_Instruction(arch=archinfo.arch_from_id('bir'), addr=0)
            for block in blocks:
                irsb_c.imark(block.label, bir_Instruction.bytewidth, 0)
                for statements in block.statements:
                    bir_Instruction.map_statements(statements, irsb_c)
                bir_Instruction.map_statements(block.last_statement, irsb_c)
                #irsb_c.imark(bir_Instruction.addr, bir_Instruction.bytewidth, 0)

            irsb_c.irsb.jumpkind = JumpKind.NoDecode
            dst = irsb_c.irsb.addr + irsb_c.irsb.size
            dst_ty = vex_int_class(irsb_c.irsb.arch.bits).type
            irsb_c.irsb.next = irsb_c.mkconst(dst, dst_ty)
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
    lifter._lift(data=bir_input)
    lifter.irsb.pp()

	
