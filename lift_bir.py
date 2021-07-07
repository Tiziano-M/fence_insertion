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
    bir_Instruction = BIR_Instruction(arch=archinfo.arch_from_id('bir'), addr=0)

    cache_blocks = None
    previous_block = None
    count_previous_block = 0 # number of executed statements of the previous block

    def parse(data):
        data = "".join(chr(i) for i in data)
        #print(data)
        parser = ParserBIR(data)
        blocks = parser.parse()
        return blocks
    
    def get_blocks(self):
        if LifterBIR.cache_blocks is None:
            LifterBIR.cache_blocks = LifterBIR.parse(self.data)
        return LifterBIR.cache_blocks

    def get_block(self, blocks):
        print(self.addr)
        print(LifterBIR.count_previous_block)
        for b in blocks:
            if b.label == self.addr:
                block = b
                break
            else:
                if LifterBIR.previous_block is None:
                    block = None
                else:
                    block = LifterBIR.previous_block
                    block.statements = block.statements[LifterBIR.count_previous_block:]
                    LifterBIR.count_previous_block = 0
                    LifterBIR.previous_block = None
                    break
        return block
        

    def lift(self, dump_irsb=True):

        try:
            blocks = self.get_blocks()
            block = self.get_block(blocks)

            if block is None:
                irsb_c = IRSBCustomizer(self.irsb)
                irsb_c.imark(self.addr, 1, 0)
                irsb_c.irsb.jumpkind = JumpKind.Exit
            else:
                LifterBIR.count_previous_block = 0
                irsb_c = IRSBCustomizer(self.irsb)
                irsb_c.imark(block.label, 1, 0)
                for statements in block.statements:
                    if self.irsb.jumpkind != JumpKind.Syscall:
                        LifterBIR.count_previous_block += 1
                    else:
                        LifterBIR.previous_block = block
                        dst = 0x1
                        dst_ty = vex_int_class(irsb_c.irsb.arch.bits).type
                        irsb_c.irsb.next = irsb_c.mkconst(dst, dst_ty)
                        irsb_c.irsb.jumpkind = JumpKind.Boring
                        if dump_irsb:
                            self.irsb.pp()
                        return self.irsb
                    LifterBIR.bir_Instruction.map_statements(statements, irsb_c)
                LifterBIR.bir_Instruction.map_statements(block.last_statement, irsb_c)
                                          

                # 2 way to manage the exit
                #if not any(block.label == int(str(irsb_c.irsb.next), 16) for block in blocks):
                #    self.irsb.jumpkind = JumpKind.Exit
        except:
            print(sys.exc_info()[0])
            raise LiftingException('Could not decode any instructions')
        if dump_irsb:
            self.irsb.pp()
        return self.irsb
        



register(LifterBIR, 'BIR')


	
