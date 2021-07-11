import sys
import archinfo
from parse_bir import ParserBIR
import instrs_bir as instrs
from BIR_Instruction import BIR_Instruction

from pyvex.lifting import register, Lifter
from pyvex.lifting.util.vex_helper import *
from pyvex.errors import LiftingException
from angr.engines.vex import lifter
from pyvex.block import IRSB
from IRSBSplitter import *
import logging

l = logging.getLogger(__name__)




class LifterBIR(Lifter):
    lifter.VEX_IRSB_MAX_SIZE = 10000

    cache_lifting = None
    cache_blocks = None


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

    def prelift(self, dump_irsb=True):
        bir_Instruction = BIR_Instruction(arch=archinfo.arch_from_id('bir'), addr=0)
        dict_irsb = {}

        try:
            blocks = self.get_blocks()

            for block in blocks:
                irsb = IRSB.empty_block(self.arch, self.addr)
                irsb_c = IRSBCustomizer(irsb)             
                is_syscall = False

                irsb_c.imark(block.label, 1, 0)
                for statements in block.statements:
                    bir_Instruction.map_statements(statements, irsb_c)
                    if irsb_c.irsb.jumpkind == JumpKind.Syscall:
                        is_syscall = True
                bir_Instruction.map_statements(block.last_statement, irsb_c)
                dict_irsb[block.label] = irsb_c

                if dump_irsb:
                    irsb_c.irsb.pp()
                if is_syscall:
                    splitter = IRSBSplitter(dict_irsb, irsb_c)
                    dict_irsb = splitter.update_dict()
        except:
            raise LiftingException('Could not decode any instructions')
        return dict_irsb

    def get_irsbs(self):
        if LifterBIR.cache_lifting is None:
            LifterBIR.cache_lifting = self.prelift()
        return LifterBIR.cache_lifting

    def lift(self, dump_irsb=True):
        try:
            irsbs = self.get_irsbs()

            print(self.addr)
            if self.addr in irsbs:
                self.irsb = irsbs[self.addr].irsb
            # 2 way to manage the exit
            #if not any(key == int(str(self.irsb.next), 16) for key in irsbs):
            #    self.irsb.jumpkind = JumpKind.Exit
            else:
                irsb_c = IRSBCustomizer(self.irsb)
                irsb_c.imark(self.addr, 1, 0)
                irsb_c.irsb.jumpkind = JumpKind.Exit
        except Exception as e:
            print(sys.exc_info()[0])
            self.errors = str(e)
            l.exception("Error decoding block at (address {:#x}):".format(self.addr))
        if dump_irsb:
            self.irsb.pp()
        return self.irsb
        



register(LifterBIR, 'BIR')


	
