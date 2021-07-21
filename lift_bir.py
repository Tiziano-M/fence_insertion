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
from angr.errors import *


def cleanup_cache_lifting():
    # Resets the IRSB dictionary in order to execute the lifting of a new program.
    # There is another static value (obs_dst) in IRSBSplitter,
    # but there is no need to reset it, as it is updated by one each time it is used.
    LifterBIR.cache_lifting = None



class LifterBIR(Lifter):
    lifter.VEX_IRSB_MAX_SIZE = 10000

    cache_lifting = None


    def get_blocks(self):
        # Returns the list of BIR blocks taken as input self.data (the BIR program)
        # self.data: the bytes to lift as either a python string of bytes
        data = "".join(chr(i) for i in self.data)
        #print(data)
        parser = ParserBIR(data)
        blocks = parser.parse()
        return blocks

    def prelift(self, dump_irsb=True):
        bir_Instruction = BIR_Instruction(arch=archinfo.arch_from_id('bir'), addr=0)
        dict_irsb = {}

        try:
            blocks = self.get_blocks()

            for block in blocks:
                irsb = IRSB.empty_block(self.arch, self.addr)
                irsb_c = IRSBCustomizer(irsb)             
                irsb_c.imark(block.label, 1, 0)

                is_syscall = False           
                for statements in block.statements:
                    bir_Instruction.map_statements(statements, irsb_c)
                    # this check is used to find blocks with Observe statement
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
        print("Pre-Lifting: Done!\n")
        return dict_irsb

    def get_irsbs(self):
        # Builds a IRSB dictionary to use it in the 'lift' function and already have all the irsb blocks translated
        if LifterBIR.cache_lifting is None:
            LifterBIR.cache_lifting = self.prelift()
        return LifterBIR.cache_lifting

    def lift(self, dump_irsb=True):
        try:
            irsbs = self.get_irsbs()

            #print(self.addr)
            if self.addr in irsbs:
                self.irsb = irsbs[self.addr].irsb
            # 2 way to manage the exit
            #if not any(key == int(str(self.irsb.next), 16) for key in irsbs):
            #    self.irsb.jumpkind = JumpKind.Exit
            elif self.addr == 0x400:
                self.irsb.jumpkind = JumpKind.NoDecode
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

