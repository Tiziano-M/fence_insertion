import sys
import archinfo
from .parse_bir import ParserBIR
from .IRSBSplitter import *

from pyvex.lifting import register, Lifter
from pyvex.lifting.util.vex_helper import *
from pyvex.errors import LiftingException
from angr.engines.vex import lifter
from pyvex.block import IRSB
import logging

l = logging.getLogger(__name__)



def cleanup_cache_lifting():
    # Resets the IRSB dictionary in order to execute the lifting of a new program.
    LifterBIR.cache_lifting = None


def set_extern_val(addr, dump_irsb, birprogjson):
    LifterBIR.extern_addr = addr
    LifterBIR._dump_irsb = dump_irsb
    LifterBIR._birprogjson = birprogjson



class LifterBIR(Lifter):
    REQUIRE_DATA_PY = True
    lifter.VEX_IRSB_MAX_SIZE = sys.maxsize
    #lifter.VEX_IRSB_MAX_INST = 99

    cache_lifting = None
    extern_addr = None
    _dump_irsb = None
    _birprogjson = None

    def prelift(self, dump_irsb=False):
        bir_Instruction = BIR_Instruction(arch=archinfo.arch_from_id('bir'), addr=0)
        dict_irsb = {}

        try:
            blocks = ParserBIR.parse(LifterBIR._birprogjson)

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
                bir_Instruction.map_last_statement(block.last_statement, irsb_c)
                dict_irsb[block.label] = irsb_c

                if dump_irsb:
                    irsb_c.irsb.pp()
                if is_syscall:
                    if IRSBSplitter.obs_dst is None:
                        IRSBSplitter.obs_dst = LifterBIR.extern_addr
                    splitter = IRSBSplitter(dict_irsb, irsb_c)
                    dict_irsb = splitter.update_dict()
        except:
            l.error("Pre-lifting Error: Block Address {:#x}".format(block.label))
            raise LiftingException('Could not decode any instructions')
        print("I - Pre-Lifting: Done!\n")
        return dict_irsb

    def get_irsbs(self):
        # Builds a IRSB dictionary to use it in the 'lift' function and already have all the irsb blocks translated
        if LifterBIR.cache_lifting is None:
            LifterBIR.cache_lifting = self.prelift()
        return LifterBIR.cache_lifting

    def lift(self):
        try:
            irsbs = self.get_irsbs()

            #print(self.addr)
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
        if LifterBIR._dump_irsb:
            self.irsb.pp()
        return self.irsb
        



register(LifterBIR, 'BIR')


from . import instrs_bir as instrs
from .BIR_Instruction import BIR_Instruction
