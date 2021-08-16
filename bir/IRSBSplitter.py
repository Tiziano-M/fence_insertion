import archinfo
import pyvex
from pyvex.lifting.util.vex_helper import *
from pyvex.block import IRSB


class IRSBSplitter:
    """
    Splits a IRSB in two blocks where there is the first system call (observation).

    :param dict_irsb:       IRSB dictionary.
    :param last_irsb:       The last IRSB block (already added to the dictionary) to be split.
    :returns:               The updated IRSB dictionary.
    :rtype:                 dict
    """    

    # default syscall address where lifting starts
    obs_dst = 0x700
    
    def __init__(self, dict_irsb, last_irsb):
        self.dict_irsb = dict_irsb
        self.last_irsb = last_irsb
        self.break_index = self.split_irsb() + 1
    
    def split_irsb(self):
        for i, stmts in enumerate(self.last_irsb.irsb.statements):
            if hasattr(stmts, 'jumpkind') and stmts.jumpkind == JumpKind.Syscall:
                # point where to split the irsb in two ones
                break_index = i
                break
        return break_index

    def get_irsb2(self):
        next_irsb = self.last_irsb.irsb.copy()
        next_irsb_c = IRSBCustomizer(next_irsb)

        next_irsb_c.irsb.statements = next_irsb_c.irsb.statements[self.break_index:]
        IRSBSplitter.obs_dst = IRSBSplitter.obs_dst + 1
        next_irsb_c.irsb.statements.insert(0, pyvex.IRStmt.IMark(IRSBSplitter.obs_dst, 1, 0))
        return next_irsb_c

    def get_irsb1(self):
        self.last_irsb.irsb.statements = self.last_irsb.irsb.statements[:self.break_index]
        # change the default address (0x700) to the updated one (obs_dst)
        setattr(self.last_irsb.irsb.statements[-1].dst, "_value", IRSBSplitter.obs_dst)
        obs_dst_ty = vex_int_class(self.last_irsb.arch.bits).type
        self.last_irsb.irsb.next = self.last_irsb.mkconst(IRSBSplitter.obs_dst, obs_dst_ty)
        return self.last_irsb

    def check_syscall(self, next_irsb):
        is_syscall = False
        for stmts in next_irsb.irsb.statements:
            if hasattr(stmts, 'jumpkind') and stmts.jumpkind == JumpKind.Syscall:
                is_syscall = True
                break
        return is_syscall
        
    def update_dict(self, dump_irsb=True):
        irsb2 = self.get_irsb2()
        irsb1 = self.get_irsb1()
        if dump_irsb:
            irsb1.irsb.pp()
            irsb2.irsb.pp()

        self.dict_irsb[IRSBSplitter.obs_dst] = irsb2
        is_syscall = self.check_syscall(irsb2)
        if is_syscall:
            splitter = IRSBSplitter(self.dict_irsb, irsb2)
            self.dict_irsb = splitter.update_dict()
        return self.dict_irsb



