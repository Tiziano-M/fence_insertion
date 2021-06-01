from pyvex.lifting.util import Type, JumpKind
from BIR_Instruction import BIR_Instruction
import logging


l = logging.getLogger(__name__)



class Instruction_ASSIGN(BIR_Instruction):
	
    def __init__(self, arch, addr, block, irsb_c):
        super().__init__(arch, addr)
        self.block = block
        self.irsb_c = irsb_c

    def get_arguments1(self, block):
        REGISTER_NAME, REGISTER_TYPE = self.map_expressions(block[0], self.irsb_c)
        return REGISTER_NAME, REGISTER_TYPE

    def get_arguments2(self, block):
        self.map_expressions(block[1], self.irsb_c)

    def compute_result(self):
        reg = self.get_arguments1(self.block)[0]
        self.get_arguments2(self.block) #VexValue object
        val = self.get("ptr", Type.int_64)
        self.put(val, reg)


class Instruction_BINEXP(BIR_Instruction):
	
    def __init__(self, arch, addr, block, irsb_c):
        super().__init__(arch, addr)
        self.block = block
        self.irsb_c = irsb_c

    def get_operator(self, block):
        operator = block[0]
        return operator

    def get_operand1(self, block):
        REGISTER_NAME, REGISTER_TYPE = self.map_expressions(block[1], self.irsb_c)
        operand1 = self.get(REGISTER_NAME, REGISTER_TYPE)
        return operand1

    def get_operand2(self, block):
        if (block[2][0].label() == "BVar"):
            REGISTER_NAME, REGISTER_TYPE = self.map_expressions(block[2], self.irsb_c)
            operand2 = self.get(REGISTER_NAME, REGISTER_TYPE)
        else:
            imm, imm_ty = self.map_expressions(block[2], self.irsb_c)
            operand2 = int(imm)
        return operand2
        
    
    def compute_result(self):
        operator = self.get_operator(self.block)
        operand1 = self.get_operand1(self.block)
        operand2 = self.get_operand2(self.block)

        if operator == "BIExp_And":
            self.put(operand1 & operand2, "ptr")
        elif operator == "BIExp_Or":
            self.put(operand1 | operand2, "ptr")
        elif operator == "BIExp_Xor":
            self.put(operand1 ^ operand2, "ptr")
        elif operator == "BIExp_Plus":
            self.put(operand1 + operand2, "ptr")
        elif operator == "BIExp_Minus":
            self.put(operand1 - operand2, "ptr")
        elif operator == "BIExp_Mult":
            self.put(operand1 * operand2, "ptr")
        elif operator == "BIExp_Div":
            self.put(operand1 // operand2, "ptr")
        elif operator == "BIExp_SignedDiv":
            self.put(operand1 / operand2, "ptr")
        elif operator == "BIExp_Mod":
            self.put(operand1 % operand2, "ptr")
        #elif operator == "BIExp_SignedMod":
        #    self.put(operand1 ??? operand2, "ptr")
        elif operator == "BIExp_LeftShift":
            self.put(operand1 << operand2, "ptr")
        elif operator == "BIExp_RightShift":
            self.put(operand1 >> operand2, "ptr")
        #elif operator == "BIExp_SignedRightShift":
        #    self.put(operand1 ??? operand2, "ptr")
 

class Instruction_LOAD(BIR_Instruction):
	
    def __init__(self, arch, addr, block, irsb_c):
        super().__init__(arch, addr)
        self.block = block
        self.irsb_c = irsb_c

    def get_register_type(self, block):
        REGISTER_TYPE_LOAD = block[3]
        if (REGISTER_TYPE_LOAD == "Bit64"):
    	    REGISTER_TYPE_LOAD = Type.int_64
        elif (REGISTER_TYPE_LOAD == "Bit32"):
    	    REGISTER_TYPE_LOAD = Type.int_32
        return REGISTER_TYPE_LOAD

    def get_register_from_bvar(self, block):
        REGISTER_NAME, REGISTER_TYPE = self.map_expressions(block[1], self.irsb_c)
        return REGISTER_NAME, REGISTER_TYPE

    def get_register_from_binexp(self, block):
        self.map_expressions(block[1], self.irsb_c)
        val = self.get("ptr", Type.int_64)
        return val

    def compute_result(self):
        REGISTER_TYPE_LOAD = self.get_register_type(self.block)
        if (self.block[1].label() == "BExp_BinExp"):
            addr_val = self.get_register_from_binexp(self.block) #reg_vv + imm
        else:
            REGISTER_NAME, REGISTER_TYPE = self.get_register_from_bvar(self.block)
            addr_val = self.get(REGISTER_NAME, REGISTER_TYPE)

        val = self.load(addr_val, REGISTER_TYPE_LOAD)
        self.put(val, "ptr")


class Instruction_STORE(BIR_Instruction):
	
    def __init__(self, arch, addr, block, irsb_c):
        super().__init__(arch, addr)
        self.block = block
        self.irsb_c = irsb_c

    def get_register_from_bvar(self, block):
        REGISTER_NAME, REGISTER_TYPE = self.map_expressions(block[1], self.irsb_c)
        return REGISTER_NAME, REGISTER_TYPE

    def get_register_from_binexp(self, block):
        self.map_expressions(block[1], self.irsb_c)
        val = self.get("ptr", Type.int_64)
        return val

    def get_value_to_store(self, block):
        REGISTER_NAME, REGISTER_TYPE = self.map_expressions(self.block[3], self.irsb_c)
        val = self.get(REGISTER_NAME, REGISTER_TYPE)
        return val

    def compute_result(self):
        if (self.block[1].label() == "BExp_BinExp"):
            addr_val = self.get_register_from_binexp(self.block) #reg_vv + imm
        else:
            REGISTER_NAME, REGISTER_TYPE = self.get_register_from_bvar(self.block)
            addr_val = self.get(REGISTER_NAME, REGISTER_TYPE)
        val = self.get_value_to_store(self.block)

        self.store(val, addr_val)
        #self.put(val, "ptr")


class Instruction_BVAR(BIR_Instruction):
    
    def get_register(self, block):
        REGISTER_NAME = block[0].strip('"')
        assert block[1].label() == "BType_Imm"
        REGISTER_TYPE = block[1][0]
        
        if (REGISTER_TYPE == "Bit64"):
    	    REGISTER_TYPE = Type.int_64
        elif (REGISTER_TYPE == "Bit32"):
    	    REGISTER_TYPE = Type.int_32

        return (REGISTER_NAME, REGISTER_TYPE)


class Instruction_JMP(BIR_Instruction):
	
    def __init__(self, arch, addr, block, irsb_c):
        super().__init__(arch, addr)
        self.block = block
        self.irsb_c = irsb_c

    def get_address(self, block):
        addr, ty = self.map_expressions(block[0][0], self.irsb_c)
        if (ty == "Imm64"):
            ty = Type.int_64
        elif (ty == "Imm32"):
    	    ty = Type.int_32
        return addr, ty

    def compute_result(self):
        addr, ty = self.get_address(self.block)
        self.jump(None, self.constant(addr, ty), jumpkind=JumpKind.Boring)


class Instruction_HALT(BIR_Instruction):
	
    def __init__(self, arch, addr, block, irsb_c):
        super().__init__(arch, addr)
        self.block = block
        self.irsb_c = irsb_c

    def get_address(self, block):
        addr, ty = self.map_expressions(block[0], self.irsb_c)
        if (ty == "Imm64"):
            ty = Type.int_64
        elif (ty == "Imm32"):
    	    ty = Type.int_32
        return addr, ty

    def compute_result(self):
        addr, ty = self.get_address(self.block)
        self.jump(None, self.constant(addr, ty), jumpkind=JumpKind.Exit)









