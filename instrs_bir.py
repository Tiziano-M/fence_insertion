from pyvex.lifting.util import Type, JumpKind
from BIR_Instruction import BIR_Instruction
import logging


l = logging.getLogger(__name__)



class Instruction_ASSIGN(BIR_Instruction):
	
    def __init__(self, arch, addr, block, irsb_c):
        super().__init__(arch, addr)
        self.block = block
        self.irsb_c = irsb_c

    def get_arguments1(self):
        REGISTER_NAME, REGISTER_TYPE = self.map_expressions(self.block[0], self.irsb_c)
        return REGISTER_NAME

    def get_arguments2(self):
        val = self.map_expressions(self.block[1], self.irsb_c)
        return val

    def compute_result(self):
        reg = self.get_arguments1()
        val = self.get_arguments2()
        self.put(val, reg)


class Instruction_BINEXP(BIR_Instruction):
	
    def __init__(self, arch, addr, block, irsb_c):
        super().__init__(arch, addr)
        self.block = block
        self.irsb_c = irsb_c

    def get_operator(self):
        operator = self.block[0]
        return operator

    def get_operand1(self):
        val = self.map_expressions(self.block[1], self.irsb_c)
        return val

    def get_operand2(self):
        val = self.map_expressions(self.block[2], self.irsb_c)
        return val
        
    def compute_result(self):
        operator = self.get_operator()
        operand1 = self.get_operand1()
        operand2 = self.get_operand2()

        if operator == "BIExp_And":
            val = operand1 & operand2
        elif operator == "BIExp_Or":
            val = operand1 | operand2
        elif operator == "BIExp_Xor":
            val = operand1 ^ operand2
        elif operator == "BIExp_Plus":
            val = operand1 + operand2
        elif operator == "BIExp_Minus":
            val = operand1 - operand2
        elif operator == "BIExp_Mult":
            val = operand1 * operand2
        elif operator == "BIExp_Div":
            val = operand1 // operand2
        elif operator == "BIExp_SignedDiv":
            val = operand1 / operand2
        elif operator == "BIExp_Mod":
            val = operand1 % operand2
        #elif operator == "BIExp_SignedMod":
        #    val = operand1 ??? operand2
        elif operator == "BIExp_LeftShift":
            val = operand1 << operand2
        elif operator == "BIExp_RightShift":
            val = operand1 >> operand2
        #elif operator == "BIExp_SignedRightShift":
        #    val = operand1 ??? operand2
        return val
 

class Instruction_LOAD(BIR_Instruction):
	
    def __init__(self, arch, addr, block, irsb_c):
        super().__init__(arch, addr)
        self.block = block
        self.irsb_c = irsb_c

    def get_register_type(self):
        REGISTER_TYPE_LOAD = self.block[3]
        if (REGISTER_TYPE_LOAD == "Bit64"):
    	    REGISTER_TYPE_LOAD = Type.int_64
        elif (REGISTER_TYPE_LOAD == "Bit32"):
    	    REGISTER_TYPE_LOAD = Type.int_32
        return REGISTER_TYPE_LOAD

    def compute_result(self):
        REGISTER_TYPE_LOAD = self.get_register_type()
        addr_val = self.map_expressions(self.block[1], self.irsb_c)

        val = self.load(addr_val, REGISTER_TYPE_LOAD)
        return val


class Instruction_STORE(BIR_Instruction):
	
    def __init__(self, arch, addr, block, irsb_c):
        super().__init__(arch, addr)
        self.block = block
        self.irsb_c = irsb_c

    def compute_result(self):
        addr_val = self.map_expressions(self.block[1], self.irsb_c)
        val = self.map_expressions(self.block[3], self.irsb_c)

        self.store(val, addr_val)


class Instruction_CAST(BIR_Instruction):
	
    def __init__(self, arch, addr, block, irsb_c):
        super().__init__(arch, addr)
        self.block = block
        self.irsb_c = irsb_c

    def get_type(self):
        ty_cast = self.block[2]
        if (ty_cast == "Bit64"):
    	    ty_cast = Type.int_64
        elif (ty_cast == "Bit32"):
    	    ty_cast = Type.int_32
        return ty_cast

    def compute_result(self):
        val = self.map_expressions(self.block[1], self.irsb_c)
        ty = self.get_type()
        
        if self.block[0] == "BIExp_UnsignedCast":
            val = val.cast_to(ty, signed=False)
        elif self.block[0] == "BIExp_SignedCast":
            val = val.cast_to(ty, signed=True)
        elif self.block[0] == "BIExp_HighCast":
            val = val.cast_to(ty, high=True)
        elif self.block[0] == "BIExp_LowCast":
            val = val.cast_to(ty, high=False)
        return val


class Instruction_DEN(BIR_Instruction):
	
    def __init__(self, arch, addr, block, irsb_c):
        super().__init__(arch, addr)
        self.block = block
        self.irsb_c = irsb_c

    def get_register(self):
        REGISTER_NAME, REGISTER_TYPE = self.map_expressions(self.block[0], self.irsb_c)
        return REGISTER_NAME, REGISTER_TYPE

    def compute_result(self):
        reg, ty = self.get_register()
        val = self.get(reg, ty)
        return val


class Instruction_BVAR(BIR_Instruction):
    
    def get_register(self, block):
        REGISTER_NAME = block[0].strip('"')
        if isinstance(block[1], str):
            if block[1] == "BType_Bool":
                REGISTER_TYPE = Type.int_8
        else:
            if block[1].label() == "BType_Imm":
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

    def get_address(self):
        addr, ty = self.map_expressions(self.block[0][0], self.irsb_c)
        if (ty == "Imm64"):
            ty = Type.int_64
        elif (ty == "Imm32"):
    	    ty = Type.int_32
        return int(addr), ty

    def compute_result(self):
        addr, ty = self.get_address()
        self.jump(None, self.constant(addr, ty))


class Instruction_CJMP(BIR_Instruction):
	
    def __init__(self, arch, addr, block, irsb_c):
        super().__init__(arch, addr)
        self.block = block
        self.irsb_c = irsb_c

    def get_condition(self):
        condition = self.map_expressions(self.block[0], self.irsb_c)
        return condition

    def get_address1(self):
        addr, ty = self.map_expressions(self.block[1][0], self.irsb_c)
        if (ty == "Imm64"):
            ty = Type.int_64
        elif (ty == "Imm32"):
            ty = Type.int_32
        return int(addr), ty

    def get_address2(self):
        addr, ty = self.map_expressions(self.block[2][0], self.irsb_c)
        if (ty == "Imm64"):
            ty = Type.int_64
        elif (ty == "Imm32"):
            ty = Type.int_32
        return int(addr), ty

    def compute_result(self):
        condition = self.get_condition()
        addr1, ty1 = self.get_address1()
        addr2, ty2 = self.get_address2()
        self.addr = addr1
        self.jump(condition, self.constant(addr2, ty2))


class Instruction_HALT(BIR_Instruction):
	
    def __init__(self, arch, addr, block, irsb_c):
        super().__init__(arch, addr)
        self.block = block
        self.irsb_c = irsb_c

    def get_address(self):
        addr, ty = self.map_expressions(self.block[0], self.irsb_c)
        if (ty == "Imm64"):
            ty = Type.int_64
        elif (ty == "Imm32"):
    	    ty = Type.int_32
        return addr, ty

    def compute_result(self):
        addr, ty = self.get_address()
        self.jump(None, self.constant(addr, ty), jumpkind=JumpKind.Exit)









