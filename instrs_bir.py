import re
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
        if not isinstance(self.block[1], str):
            if self.block[1].label() == "BExp_Store":
                val = self.map_expressions(self.block[1], self.irsb_c)
            else:
                val = self.map_expressions(self.block[1], self.irsb_c)
        else:
            if (self.block[1] == "bir_exp_true"):
                val = self.constant(1, Type.int_8)
            elif (self.block[1] == "bir_exp_false"):
                val = self.constant(0, Type.int_8)
        return val

    def compute_result(self):
        val = self.get_arguments2()
        if not val:
            return
        reg = self.get_arguments1()
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
        elif operator == "BIExp_SignedMod":
            val = operand1 % operand2
            val.is_signed = True
        elif operator == "BIExp_LeftShift":
            val = (operand1.cast_to(Type.int_8) << operand2.cast_to(Type.int_8)).cast_to(Type.int_64)
        elif operator == "BIExp_RightShift":
            val = (operand1.cast_to(Type.int_8) >> operand2.cast_to(Type.int_8)).cast_to(Type.int_64)
        elif operator == "BIExp_SignedRightShift":
            val = operand1 >> operand2
            val.is_signed = True
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
        elif (REGISTER_TYPE_LOAD == "Bit16"):
    	    REGISTER_TYPE_LOAD = Type.int_16
        elif (REGISTER_TYPE_LOAD == "Bit8"):
    	    REGISTER_TYPE_LOAD = Type.int_8
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
        elif (ty_cast == "Bit16"):
    	    ty_cast = Type.int_16
        elif (ty_cast == "Bit8"):
    	    ty_cast = Type.int_8
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


class Instruction_UNARY(BIR_Instruction):
	
    def __init__(self, arch, addr, block, irsb_c):
        super().__init__(arch, addr)
        self.block = block
        self.irsb_c = irsb_c

    def compute_result(self):
        val = self.map_expressions(self.block[1], self.irsb_c)

        if self.block[0] == "BIExp_ChangeSign":
            raise Exception("BIExp_ChangeSign found!")
        elif self.block[0] == "BIExp_Not":
            val = ~val
        elif self.block[0] == "BIExp_CLZ":
            raise Exception("BIExp_CLZ found!")
        elif self.block[0] == "BIExp_CLS":
            raise Exception("BIExp_CLS found!")
        return val


class Instruction_BINPRED(BIR_Instruction):
	
    def __init__(self, arch, addr, block, irsb_c):
        super().__init__(arch, addr)
        self.block = block
        self.irsb_c = irsb_c

    def compute_result(self):
        val1 = self.map_expressions(self.block[1], self.irsb_c)
        val2 = self.map_expressions(self.block[2], self.irsb_c)

        if self.block[0] == "BIExp_Equal":
            val = val1 == val2
        elif self.block[0] == "BIExp_NotEqual":
            val = val1 != val2
        elif self.block[0] == "BIExp_LessThan":
            val = val1 < val2
        elif self.block[0] == "BIExp_SignedLessThan":
            val = val1 < val2
            val.is_signed = True
        elif self.block[0] == "BIExp_LessOrEqual":
            val = val1 <= val2
        elif self.block[0] == "BIExp_SignedLessOrEqual":
            val = val1 <= val2
            val.is_signed = True
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


class Instruction_CONST(BIR_Instruction):
	
    def __init__(self, arch, addr, block, irsb_c):
        super().__init__(arch, addr)
        self.block = block
        self.irsb_c = irsb_c

    def get_value(self):
        Imm = self.block[0][0]
        Imm = re.sub(r'[^a-zA-Z0-9\[\]]',' ', str(Imm))
        Imm = Imm.split()[0][:-1]
        Imm = int(Imm, 16)
        return Imm

    def get_type(self):
        ty = self.block[0].label()
        if (ty == "Imm64"):
            ty = Type.int_64
        elif (ty == "Imm32"):
    	    ty = Type.int_32
        elif (ty == "Imm16"):
    	    ty = Type.int_16
        elif (ty == "Imm8"):
    	    ty = Type.int_8
        elif (ty == "Imm1"):
    	    ty = Type.int_1
        return ty

    def compute_result(self):
        Imm = self.get_value()
        ty = self.get_type()
        val = self.constant(Imm, ty)
        return val


class Instruction_LABEL(BIR_Instruction):
	
    def __init__(self, arch, addr, block, irsb_c):
        super().__init__(arch, addr)
        self.block = block
        self.irsb_c = irsb_c

    def compute_result(self):
        val = self.map_expressions(self.block[0], self.irsb_c)
        return val


class Instruction_ADDRESS(BIR_Instruction):
	
    def __init__(self, arch, addr, block, irsb_c):
        super().__init__(arch, addr)
        self.block = block
        self.irsb_c = irsb_c

    def get_addr(self):
        addr = self.block[0][0]
        addr = re.sub(r'[^a-zA-Z0-9\[\]]',' ', str(addr))
        addr = addr.split()[0][:-1]
        return int(addr)

    def get_type(self):
        ty = self.block[0].label()
        if (ty == "Imm64"):
            ty = Type.int_64
        elif (ty == "Imm32"):
    	    ty = Type.int_32
        elif (ty == "Imm16"):
    	    ty = Type.int_16
        elif (ty == "Imm8"):
    	    ty = Type.int_8
        return ty

    def compute_result(self):
        addr = self.get_addr()
        ty = self.get_type()
        val = self.constant(addr, ty)
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
                elif (REGISTER_TYPE == "Bit16"):
    	            REGISTER_TYPE = Type.int_16
                elif (REGISTER_TYPE == "Bit8"):
    	            REGISTER_TYPE = Type.int_8

        return (REGISTER_NAME, REGISTER_TYPE)


class Instruction_OBSERVE(BIR_Instruction):
	
    def __init__(self, arch, addr, block, irsb_c):
        super().__init__(arch, addr)
        self.block = block
        self.irsb_c = irsb_c

    def compute_result(self):
        condition = self.map_expressions(self.block[1], self.irsb_c)
        obs = self.map_expressions(self.block[2], self.irsb_c)

        self.put(obs, 'obs')
        self.jump(condition, self.constant(0, Type.int_64), jumpkind=JumpKind.Syscall)


class Instruction_JMP(BIR_Instruction):
	
    def __init__(self, arch, addr, block, irsb_c):
        super().__init__(arch, addr)
        self.block = block
        self.irsb_c = irsb_c

    def compute_result(self):
        val = self.map_expressions(self.block[0], self.irsb_c)
        self.jump(None, val)


class Instruction_CJMP(BIR_Instruction):
	
    def __init__(self, arch, addr, block, irsb_c):
        super().__init__(arch, addr)
        self.block = block
        self.irsb_c = irsb_c

    def compute_result(self):
        condition = self.map_expressions(self.block[0], self.irsb_c)
        val1 = self.map_expressions(self.block[1], self.irsb_c)
        val2 = self.map_expressions(self.block[2], self.irsb_c)

        self.addr = int(str(val1.rdt), 16)
        self.jump(condition, val2)


class Instruction_HALT(BIR_Instruction):
	
    def __init__(self, arch, addr, block, irsb_c):
        super().__init__(arch, addr)
        self.block = block
        self.irsb_c = irsb_c

    def compute_result(self):
        val = self.map_expressions(self.block[0], self.irsb_c) #Const
        self.jump(None, val, jumpkind=JumpKind.Exit)



