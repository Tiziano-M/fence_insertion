from pyvex.lifting.util import Type, JumpKind
from pyvex.lifting.util.syntax_wrapper import VexValue
from .BIR_Instruction import BIR_Instruction
from .lift_bir import LifterBIR
import logging


l = logging.getLogger(__name__)



class Instruction_ASSIGN(BIR_Instruction):
	
    def __init__(self, arch, addr, block, irsb_c):
        super().__init__(arch, addr)
        self.block = block
        self.irsb_c = irsb_c

    def get_argument1(self):
        REGISTER_NAME = self.block["var"]["name"]
        return REGISTER_NAME

    def get_argument2(self):
        val = self.map_expressions(self.block["exp"], self.irsb_c)
        return val

    def compute_result(self):
        val = self.get_argument2()
        if not val:
            return
        if val.ty == Type.int_1:
            val = val.cast_to(Type.int_8)
        reg = self.get_argument1()
        self.put(val, reg)


class Instruction_ASSERT(BIR_Instruction):
	
    def __init__(self, arch, addr, block, irsb_c):
        super().__init__(arch, addr)
        self.block = block
        self.irsb_c = irsb_c

    def get_argument(self):
        val = self.map_expressions(self.block["exp"], self.irsb_c)
        return val

    def compute_result(self):
        condition = self.get_argument()
        to_addr = self.constant(LifterBIR.extern_addr, Type.int_64)
        negated_condition = self.ite(condition, self.constant(0, condition.ty), self.constant(1, condition.ty))

        self.irsb_c.add_exit(negated_condition, to_addr.rdt, JumpKind.Boring, self.arch.ip_offset)


class Instruction_BINEXP(BIR_Instruction):
	
    def __init__(self, arch, addr, block, irsb_c):
        super().__init__(arch, addr)
        self.block = block
        self.irsb_c = irsb_c

    def get_operator(self):
        operator = self.block["type"]
        return operator

    def get_operand1(self):
        val = self.map_expressions(self.block["exp1"], self.irsb_c)
        return val

    def get_operand2(self):
        val = self.map_expressions(self.block["exp2"], self.irsb_c)
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
            val = operand1 << operand2.cast_to(Type.int_8)
        elif operator == "BIExp_RightShift":
            val = operand1 >> operand2.cast_to(Type.int_8)
        elif operator == "BIExp_SignedRightShift":
            val = operand1 >> operand2.cast_to(Type.int_8)
            val.is_signed = True
        return val


class Instruction_IFTHENELSE(BIR_Instruction):

    def __init__(self, arch, addr, block, irsb_c):
        super().__init__(arch, addr)
        self.block = block
        self.irsb_c = irsb_c

    def compute_result(self):
        exp_cond = self.map_expressions(self.block["cond"], self.irsb_c)
        exp_then = self.map_expressions(self.block["then"], self.irsb_c)
        exp_else = self.map_expressions(self.block["else"], self.irsb_c)

        val = self.ite(exp_cond, exp_then, exp_else)
        val = VexValue(self.irsb_c, val)
        return val
 

class Instruction_LOAD(BIR_Instruction):
	
    def __init__(self, arch, addr, block, irsb_c):
        super().__init__(arch, addr)
        self.block = block
        self.irsb_c = irsb_c

    def get_register_type(self):
        REGISTER_TYPE_LOAD = self.block["sz"]
        if (REGISTER_TYPE_LOAD == "Bit64"):
    	    REGISTER_TYPE_LOAD = Type.int_64
        elif (REGISTER_TYPE_LOAD == "Bit32"):
    	    REGISTER_TYPE_LOAD = Type.int_32
        elif (REGISTER_TYPE_LOAD == "Bit16"):
    	    REGISTER_TYPE_LOAD = Type.int_16
        elif (REGISTER_TYPE_LOAD == "Bit8"):
    	    REGISTER_TYPE_LOAD = Type.int_8
        elif (REGISTER_TYPE_LOAD == "Bit1"):
    	    REGISTER_TYPE_LOAD = Type.int_1
        return REGISTER_TYPE_LOAD

    def compute_result(self):
        REGISTER_TYPE_LOAD = self.get_register_type()
        addr_val = self.map_expressions(self.block["addr"], self.irsb_c)

        val = self.load(addr_val, REGISTER_TYPE_LOAD)
        return val


class Instruction_STORE(BIR_Instruction):
	
    def __init__(self, arch, addr, block, irsb_c):
        super().__init__(arch, addr)
        self.block = block
        self.irsb_c = irsb_c

    def compute_result(self):
        addr_val = self.map_expressions(self.block["addr"], self.irsb_c)

        val = self.map_expressions(self.block["val"], self.irsb_c)
        if val.ty == Type.int_1:
            raise Exception("BIR Store expression is attempting to store 1 bit.")

        self.store(val, addr_val)


class Instruction_CAST(BIR_Instruction):
	
    def __init__(self, arch, addr, block, irsb_c):
        super().__init__(arch, addr)
        self.block = block
        self.irsb_c = irsb_c

    def get_type(self):
        ty_cast = self.block["sz"]
        if (ty_cast == 64):
    	    ty_cast = Type.int_64
        elif (ty_cast == 32):
    	    ty_cast = Type.int_32
        elif (ty_cast == 16):
    	    ty_cast = Type.int_16
        elif (ty_cast == 8):
    	    ty_cast = Type.int_8
        elif (ty_cast == 1):
    	    ty_cast = Type.int_1
        return ty_cast

    def compute_result(self):
        val = self.map_expressions(self.block["exp"], self.irsb_c)
        ty = self.get_type()
        
        if self.block["type"] == "BIExp_UnsignedCast":
            val = val.cast_to(ty, signed=False)
        elif self.block["type"] == "BIExp_SignedCast":
            val = val.cast_to(ty, signed=True)
        elif self.block["type"] == "BIExp_HighCast":
            val = val.cast_to(ty, high=True)
        elif self.block["type"] == "BIExp_LowCast":
            val = val.cast_to(ty, high=False)
        return val


class Instruction_UNARY(BIR_Instruction):
	
    def __init__(self, arch, addr, block, irsb_c):
        super().__init__(arch, addr)
        self.block = block
        self.irsb_c = irsb_c

    def compute_result(self):
        val = self.map_expressions(self.block["exp"], self.irsb_c)

        if self.block["type"] == "BIExp_ChangeSign":
            raise Exception("BIExp_ChangeSign found!")
        elif self.block["type"] == "BIExp_Not":
            val = ~val
        elif self.block["type"] == "BIExp_CLZ":
            raise Exception("BIExp_CLZ found!")
        elif self.block["type"] == "BIExp_CLS":
            raise Exception("BIExp_CLS found!")
        return val


class Instruction_BINPRED(BIR_Instruction):
	
    def __init__(self, arch, addr, block, irsb_c):
        super().__init__(arch, addr)
        self.block = block
        self.irsb_c = irsb_c

    def compute_result(self):
        val1 = self.map_expressions(self.block["exp1"], self.irsb_c)
        val2 = self.map_expressions(self.block["exp2"], self.irsb_c)

        if self.block["type"] == "BIExp_Equal":
            val = val1 == val2
        elif self.block["type"] == "BIExp_NotEqual":
            val = val1 != val2
        elif self.block["type"] == "BIExp_LessThan":
            val = val1 < val2
        elif self.block["type"] == "BIExp_SignedLessThan":
            val = val1 < val2
            val.is_signed = True
        elif self.block["type"] == "BIExp_LessOrEqual":
            val = val1 <= val2
        elif self.block["type"] == "BIExp_SignedLessOrEqual":
            val = val1 <= val2
            val.is_signed = True
        return val.cast_to(Type.int_1)


class Instruction_DEN(BIR_Instruction):
	
    def __init__(self, arch, addr, block, irsb_c):
        super().__init__(arch, addr)
        self.block = block
        self.irsb_c = irsb_c

    def get_register(self, block):
        REGISTER_NAME = block["name"]
        REGISTER_TYPE = block["type"]     
        if (REGISTER_TYPE == "imm64"):
            REGISTER_TYPE = Type.int_64
        elif (REGISTER_TYPE == "imm32"):
            REGISTER_TYPE = Type.int_32
        elif (REGISTER_TYPE == "imm16"):
            REGISTER_TYPE = Type.int_16
        elif (REGISTER_TYPE == "imm8"):
            REGISTER_TYPE = Type.int_8
        elif (REGISTER_TYPE == "imm1"):
            REGISTER_TYPE = Type.int_8
            val = self.get(REGISTER_NAME, REGISTER_TYPE)
            val = val.cast_to(Type.int_1)
            return val
        val = self.get(REGISTER_NAME, REGISTER_TYPE)
        return val

    def compute_result(self):
        val = self.get_register(self.block["var"])
        return val


class Instruction_CONST(BIR_Instruction):
	
    def __init__(self, arch, addr, block, irsb_c):
        super().__init__(arch, addr)
        self.block = block
        self.irsb_c = irsb_c

    def get_value(self):
        Imm = self.block["val"]
        return Imm

    def get_type(self):
        ty = self.block["sz"]
        if (ty == 64):
            ty = Type.int_64
        elif (ty == 32):
    	    ty = Type.int_32
        elif (ty == 16):
    	    ty = Type.int_16
        elif (ty == 8):
    	    ty = Type.int_8
        elif (ty == 1):
    	    ty = Type.int_1
        return ty

    def compute_result(self):
        Imm = self.get_value()
        ty = self.get_type()
        val = self.constant(Imm, ty)
        return val


class Instruction_BLE_LABEL(BIR_Instruction):
	
    def __init__(self, arch, addr, block, irsb_c):
        super().__init__(arch, addr)
        self.block = block
        self.irsb_c = irsb_c

    def compute_result(self):
        val = self.map_label(self.block["exp"], self.irsb_c)
        return val


class Instruction_BLE_EXP(BIR_Instruction):
	
    def __init__(self, arch, addr, block, irsb_c):
        super().__init__(arch, addr)
        self.block = block
        self.irsb_c = irsb_c

    def compute_result(self):
        val = self.map_expressions(self.block["exp"], self.irsb_c)
        return val


class Instruction_BL_LABEL(BIR_Instruction):
	
    def __init__(self, arch, addr, block, irsb_c):
        super().__init__(arch, addr)
        self.block = block
        self.irsb_c = irsb_c

    def compute_result(self):
        val = self.block["str"]
        return val


class Instruction_BL_ADDRESS(BIR_Instruction):
	
    def __init__(self, arch, addr, block, irsb_c):
        super().__init__(arch, addr)
        self.block = block
        self.irsb_c = irsb_c

    def get_addr(self):
        addr = self.block["val"]
        return addr

    def get_type(self):
        ty = self.block["sz"]
        if (ty == 64):
            ty = Type.int_64
        elif (ty == 32):
    	    ty = Type.int_32
        elif (ty == 16):
    	    ty = Type.int_16
        elif (ty == 8):
    	    ty = Type.int_8
        elif (ty == 1):
    	    ty = Type.int_1
        return ty

    def compute_result(self):
        addr = self.get_addr()
        ty = self.get_type()
        val = self.constant(addr, ty)
        return val


class Instruction_OBSERVE(BIR_Instruction):
	
    def __init__(self, arch, addr, block, irsb_c):
        super().__init__(arch, addr)
        self.block = block
        self.irsb_c = irsb_c

    def get_idx(self):
        if "id" in self.block:
            idx = int(self.block["id"])
        elif "obsref" in self.block:
            idx = self.block["obsref"]
        else:
            raise Exception("Error in getting the index of the Observe statement!")
        return idx

    def compute_result(self):
        # to match the system call with 1 of 'accumulate'
        self.put(self.constant(1, Type.int_64), 'syscall_num')
        for obs in self.block["obss"]:
            obs = self.map_expressions(obs, self.irsb_c)
            self.put(obs, 'obs')
            self.jump(self.constant(1, Type.int_1), self.constant(LifterBIR.extern_addr+1, Type.int_64), jumpkind=JumpKind.Syscall)

        # to match the system call with 0 of 'observation'
        self.put(self.constant(0, Type.int_64), 'syscall_num')
        idx = self.get_idx()
        condition = self.map_expressions(self.block["cnd"], self.irsb_c)
        if condition.ty == Type.int_1:
            condition = condition.cast_to(Type.int_8)
        else:
            raise Exception("condition in Observe statement is not well-typed")
        self.put(condition, 'cond_obs')
        self.put(self.constant(idx, Type.int_64), 'idx_obs')
        self.jump(self.constant(1, Type.int_1), self.constant(LifterBIR.extern_addr+1, Type.int_64), jumpkind=JumpKind.Syscall)


class Instruction_JMP(BIR_Instruction):
	
    def __init__(self, arch, addr, block, irsb_c):
        super().__init__(arch, addr)
        self.block = block
        self.irsb_c = irsb_c

    def compute_result(self):
        val = self.map_label_expressions(self.block["lbl"], self.irsb_c)
        self.jump(None, val)


class Instruction_CJMP(BIR_Instruction):
	
    def __init__(self, arch, addr, block, irsb_c):
        super().__init__(arch, addr)
        self.block = block
        self.irsb_c = irsb_c

    def compute_result(self):
        condition = self.map_expressions(self.block["cnd"], self.irsb_c)
        val1 = self.map_label_expressions(self.block["lblt"], self.irsb_c)
        val2 = self.map_label_expressions(self.block["lblf"], self.irsb_c)

        self.addr = int(str(val2.rdt), 16)
        self.jump(condition, val1)


class Instruction_HALT(BIR_Instruction):
	
    def __init__(self, arch, addr, block, irsb_c):
        super().__init__(arch, addr)
        self.block = block
        self.irsb_c = irsb_c

    def compute_result(self):
        val = self.map_expressions(self.block["exp"], self.irsb_c)
        self.jump(None, val, jumpkind=JumpKind.Exit)



