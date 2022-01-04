import claripy


class SimplificationManagerBIR(claripy.simplifications.SimplificationManager):
    def __init__(self):
        super(SimplificationManagerBIR, self).__init__()
        # remove what you do not want to be simplified
        self._simplifiers = {
            'Reverse': self.bv_reverse_simplifier,
            'And': self.boolean_and_simplifier,
            'Or': self.boolean_or_simplifier,
            'Not': self.boolean_not_simplifier,
            'Extract': self.extract_simplifier,
            'Concat': self.concat_simplifier,
            'If': self.if_simplifier,
            '__lshift__': self.lshift_simplifier,
            '__rshift__': self.rshift_simplifier,
            'LShR': self.lshr_simplifier,
            '__eq__': self.eq_simplifier,
            '__ne__': self.ne_simplifier,
            '__or__': self.bitwise_or_simplifier,
            '__and__': self.bitwise_and_simplifier,
            '__xor__': self.bitwise_xor_simplifier,
            '__add__': self.bitwise_add_simplifier,
            '__sub__': self.bitwise_sub_simplifier,
            '__mul__': self.bitwise_mul_simplifier,
            'ZeroExt': self.zeroext_simplifier,
            'SignExt': self.signext_simplifier,
            'fpToIEEEBV': self.fptobv_simplifier,
            'fpToFP': self.fptofp_simplifier,
            'StrReverse': self.str_reverse_simplifier,
        }
