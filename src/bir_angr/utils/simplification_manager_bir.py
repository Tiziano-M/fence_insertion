import claripy


class SimplificationManagerBIR(claripy.simplifications.SimplificationManager):
    def __init__(self):
        super(SimplificationManagerBIR, self).__init__()
        # look at self._simplifiers what you want to change



    @staticmethod
    def zeroext_simplifier(n, e):
        if n == 0:
            return e
        elif n == 24:
            assert e.size() == 8
            return e.make_like('ZeroExt', (16, claripy.ZeroExt(8, e)), length=n + e.size(), simplify=False)
        elif n == 48:
            assert e.size() == 16
            return e.make_like('ZeroExt', (32, claripy.ZeroExt(16, e)), length=n + e.size(), simplify=False)
        elif n == 56:
            assert e.size() == 8
            new_e = e.make_like('ZeroExt', (16, claripy.ZeroExt(8, e)), length=24 + e.size(), simplify=False)
            return e.make_like('ZeroExt', (32, new_e), length=n + e.size(), simplify=False)
        elif n == 63:
            assert e.size() == 1
            # Note: dirty hack to handle 1-bit flags
            return e.make_like('Extract', (0, 0, e), length=63+e.size(), simplify=False)
            

        if e.op == 'ZeroExt':
            # ZeroExt(A, ZeroExt(B, x)) ==> ZeroExt(A + B, x)
            return e.make_like(e.op, (n + e.args[0], e.args[1]), length=n + e.size(), simplify=True)
