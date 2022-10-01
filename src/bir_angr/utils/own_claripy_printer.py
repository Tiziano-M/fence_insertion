import claripy
import angr

#e = claripy.BVS("z", 32) % claripy.Extract(63, 32, claripy.BVS("y", 64) - (claripy.BVS("x", 64)))
#e = claripy.BVV(0x1, 32)
#e1 = claripy.BVS("z", 32)
#e2 = claripy.BVV(0x1, 32)
#e = ~e1
#e = claripy.Concat(e1,e1)
#e = claripy.ZeroExt(32, e1)
#e = claripy.SignExt(32, e1)
#e = claripy.LShR(e1, e2)
#e = e1 << e2
#e = e1 >> e2
#e = claripy.If(e1, e1, e2)
#e1 = claripy.BVS("x", 1)
#e1 = claripy.BVS("x", 32)
#e2 = claripy.BVS("y", 8)
#e3 = claripy.BVS("z", 8)
#e = e1 + (claripy.Extract(7, 0, e2 + e3))
#e =claripy.Extract(12, 0, claripy.Concat(claripy.BVS("x", 8), ((e2 + e3)))) + (claripy.Extract(15, 0, e2 + e3))

#e1 = claripy.BVS("z", 32)
#e2 = claripy.BVV(0x1, 32)
#e3 = claripy.BVS("y", 32)
#e4 = claripy.BVS("x", 32)
#e = e1%e2%e3%e1
#e = (e2 == e3)
#e = claripy.Concat(claripy.Concat(claripy.Concat(e1,e2),e3),e4)
#e = e1<<e2<<e3<<e4

#e1 = claripy.BoolS("z")
#e2 = claripy.BoolV(0x1)
#e3 = claripy.BoolS("y")
#e4 = claripy.BoolS("z")
#e = claripy.And(claripy.And(claripy.And(e1,e2),e3),e1)
#e = claripy.Or(e1,e3, e4)


def str_claripy_with_extreme_parenthesis(e):
  def check_claripy_type(e):
    return isinstance(e, claripy.ast.bv.BV) or isinstance(e, claripy.ast.bool.Bool)
  def str_claripy_type(e):
    return str_claripy_with_extreme_parenthesis(e)
  #
  def mapargs(args):
    return list(map(str_claripy_type, args))
  #
  def str_infix_naryop(e, opstr, n = None):
    argsraw = list(e.args)
    assert len(argsraw) >= 2
    if n != None:
      assert len(argsraw) == n
    #print(list(map(type,argsraw)))
    assert (all(map(check_claripy_type, argsraw)))
    args = mapargs(argsraw)
    return (f" {opstr} ").join(map(lambda x: f"({x})", args))
  #
  def str_infix_binop(e, opstr):
    return str_infix_naryop(e, opstr, 2)
  #
  def str_prefix_unop(e, opstr):
    argsraw = list(e.args)
    assert len(argsraw) == 1
    assert (all(map(check_claripy_type, argsraw)))
    args = mapargs(argsraw)
    return f"{opstr}({args[0]})"
  #
  def str_fun_op(e, arglen):
    argsraw = list(e.args)
    assert (len(argsraw) == arglen)
    assert (all(map(check_claripy_type, argsraw)))
    args = mapargs(argsraw)
    args_str = ", ".join(args)
    return f"{e.op}({args_str})"
  #
  try:
    # const
    if e.op == "BVV":
      return f"{hex(e.args[0])}#{e.args[1]}"
    # bool
    elif e.op == "BoolV":
      return e.args[0]
    # var
    elif e.op == "BVS":
      return e.args[0]
    # binop infix
    elif e.op == "__add__":
      return str_infix_naryop(e, "+")
    elif e.op == "__sub__":
      return str_infix_naryop(e, "-")
    elif e.op == "__mul__":
      return str_infix_naryop(e, "*")
    elif e.op == "__xor__":
      return str_infix_naryop(e, "^")
    elif e.op == "__mod__":
      return str_infix_binop(e, "%")
    elif e.op == "__and__":
      return str_infix_naryop(e, "&")
    elif e.op == "__or__":
      return str_infix_naryop(e, "|")
    elif e.op == "__floordiv__":
      return str_infix_binop(e, "/")
    elif e.op == "__eq__":
      return str_infix_binop(e, "==")
    elif e.op == "__ne__":
      return str_infix_binop(e, "!=")
    elif e.op == "__lt__":
      return str_infix_binop(e, "<")
    elif e.op == "__le__":
      return str_infix_binop(e, "<=")
    elif e.op == "__gt__":
      return str_infix_binop(e, ">")
    elif e.op == "__ge__":
      return str_infix_binop(e, ">=")
    elif e.op == "And":
      return str_infix_naryop(e, "&&")
    elif e.op == "Or":
      return str_infix_naryop(e, "||")
    elif e.op == "Concat":
      return str_infix_naryop(e, "..")
    elif e.op == "__lshift__":
      return str_infix_binop(e, "<<")
    elif e.op == "__rshift__":
      return str_infix_binop(e, ">>")
    elif e.op == "UGE":
      return str_infix_binop(e, ">=")
    elif e.op == "ULE":
      return str_infix_binop(e, "<=")
    elif e.op == "UGT":
      return str_infix_binop(e, ">")
    elif e.op == "ULT":
      return str_infix_binop(e, "<")
    elif e.op == "SGE":
      return str_infix_binop(e, ">=s")
    elif e.op == "SLE":
      return str_infix_binop(e, "<=s")
    elif e.op == "SGT":
      return str_infix_binop(e, ">s")
    elif e.op == "SLT":
      return str_infix_binop(e, "<s")
    elif e.op == "SDiv":
      return str_infix_binop(e, "/s")
    # unary prefix
    elif e.op == "Not":
      return str_prefix_unop(e, "!")
    elif e.op == "__neg__":
      return str_prefix_unop(e, "-")
    elif e.op == "__invert__":
      return str_prefix_unop(e, "~")
    # masking
    elif e.op == "Extract":
      argsraw = list(e.args)
      assert len(argsraw) == 3
      assert (type(argsraw[0]) == int)
      assert (type(argsraw[1]) == int)
      assert (check_claripy_type(argsraw[2]))
      args = mapargs([argsraw[2]])
      return f"({args[0]})[{argsraw[0]}:{argsraw[1]}]"
    # zero extension
    elif e.op == "ZeroExt":
      argsraw = list(e.args)
      assert len(argsraw) == 2
      assert (type(argsraw[0]) == int)
      assert (check_claripy_type(argsraw[1]))
      args = mapargs([argsraw[1]])
      return f"0#{argsraw[0]} .. ({args[0]})"
    # sign extension
    elif e.op == "SignExt":
      argsraw = list(e.args)
      assert len(argsraw) == 2
      assert (type(argsraw[0]) == int)
      assert (check_claripy_type(argsraw[1]))
      args = mapargs([argsraw[1]])
      return f"SignExt({argsraw[0]}, {args[0]})"
    # if-then-else expression
    elif e.op == "If":
      argsraw = list(e.args)
      assert (len(argsraw) == 3)
      #print(list(map(type,argsraw)))
      assert (all(map(check_claripy_type, argsraw)))
      args = mapargs(argsraw)
      return f"if {args[0]} then {args[1]} else {args[2]}"
    # logical right shift, if-then-else expression
    elif e.op == "LShR":
      return str_fun_op(e, 2)
    else:
      raise Exception(f'unknown operation: "{e.op}" - ({e})')
  except AssertionError:
    print(e)
    raise

def own_bv_str(e):
  # import sys
  # return e.shallow_repr(max_depth=sys.maxsize, explicit_length=True)
  expr_str = str_claripy_with_extreme_parenthesis(e)
  #print(type(e))
  #print(e.length)
  if isinstance(e, claripy.ast.bv.BV) or isinstance(e, angr.state_plugins.sim_action_object.SimActionObject):
    s = f"<BV{e.length} {expr_str}>"
  elif isinstance(e, claripy.ast.bool.Bool):
    s = f"<Bool {expr_str}>"
  else:
    raise Exception("this never happens")
  return s

#own_bv_str(e)

