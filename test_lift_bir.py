

def test1():
    import archinfo
    from arch_bir import ArchBIR
    from parse_bir import ParserBIR
    from lift_bir import LifterBIR

    bir_input = open("examples/bir_program.bir", "rb")
    bir_input = bir_input.read()
    lifter = LifterBIR(arch=archinfo.arch_from_id('bir'), addr=2)
    #bir_program = ParserBIR(bir_input)
    #blocks = bir_program.parse()
    #irsb_list = list()
    #for block in blocks:
    lifter._lift(data=bir_input)
    #lifter.irsb.pp()
    #irsb_list.append(lifter.irsb)


def test2():
    import angr
    import __init__
    proj = angr.Project("examples/test.bir", main_opts={'backend': 'bir'})
    irsb = proj.factory.block(proj.entry)
    irsb.vex.pp()
    #irsb = proj.factory.block(proj.entry, size = 400).vex



def main():
    test1()
    #test2()


if __name__ == '__main__':
    main()
