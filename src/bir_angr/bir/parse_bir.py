import json


class ParserBIR:
    """
    Returns the list of BIR blocks taken as input self.data (the BIR program) in the lifter

    :param data:       The bytes to lift as either a python string of bytes.
    :returns:          The list of BIR blocks.
    :rtype:            list
    """

    def parse(birprogjson):
        data = open(birprogjson, "rb")
        data = data.read()
        bir_program = json.loads(data)
        
        list_blocks = list()        
        for block in bir_program:
            new_block = Block(block)
            list_blocks.append(new_block)    
        return list_blocks



class Block:

    def __init__(self, block):
        self.label = self.get_label(block["lbl"])
        self.statements = self.get_statements(block["stmts"])
        self.last_statement = self.get_last_statement(block["estmt"])
   
    def get_label(self, label):
        if "val" in label:
            lbl_addr = label["val"]
            assert isinstance(lbl_addr, int)
        elif "str" in label:
            lbl_addr = label["str"]
            assert isinstance(lbl_addr, str)
        else:
            raise KeyError("BIR Label address is not as expected")
        return lbl_addr

    def get_statements(self, statements, show_statements=False):
        if not statements:
            # if the list is empty, adds a None value for no-op instruction
            statements.append({"stmttype": None})
        return statements

    def get_last_statement(self, last_statement):
        return last_statement


