import sys
import json


class ParserBIR:
	
    #def __init__(self, data):
    #    self.bir_program = data

    def get_birprog_from_json(self):
        with open(sys.argv[1], "r") as json_file:
            birprog = json.load(json_file)
        return birprog

    def parse(self):
        bir_program = self.get_birprog_from_json()
        
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
        value = label["val"]
        value = int(value)
        return value

    def get_statements(self, statements, show_statements=False):
        if not statements:
            # if the list is empty, adds a None value for no-op instruction
            statements.append({"stmttype": None})
        return statements

    def get_last_statement(self, last_statement):
        return last_statement


