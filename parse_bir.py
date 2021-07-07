import re
from nltk.tree import Tree



class ParserBIR:
	
    def __init__(self, data):
        self.bir_program = data

    def parse(self):
        list_blocks = list()
        bir_program = self.bir_program.split("\n")

        for line in bir_program:
            if (line.count("BirProgram")):
                continue
            elif (line.count("<|")):
                block = list()
                block.append(line)
            elif (line.count("|>")):
                block.append(line)
                new_block = Block(block)
                list_blocks.append(new_block)
            else:
                block.append(line)
        return list_blocks



class Block:

    def __init__(self, data):
        block = self.split_data(data)
        self.label = self.get_label(block[0])
        self.statements = self.get_statements(block[1])
        self.last_statement = self.get_last_statement(block[2])

    def split_data(self, data):
        data = " ".join(d.strip() for d in data)

        label = re.search("bb_label(.*)bb_statements", data).group(1)
        statements = re.search("bb_statements(.*)bb_last_statement", data).group(1)
        last_statement = re.search("bb_last_statement(.*)>", data).group(1).replace("|", "")
        
        values = (label, statements, last_statement)
        return values    

    def get_label(self, label):
        label = label.replace(":=", "").strip()
        value = re.search('Imm(.*)w', label).group(1)
        value = re.sub(r'[^a-zA-Z0-9\[\]]',' ', value)
        value = value.split()[1]
        value = value.split("w", 1)[0]
        return int(value)

    def get_statements(self, statements, show_statements=False):
        processed_statements = statements.replace(":=", "").strip()
        processed_statements = processed_statements[:-2]

        if (processed_statements.count("bir_val_t") or processed_statements.count("bir_stmt_basic_t")):
            processed_statements = processed_statements.replace(": bir_val_t", "")
            processed_statements = processed_statements.replace(":bir_val_t", "")
            processed_statements = processed_statements.replace("bir_stmt_basic_t", "")
            processed_statements = processed_statements.replace("list", "")
        processed_statements = processed_statements.replace("[", "", 1)
        processed_statements = processed_statements.split(";")
        processed_statements = list(filter(None, processed_statements))
        
        for i in range(len(processed_statements)):
            if processed_statements[i].count("(BStmt"):
                continue
            elif processed_statements[i].count("BStmt"):
                processed_statements[i] = processed_statements[i].replace("BStmt", "(BStmt")
                processed_statements[i] = processed_statements[i]+")"
                if processed_statements[i].count("BStmt_Observe"):
                    processed_statements[i] = processed_statements[i].replace("[", "(")
                    processed_statements[i] = processed_statements[i].replace("]", ")")

        if not len(processed_statements):
            processed_statements.append("()")
        #print(processed_statements)

        trees_statements = [Tree.fromstring(statement) for statement in processed_statements]		
        if show_statements:
            for tree in trees_statements:
                print(tree)
                tree.pretty_print()
        return trees_statements

    def get_last_statement(self, last_statement):
        processed_last_statement = last_statement.replace(":=", "").strip()

        if processed_last_statement.count("BStmt"):
            processed_last_statement = processed_last_statement.replace("BStmt", "(BStmt")
            processed_last_statement = processed_last_statement+")"
        if processed_last_statement.count("(Imm"):
        	processed_last_statement = processed_last_statement+" "
        #print(processed_last_statement)

        tree_last_statement = Tree.fromstring(processed_last_statement)
        return tree_last_statement



############################################
#################   TEST   #################
############################################
'''input = open("examples/bir_program.bir", "rb")
bir_input = input.read() # angr uses the byte form
bir_input = bir_input.decode("utf-8") 
print(bir_input)
bir_program = ParserBIR(bir_input)
blokcs = bir_program.parse()
print(blokcs)
print(blokcs[0].label)
print(blokcs[0].statements)
print(blokcs[0].last_statement)'''



