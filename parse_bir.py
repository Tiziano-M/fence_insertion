import re
from nltk.tree import Tree



class ParserBIR:
	
    def __init__(self, data):
        self.bir_program = data

    def parse(self):
        list_blocks = list()
        #bir_program = "".join(char for char in self.bir_program)
        #start = bir_program.find("<|")
        #end = bir_program.find("|>")
        #print(bir_program[start:end])
        #new_block = Block(bir_program[start:end])
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
        self.label = self.get_label(block["bb_label"])
        self.statements = self.get_statements(block["bb_statements"])
        self.last_statement = self.get_last_statement(block["bb_last_statement"])


    def split_data(self, data):
        block_dict = {"bb_label" : [], "bb_statements" : [], "bb_last_statement" : []}
        for line in data:
            if line.count("bb_label"):
                key = "bb_label"
                block_dict[key].append(line)
            elif line.count("bb_statements"):
                key = "bb_statements"
                block_dict[key].append(line)
            elif line.count("bb_last_statement"):
                key = "bb_last_statement"
                block_dict[key].append(line)
            else:
                if(key):
                    block_dict[key].append(line)
        return block_dict

    def get_block_size(self, data):
        label_size = 0
        statements_size = 0
        last_statement_size = 0
        for line in data:
            if line.count("bb_label"):
                label_size = 1
            elif line.count("bb_statements"):
                final_label_size = label_size
                statements_size = 1
            elif line.count("bb_last_statement"):
                final_statements_size = statements_size
                last_statement_size = 1
            else:
                label_size += 1
                statements_size += 1
                last_statement_size += 1
        final_last_statement_size = last_statement_size
        return final_label_size, final_statements_size, final_last_statement_size        

    def get_label(self, label):
        label = " ".join(label)
        assert label.count("bb_label")
        assert label.count("BL_Address")
        value = re.search('Imm(.*)w', label).group(1)
        value = value.split()[1]
        value = value.split("w", 1)[0]
        return int(value)

    def get_last_statement(self, last_statement):
        last_statement = " ".join(last_statement)
        assert last_statement.count("bb_last_statement")
        exps = last_statement.split()

        processed_exps = list()
        for exp in exps:
            if exp.startswith("BStmt"):
                exp = "("+exp
            elif exp.count("|>"):
                idx_remove = exp.index("|>")
                exp = exp[:idx_remove]
                exp = exp+")"
            elif exp.startswith("(Imm"):
            	exp = exp+" "
            processed_exps.append(exp)
        processed_exps = processed_exps[2:]
        
        last_statement = " ".join(exp for exp in processed_exps)
        tree_last_statement = Tree.fromstring(last_statement)
        return tree_last_statement

    def get_statements(self, statements, show_statements=False):
        #print(statements)
       

        statements = " ".join(statement.strip() for statement in statements)

        processed_statements = list()
        for word in statements.split():
            if word.startswith("BStmt"):
                word = "("+word
            elif word == ("[];"):
                word = word.replace("[];", "();")
            elif word.startswith("["):
                word = word.replace("[", "(")
            elif word.endswith("];"):
                word = word.replace("];", ");")
            elif word.endswith(";"):
                word = word.replace(";", ");")
            processed_statements.append(word)
        #print(processed_statements)

        '''processed_statements = list()
        for statement in statements:
            statement = statement.strip()
            if statement.startswith("BStmt"):
                statement = "("+statement
            elif statement.endswith(";"):
                statement = statement.replace(";", ");")
            processed_statements.append(statement)'''
        
        '''assert statements[0].count("bb_statements")
        statements = statements[1:]
        assert statements[0].count("[")
        statements[0] = statements[0].replace("[", "(")
        assert statements[-1].count("]")
        statements[-1] = statements[-1].replace("]", "")'''

        if processed_statements[0] == "bb_statements" and processed_statements[1] == ":=":
            processed_statements = processed_statements[2:]
        statements = " ".join(statement for statement in processed_statements)
        statements = statements.split(";")
        statements = list(filter(None, statements))
        #print(statements)

        trees_statements = [Tree.fromstring(statement) for statement in statements]		
        if show_statements:
            for tree in trees_statements:
                print(tree)
                tree.pretty_print()
        
        return trees_statements



############################################
#################   TEST   #################
############################################
'''input = open("examples/bir_progam.bir", "rb")
bir_input = input.read() # angr uses the byte form
bir_input = bir_input.decode("utf-8") 
print(bir_input)
bir_program = ParserBIR(bir_input)
blokcs = bir_program.parse()
print(blokcs)
print(blokcs[0].label)
print(blokcs[0].statements)
print(blokcs[0].last_statement)'''



