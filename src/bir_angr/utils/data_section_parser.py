import os
import re
import subprocess
import claripy

from bir_angr.utils.own_claripy_printer import own_bv_str


class DataSectionParser:

    def __init__(self, binfile):
        self.binfile = binfile
        self.objdump_prefix = self.get_objdump_prefix()
        self.data_map = self.parse_data_section_lines()
        self.data_constraints = self.make_data_section_constraints()
   
    def get_objdump_prefix(self):
        gcc_var = "HOLBA_GCC_ARM8_CROSS"
        if gcc_var in os.environ:
            objdump_prefix = os.environ[gcc_var] + "objdump"
        else:
            raise Exception("no HOLBA_GCC_ARM8_CROSS environmental variable")
        return objdump_prefix

    def objdump_all_sections(self):
        out = subprocess.check_output([self.objdump_prefix, '-D', self.binfile])
        return out.decode("utf-8")

    def extract_data_section_lines(self):
        sections = self.objdump_all_sections()
        lines = sections.split("\n")
        
        active = False
        collect_lines = []
        for line in lines:
            if line.startswith("Disassembly of section"):
                if ".data" in line:
                    active = True
                else:
                    active = False
            else:
                if active:
                    collect_lines.append(line)
        return collect_lines

    def parse_data_section_lines(self):
        data_section_lines = self.extract_data_section_lines()
        data_map = {}
        data_index = 0
        for line in data_section_lines:
            if line == "":
                continue
            elif "<" and ">" in line:
                data_index += 1
                data_counter = "data" + str(data_index)
                data_map[data_counter] = {}
                entry = line.strip().split()[0]
                assert type(int(entry, 16)) == int
                data_map[data_counter]["entry"] = "0x" + entry
                find_data_name = re.search('<(.*)>', line)
                if find_data_name:
                    data_map[data_counter]["name"] = find_data_name.group(1)
                    #print(data_map[data_counter]["name"])
                    data_map[data_counter]["values"] = {}
            else:
                data = line.split("\t")
                #print(data)
                try:
                    addr = data[0].strip()
                    assert addr[-1] == ":"
                    addr= "0x" + addr[:-1]
                    assert (addr[:3] == "0x8") and (len(addr) == 2+8)
                    value = "0x" + data[1].strip()
                    #print(addr, value)
                    assert type(int(value, 16)) == int
                    data_map[data_counter]["values"][addr] = value
                except Exception as e:
                    if "..." in line.strip():
                        pass
                    else:
                        raise Exception(f"{e}\nUnknown data: {line}")
        return data_map
    
    def make_data_section_constraints(self):
        data_section_constraints = []
        for _,data in self.data_map.items():
            iter_mem = iter(data["values"])
            while True:
                try:
                    addr1 = iter_mem.__next__()
                    val1 = data["values"][addr1]
                    addr2 = next(iter_mem,None)
                    if addr2:
                        val2 = data["values"][addr2]
                        assert int(val2, 16) == 0
                        val = claripy.BVV(int(val1, 16), 64)
                    else:
                        val = claripy.BVV(int(val1, 16), 64)
                    dc = claripy.BVS(f"MEM[{own_bv_str(claripy.BVV(int(addr1, 16), 64))}]_0_64", 64, explicit_name=True) == val
                    data_section_constraints.append(dc)
                except StopIteration:
                    break
        return data_section_constraints


