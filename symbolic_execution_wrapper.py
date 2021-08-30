#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), "./src"))

import bir_angr.symbolic_execution

bir_angr.symbolic_execution.main()

#import subprocess

#python_script = os.path.join(os.path.dirname(__file__), "./src/bir_angr/symbolic_execution.py")
#cmd = ["python3", python_script] + (sys.argv[1:])

#subprocess.call(cmd)

