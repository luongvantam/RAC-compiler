# -*- coding: utf-8 -*-

# Global configurations
max_call_adr = 0x3ffff

# Data containers
commands = {}
datalabels = {}
disassembly = [""] * 0x40000
KEY_MAP = {}
rom = None

# Font and Display settings
font = []
font_assoc = {}
npress = []
symbolrepr = []

# Compiler State (Used by engine)
result = []
labels = {}
address_requests = []
relocation_expressions = []
pr_length_cmds = []
deferred_evals = []
home = None
string_vars = {}
vars_dict = {}