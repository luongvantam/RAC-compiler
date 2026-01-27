# -*- coding: utf-8 -*-
import os, re
from . import context
from .utils import canonicalize, del_inline_comment, to_lowercase

def add_command(command_dict, address, command, tags, debug_info=''):
    ''' Add a command to command_dict. '''
    assert command, f'Empty command {debug_info}'
    assert type(command_dict) is dict

    for disallowed_prefix in '0x', 'call', 'goto':
        assert not command.startswith(disallowed_prefix), \
            f'Command ends with "{disallowed_prefix}" {debug_info}'
    assert not command.endswith(':'), \
        f'Command ends with ":" {debug_info}'
    assert ';' not in command, \
        f'Command contains ";" {debug_info}'

    for prev_command, (prev_adr, prev_tags) in command_dict.items():
        if prev_command == command or prev_adr == address:
            # Note: Logic slightly adjusted to prevent crash on re-imports if needed, but keeping strict as per original
            assert False, f'Command appears twice - ' \
                f'first: {prev_command} -> {prev_adr:05X} {prev_tags}, ' \
                f'second: {command} -> {address:05X} {tags} - ' \
                f'{debug_info}'

    command_dict[command] = (address, tuple(tags))

def get_commands(filename):
    ''' Read a list of gadget names. '''
    with open(filename, 'r', encoding='utf-8') as f:
        data = f.read().splitlines()

    in_comment = False
    line_regex = re.compile(r'([0-9a-fA-F]+)\s+(.+)')
    for line_index0, line in enumerate(data):
        line = line.strip()

        if line == '/*':
            in_comment = True
            continue
        if line == '*/':
            in_comment = False
            continue
        if in_comment:
            continue

        line = del_inline_comment(line)
        if not line:
            continue

        match = line_regex.fullmatch(line)
        if not match: continue
        
        address, command = match[1], match[2]
        command = canonicalize(command)
        command = to_lowercase(command)

        tags = []
        while command and command[0] == '{':
            i = command.find('}')
            if i < 0:
                raise Exception(f'Line {line_index0 + 1} has unmatched "{{"')
            tags.append(command[1:i])
            command = command[i + 1:]

        try:
            address = int(address, 16)
        except ValueError:
            raise Exception(f'Line {line_index0 + 1} has invalid address: {address!r}')

        add_command(context.commands, address, command, tags, f'at {filename}:{line_index0 + 1}')
        
def get_key_map(filename):
    context.KEY_MAP = {}
    if not os.path.exists(filename):
        return
    with open(filename, 'r', encoding='utf-8') as f:
        data = f.read().splitlines()
    line_regex = re.compile(r'(?:([0-9A-Fa-f]{4})\s+(\w+)|(\w+)\s+([0-9A-Fa-f]{4}))')
    for line in data:
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('//'):
            continue
        line = del_inline_comment(line)
        if not line:
            continue
        m = line_regex.fullmatch(line)
        if not m:
            continue
        if m[1]:
            hex_raw, key_name = m[1], m[2]
        else:
            key_name, hex_raw = m[3], m[4]
        context.KEY_MAP[key_name] = f"0x{hex_raw[:2]}, 0x{hex_raw[2:]}"

def get_disassembly(filename):
    context.disassembly = [""] * 0x40000 

    with open(filename, 'r', encoding='utf-8') as f:
        for line in f:
            parts = line.split('\t')
            if len(parts) < 3: continue
            
            addr_info = parts[0].split(':')
            if len(addr_info) < 2: continue
            
            try:
                bank = int(addr_info[0], 16)
                offset = int(addr_info[1].rstrip('H'), 16)
                
                address = (bank * 0x4000) + (offset % 0x4000)
                if address < 0x40000:
                    context.disassembly[address] = parts[2].strip().lower()
            except ValueError:
                continue

def read_rename_list(filename):
    STOP_KEYWORDS = ('push lr', 'pop pc', 'rt')
    with open(filename, 'r', encoding='utf-8') as f:
        data = f.read().splitlines()

    line_regex = re.compile(r'^\s*([\w_.]+)\s+([\w_.]+)')
    global_regex = re.compile(r'f_([0-9a-fA-F]+)')
    local_regex = re.compile(r'\.l_([0-9a-fA-F]+)')
    data_regex = re.compile(r'd_([0-9a-fA-F]+)')
    hexadecimal = re.compile(r'[0-9a-fA-F]+')

    last_global_label = None
    for line_index0, line in enumerate(data):
        match = line_regex.match(line)
        if not match: continue
            
        raw, real = match.group(1), match.group(2)
        if real.startswith('.'): continue

        match_data = data_regex.fullmatch(raw)
        if match_data:
            addr = int(match_data.group(1), 16)
            context.datalabels[real] = addr
            continue

        addr = None
        if hexadecimal.fullmatch(raw):
            addr = int(raw, 16)
            last_global_label = None
        else:
            match_glob = global_regex.match(raw)
            if match_glob:
                addr = int(match_glob.group(1), 16)
                if len(match_glob.group(0)) == len(raw):
                    last_global_label = addr
                else:
                    suffix = raw[len(match_glob.group(0)):]
                    match_loc = local_regex.fullmatch(suffix)
                    if match_loc:
                        addr += int(match_loc.group(1), 16)
            else:
                match_loc = local_regex.fullmatch(raw)
                if match_loc:
                    if last_global_label is None:
                        print(f'Label cannot be read at line {line_index0+1}: {line}')
                        continue
                    else:
                        addr = last_global_label + int(match_loc.group(1), 16)

        if addr is not None:
            if addr >= len(context.disassembly): continue

            current_instr = context.disassembly[addr]
            
            if current_instr.startswith('push lr'):
                tags = ('del lr',)
                addr_ptr = addr + 2
            else:
                tags = ('rt',)
                addr_ptr = addr + 2
                while addr_ptr < len(context.disassembly):
                    target = context.disassembly[addr_ptr]
                    if not target: 
                        addr_ptr += 2
                        continue
                    
                    if any(target.startswith(x) for x in STOP_KEYWORDS):
                        break
                    addr_ptr += 2
                
                if addr_ptr < len(context.disassembly) and not context.disassembly[addr_ptr].startswith('rt'):
                    tags = tags + ('del lr',)

            if real in context.commands:
                if 'override rename list' in context.commands[real][1]:
                    continue
                if context.commands[real] == (addr, tags):
                    continue

            add_command(context.commands, addr, real, tags=tags,
                         debug_info=f'at {filename}:{line_index0 + 1}')

def sizeof_register(reg_name):
    return {'r': 1, 'e': 2, 'x': 4, 'q': 8}[reg_name[0]]