# -*- coding: utf-8 -*-
# Created by luongvantam last created: 02:45 PM 11-01-2025(GMT+7)
import re, sys, os
from functools import lru_cache

max_call_adr = 0x3ffff

def set_font(font_):
    global font, font_assoc
    font = font_
    font_assoc = dict((c, i) for i, c in enumerate(font))

def from_font(st):
    return [font_assoc[char] for char in st]

def to_font(charcodes):
    return ''.join(font[charcode] for charcode in charcodes)

def set_npress_array(npress_):
    global npress
    npress = npress_

def set_symbolrepr(symbolrepr_):
    global symbolrepr
    symbolrepr = symbolrepr_

@lru_cache(maxsize=256)
def byte_to_key(byte):
    if byte == 0:
        return '<NUL>'

    # TODO hack for classwiz without unstable
    sym = symbolrepr[byte]
    return f'<{byte:02x}>' if sym in ('@', '') else sym

    offset = 0
    sym = symbolrepr[byte]
    while byte and npress[byte] >= 100:
        byte = byte - 1
        offset += 1
    typesym = symbolrepr[byte] if byte else 'NUL'

    if set(sym) & set('\'"<>:'):
        sym = repr(sym)
    if set(typesym) & set('\'"<>:+'):
        typesym = repr(typesym)

    if offset == 0:
        return sym
    else:
        return f'<{sym}:{typesym}+{offset}>'

def get_npress(charcodes):
    if isinstance(charcodes, int):
        charcodes = (charcodes,)
    return sum(npress[charcode] for charcode in charcodes)

def get_npress_adr(adrs):
    if isinstance(adrs, int):
        adrs = (adrs,)
    assert all(0 <= adr <= max_call_adr for adr in adrs)
    return sum(get_npress((adr & 0xFF, (adr >> 8) & 0xFF)) for adr in adrs)

def optimize_adr_for_npress(adr):
    '''
    For a 'POP PC' command, the lowest significant bit in the address
    does not matter. This function use that fact to minimize number
    of key strokes used to enter the hackstring.
    '''
    return min((adr, adr ^ 1), key=get_npress_adr)

def optimize_sum_for_npress(total):
    ''' Return (a, b) such that a + b == total. '''
    return ['0x' + hex(x)[2:].zfill(4) for x in min(
        ((x, (total - x) % 0x10000) for x in range(0x0101, 0x10000)),
        key=get_npress_adr
    )]

def note(st):
    ''' Print st to stderr. Used for additional information (note, warning) '''
    sys.stderr.write(st)

def to_lowercase(s):
    return s.lower()

def canonicalize(st):
    ''' Make (st) canonical. '''
    #st = st.lower()
    st = st.strip()
    # remove spaces around non alphanumeric
    st = re.sub(r' *([^a-z0-9]) *', r'\1', st)
    return st

def del_inline_comment(line):
    return (line + '#')[:line.find('#')].rstrip()

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

    # this is inefficient
    for prev_command, (prev_adr, prev_tags) in command_dict.items():
        if prev_command == command or prev_adr == address:
            assert False, f'Command appears twice - ' \
                f'first: {prev_command} -> {prev_adr:05X} {prev_tags}, ' \
                f'second: {command} -> {address:05X} {tags} - ' \
                f'{debug_info}'

    command_dict[command] = (address, tuple(tags))

# A dict of {name: (address, tags)} to append result to.
commands = {}
datalabels = {}

def get_commands(filename):
    ''' Read a list of gadget names.

    Args:
        A dict
    '''
    global commands
    with open(filename, 'r', encoding='utf-8') as f:
        data = f.read().splitlines()

    in_comment = False
    line_regex = re.compile(r'([0-9a-fA-F]+)\s+(.+)')
    for line_index0, line in enumerate(data):
        line = line.strip()

        # multi-line comments
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
        address, command = match[1], match[2]

        command = canonicalize(command)
        command = to_lowercase(command)

        tags = []
        while command and command[0] == '{':
            i = command.find('}')
            if i < 0:
                raise Exception(f'Line {line_index0 + 1} '
                                'has unmatched "{"')
            tags.append(command[1:i])
            command = command[i + 1:]

        try:
            address = int(address, 16)
        except ValueError:
            raise Exception(f'Line {line_index0 + 1} has invalid address: {address!r}')

        add_command(commands, address, command, tags, f'at {filename}:{line_index0 + 1}')

def get_disassembly(filename):
    '''Try to parse a disassembly file with annotated address.
    Each line should look like this:
        mov r2, 1                      ; 0A0A2 | 0201
    '''
    global disasm
    with open(filename, 'r', encoding='utf-8') as f:
        data = f.read().splitlines()

    line_regex = re.compile(r'\t(.*?)\s*; ([0-9a-fA-F]*) \|')
    disasm = []
    for line in data:
        match = line_regex.match(line)
        if match:
            addr = int(match[2], 16)
            while addr >= len(disasm):
                disasm.append('')
            disasm[addr] = match[1]
            
def load_extensions(path):
    if not os.path.exists(path):
        print(f"[WARN] No extension file found: {path}")
        return []

    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    pattern = r"---syntax---\s*(.*?)\s*---output---\s*(.*?)\s*(?=---syntax---|$)"
    matches = re.findall(pattern, content, re.DOTALL)

    extensions = []
    for syntax_block, output_block in matches:
        syntax_line = syntax_block.strip()
        output_lines = [ln.strip() for ln in output_block.strip().splitlines() if ln.strip()]
        extensions.append({
            "syntax": syntax_line,
            "output": output_lines
        })
    return extensions


def match_extension(line, extensions):
    for ext in extensions:
        syntax = ext["syntax"]
        pattern = re.escape(syntax)
        pattern = re.sub(r'\\\{(\w+)\\\}', r'(?P<\1>.+?)', pattern)
        
        m = re.fullmatch(pattern, line.strip())
        if m:
            return ext, m.groupdict()
    return None, None


def expand_extensions_in_program(program_lines, extensions):
    expanded = []
    for line in program_lines:
        ext, groups = match_extension(line, extensions)
        if ext:
            for out_line in ext["output"]:
                for k, v in groups.items():
                    out_line = out_line.replace(f"{{{k}}}", v)
                expanded.append(out_line)
        else:
            expanded.append(line)

    expanded = [ln for ln in expanded if ln.strip() and ln.strip() != "---"]
    return expanded

def read_rename_list(filename):
    '''Try to parse a rename list.
    If the rename list is ambiguous without disassembly, it raises an error.
    '''
    global commands, datalabels
    with open(filename, 'r', encoding='utf-8') as f:
        data = f.read().splitlines()

    line_regex = re.compile(r'^\s*([\w_.]+)\s+([\w_.]+)')
    global_regex = re.compile(r'f_([0-9a-fA-F]+)')
    local_regex = re.compile(r'.l_([0-9a-fA-F]+)')
    data_regex = re.compile(r'd_([0-9a-fA-F]+)')
    hexadecimal = re.compile(r'[0-9a-fA-F]+')

    last_global_label = None
    for line_index0, line in enumerate(data):
        match = line_regex.match(line)
        if not match:
            continue
        raw, real = match[1], match[2]
        if real.startswith('.'):
            continue

        match = data_regex.fullmatch(raw)
        if match:
            addr = int(match[1], 16)
            datalabels[real] = addr
            continue

        addr = None
        if hexadecimal.fullmatch(raw):
            addr = int(raw, 16)
            last_global_label = None
        else:
            match = global_regex.match(raw)
            if match:
                addr = int(match[1], 16)
                if len(match[0]) == len(raw):
                    last_global_label = addr
                else:
                    match = local_regex.fullmatch(raw[len(match[0]):])
                    if match:  # full address f_12345.l_67
                        addr += int(match[1], 16)
            else:
                match = local_regex.fullmatch(raw)
                if match:
                    if last_global_label is None:
                        print('Label cannot be read: ', line)
                        continue
                    else:
                        addr = last_global_label + int(match[1], 16)

        if addr is not None:
            assert addr < len(disasm), f'{addr:05X}'
            if disasm[addr].startswith('push lr'):
                tags = 'del lr',
                addr += 2
            else:
                tags = 'rt',
                a1 = addr + 2
                while not any(disasm[a1].startswith(x) for x in ('push lr', 'pop pc', 'rt')):
                    a1 += 2
                if not disasm[a1].startswith('rt'):
                    tags = tags + ('del lr',)

            if real in commands:
                if 'override rename list' in commands[real][1]:
                    continue
                if commands[real] == (addr, tags):
                    note(f'Warning: Duplicated command {real}\n')
                    continue

            add_command(commands, addr, real, tags=tags,
                       debug_info=f'at {filename}:{line_index0 + 1}')
        else:
            raise ValueError('Invalid line: ' + repr(line))

def sizeof_register(reg_name):
    return {'r': 1, 'e': 2, 'x': 4, 'q': 8}[reg_name[0]]

result = []
labels = {}
address_requests = []
relocation_expressions = []
pr_length_cmds = []
deferred_evals = []
home = None
in_comment = False
string_vars = {}
vars_dict = {}

def handle_label_definition(line):
    """
    Syntax: lbl <label>:
    Special: If the label is 'home', it specifies the point to
    start program execution. By default it's at the begin.
    """
    global labels, result
    label = to_lowercase(line.strip()[4:].strip())
    assert label not in labels, f'Duplicate label: {label}'
    labels[label] = len(result)
    
def handle_function_definition(line, program_iter, defined_functions):
    """
    Xử lý cú pháp:
        func <name>(<args>) {
            ...
        }
    Lưu trữ body vào defined_functions[<name>] = {"args": [...], "body": [...]}
    """
    m = re.match(r'func\s+(\w+)\s*\((.*?)\)\s*\{', line.strip())
    if not m:
        raise ValueError(f"Invalid func definition: {line}")
    func_name = m.group(1)
    func_args = [arg.strip() for arg in m.group(2).split(',')] if m.group(2) else []
    
    body = []
    for _, raw_line in program_iter:
        stripped = raw_line.strip()
        if stripped == '}':
            break
        body.append(stripped)
    
    if func_name in defined_functions:
        raise ValueError(f"Duplicate function: {func_name}")
    defined_functions[func_name] = {"args": func_args, "body": body}

def handle_hex_data(line):
    """Syntax: 0x<hex_digits>"""
    global result
    hex_str = line[2:]
    if len(hex_str) % 2 != 0:
        hex_str = '0' + hex_str
    n_byte = len(hex_str) // 2
    data = int(hex_str, 16)
    for _ in range(n_byte):
        result.append(data & 0xFF)
        data >>= 8

def handle_eval_expression(line):
    """Syntax: eval(<expression>)"""
    global result, deferred_evals, vars_dict
    
    expr = line[5:-1].strip()
    
    if 'adr(' in expr:
        deferred_evals.append((len(result), expr))
        result.extend((0, 0))
    else:
        local_vars = {}
        for k, v in vars_dict.items():
            local_vars[k] = v
        
        try:
            val = eval(expr, {}, local_vars)
        except Exception as e:
            raise ValueError(f"Eval error in line {line!r}: {e}")
        
        new_bytes_list = []
        if isinstance(val, int):
            hex_str = f"{val:x}"
            if len(hex_str) % 2 != 0:
                hex_str = '0' + hex_str
            val_bytes = val.to_bytes((val.bit_length() + 7) // 8, 'little', signed=val<0)
            if not val_bytes: val_bytes = b'\x00'
            new_bytes_list.extend(list(val_bytes))
        elif isinstance(val, str):
            for c in val:
                hx = char_to_hex.get(c)
                if not hx:
                    raise ValueError(f"Character '{c}' not found in char_to_hex")
                if len(hx) == 2:
                    new_bytes_list.append(int(hx, 16))
                elif len(hx) == 4:
                    new_bytes_list.extend([int(hx[:2],16), int(hx[2:],16)])
        elif isinstance(val, list):
            new_bytes_list.extend(val)
        else:
            raise ValueError(f"Unsupported eval result type: {type(val)}")
        
        result.extend(new_bytes_list)

def handle_long_hex_data(line):
    """Syntax: hex <hexadecimal digits>"""
    global result
    data_str = line[3:].strip()
    assert len(data_str.replace(" ", "")) % 2 == 0, f'Invalid data length'
    data_bytes = bytes.fromhex(data_str)
    result.extend(data_bytes)

def handle_call_command(line):
    """Syntax: `call <address>` or `call <built-in>`."""
    global commands
    try:
        adr = int(line[4:], 16)
    except ValueError:
        func_name = line[4:].strip()
        adr, tags = commands[func_name]
        for tag in tags:
            if tag.startswith('warning'):
                note(tag + '\n')

    assert 0 <= adr <= max_call_adr, f'Invalid address: {adr}'
    adr = optimize_adr_for_npress(adr)
    process_line(f'0x{adr + 0x30300000:0{8}x}')

def handle_goto_command(line):
    """Syntax: `goto <label>`"""
    label = to_lowercase(line[4:])
    process_line(f'er14 = eval(adr({label}) - 0x02)')
    process_line('call sp=er14,pop er14')

def handle_address_command(line):
    """
    syntax:
    - adr(label)
    """
    global deferred_evals, result
    
    line_strip = line.strip()
    if line_strip.startswith('adr(') and line_strip.endswith(')'):
        inner_content = line_strip[4:-1].strip()
        
        if ',' in inner_content:
            raise ValueError(f"Invalid adr(...) syntax: {line}")
        
        label_name = inner_content
        expr = f'adr("{label_name}")'
        deferred_evals.append((len(result), expr))
        result.extend((0, 0))
        
    else:
        raise ValueError(f"Unrecognized adr command: {line}")

def handle_data_label(line):
    """`<label>`."""
    process_line(f'adr({line}, 0)')

def handle_builtin_command(line):
    """`<built-in>`. Equivalent to `call <built-in>`."""
    line = to_lowercase(line)
    process_line('call ' + line)

def handle_assignment_command(line):
    """
    Syntax:
    int a = 0x3031
    str b = "hello"
    rel c = 0xabbcc
    reg [r/er/xr/qr] = value
    var <name> = <value>
    """
    global vars_dict, result
    
    i = line.index('=')
    left, right = line[:i].strip(), line[i+1:].strip()

    if left.startswith("int "):
        var_name = left[4:].strip()
        if "eval(" in right:
            vars_dict[var_name] = right
        else:
            assert right.startswith("0x"), f"Invalid int assignment: {line}"
            val = int(right, 16)
            val_bytes = val.to_bytes((val.bit_length() + 7) // 8, 'little', signed=val<0)
            if not val_bytes: val_bytes = b'\x00'
            vars_dict[var_name] = list(val_bytes)

    elif left.startswith("str "):
        var_name = left[4:].strip()
        assert '"' in right, f"Invalid str assignment: {line}"
        text = right.strip().strip('"').replace(" ", "~")
        new_bytes_list = []
        for c in text:
            if c not in char_to_hex:
                raise ValueError(f"Character '{c}' not found in conversion table")
            hx = char_to_hex[c]
            if len(hx) == 2:
                new_bytes_list.append(int(hx, 16))
            elif len(hx) == 4:
                new_bytes_list.extend([int(hx[:2], 16), int(hx[2:], 16)])
        vars_dict[var_name] = new_bytes_list

    elif left.startswith("rel "):
        var_name = left[4:].strip()
        assert right.startswith("0x"), f"Invalid rel assignment: {line}"
        val = int(right, 16)
        vars_dict[var_name] = val
        
    elif left.startswith("var "):
        var_name = left[4:].strip()
        try:
            import ast
            vars_dict[var_name] = ast.literal_eval(right.strip())
        except (ValueError, SyntaxError):
            vars_dict[var_name] = right.strip()

    elif left.startswith("reg "):
        register = left[4:].strip()
        value = right.replace(',', ';')
        process_line(f'call pop {register}')
        l1 = len(result)
        process_line(value)
        assert len(result) - l1 == sizeof_register(register), f'Line {line!r} source/destination target mismatches'

    else:
        register, value = left, right
        value = value.replace(',', ';')
        process_line(f'call pop {register}')
        l1 = len(result)
        process_line(value)
        assert len(result) - l1 == sizeof_register(register), f'Line {line!r} source/destination target mismatches'

def handle_variable_expansion(line):
    '''
    Syntax: Allows inserting variables `{var}` into any line.
    Ex:
    xr0 = {a}, {b}, adr(label)
    call {func}
    Each `{var}` is replaced with its stored value.
    '''
    global vars_dict

    def expand_vars_in_line(s):
        expanded_s = s
        vars_found = re.findall(r'\{([a-zA-Z_]\w*)\}', s)
        
        changed = False
        for var_name in vars_found:
            if var_name not in vars_dict:
                raise ValueError(f"Undefined variable: {var_name}")
            
            var_value = vars_dict[var_name]
            
            replacement_str = ""
            if isinstance(var_value, list):
                replacement_str = '0x' + ''.join(f'{b:02x}' for b in var_value)
            elif isinstance(var_value, int):
                replacement_str = f'0x{var_value:x}'
            elif isinstance(var_value, str):
                replacement_str = var_value
            else:
                raise ValueError(f"Unsupported variable type for {var_name}: {type(var_value)}")

            if f'{{{var_name}}}' in expanded_s:
                expanded_s = expanded_s.replace(f'{{{var_name}}}', replacement_str)
                changed = True
        
        if changed and '{' in expanded_s:
            return expand_vars_in_line(expanded_s)
        return expanded_s

    expanded_line = expand_vars_in_line(line)
    process_line(expanded_line)

def handle_org_command(line):
    ''' Syntax: `org <expr>`
    Specify the address of this location after mapping.
    Only use this for loader mode.
    '''
    global home, result
    hx = eval(line[3:])
    new_home = hx - len(result)
    assert home is None or home == new_home, 'Inconsistent value of `home`'
    home = new_home

def handle_pr_length_command(line):
    ''' Syntax: `pr_length`
    Defers the calculation of the program length until the end of processing.
    '''
    global pr_length_cmds, result
    pr_length_cmds.append(len(result))
    result.extend((0, 0))

def handle_key_constant(line):
    global result
    
    keyname = line.strip().upper()
    if 'KEY_MAP' not in globals():
        raise ValueError("KEY_MAP not found in globals; please define it first.")
    
    keymap = globals()['KEY_MAP']
    if keyname not in keymap:
        raise ValueError(f"Unknown key constant: {keyname}")

    value = keymap[keyname]
    new_bytes_list = []
    if isinstance(value, str):
        for part in value.split(','):
            part = part.strip()
            new_bytes_list.append(int(part, 0) & 0xFF)
    elif isinstance(value, (list, tuple)):
        new_bytes_list = [int(x) & 0xFF for x in value]
    else:
        raise ValueError(f"Invalid KEY_MAP entry for {keyname}: {value!r}")

    result.extend(new_bytes_list)

def handle_string_command(line):
    ''' Syntax: str "<string>" -> convert string directly to hex and append to result
        - char "~" converted to space
    '''
    global result
    
    content = line[3:].strip()
    if not (content.startswith('"') and content.endswith('"')):
        raise ValueError('Invalid str command syntax, must be: str "<string>"')
    
    text = content[1:-1].replace(" ", "~")
    
    # Convert string to bytes
    byte_list = []
    for c in text:
        try:
            hex_val = char_to_hex[c]
            if len(hex_val) == 2:
                byte_list.append(int(hex_val, 16))
            elif len(hex_val) == 4:
                byte_list.extend([int(hex_val[:2], 16), int(hex_val[2:], 16)])
        except KeyError:
            raise ValueError(f"Character '{c}' not found in conversion table")
    
    result.extend(byte_list)

def dispatch_command_handler(line, program_iter=None, defined_functions=None):
    global datalabels, commands, vars_dict
    line_strip = line.strip()

    if line.strip().lower().startswith('lbl '):
        handle_label_definition(line)
    elif line_strip.startswith("func "):
        if program_iter is None or defined_functions is None:
            raise ValueError("Function handling requires program_iter and defined_functions")
        handle_function_definition(line, program_iter, defined_functions)
    elif line.startswith('0x'):
        handle_hex_data(line)
    elif line.startswith('eval(') and line.endswith(')'):
        handle_eval_expression(line)
    elif line.startswith('hex') and 'hex_' not in line:
        handle_long_hex_data(line)
    elif line.startswith('call'):
        handle_call_command(line)
    elif line.startswith('goto'):
        handle_goto_command(line)
    elif line.startswith('adr'):
        handle_address_command(line)
    elif line in datalabels:
        # Must check after `call`, `goto`, `adr`.
        handle_data_label(line)
    elif line in commands:
        # Must check after `call`, `goto`, `adr`.
        handle_builtin_command(line)
    elif '=' in line:
        handle_assignment_command(line)
    elif '{' in line and '}' in line:
        # Check for {var} near the end
        handle_variable_expansion(line)
    elif line.startswith('org'):
        handle_org_command(line)
    elif line.startswith('pr_length'):
        handle_pr_length_command(line)
    elif line.strip().upper().startswith('KEY_'):
        handle_key_constant(line)
    elif line.startswith('str'):
        handle_string_command(line)
    else:
        assert False, f'Unrecognized command: {line!r}'


def process_line(line):
    global result, labels, address_requests, relocation_expressions, pr_length_cmds
    global home, string_vars, in_comment, vars_dict, deferred_evals

    if not line or line.isspace():
        return

    if line.startswith('/*'):
        in_comment = True
        return
        
    if '*/' in line:
        in_comment = False
        return
        
    if in_comment:
        return

    elif ';' in line:
        ''' Compound statement. Syntax:
        `<statement1> ; <statement2> ; ...`
        '''
        for command in line.split(';'):
            process_line(to_lowercase(command))

    else:
        dispatch_command_handler(line)

def finalize_processing():
    global result, labels, address_requests
    global relocation_expressions, pr_length_cmds
    global deferred_evals

    for pos, left_offset, left_label, right_offset, right_label, op in relocation_expressions:
        if left_label not in labels or right_label not in labels:
            raise ValueError(f'Label not found in adr: {left_label}, {right_label}')
        left_addr = labels[left_label] + left_offset
        right_addr = labels[right_label] + right_offset
        
        if op == '+':
            result_addr = (left_addr + right_addr) & 0xFFFF
        else: # op == '-'
            result_addr = (left_addr - right_addr) & 0xFFFF
        
        if result[pos] != 0 or result[pos+1] != 0:
            print(f"[WARN] adr overwrite at {pos:04X}")
        result[pos] = result_addr & 0xFF
        result[pos + 1] = (result_addr >> 8) & 0xFF

    for pos in pr_length_cmds:
        pr_length = len(result)
        if result[pos] != 0 or result[pos+1] != 0:
            print(f"[WARN] pr_length overwrite at {pos:04X}")
        result[pos] = pr_length & 0xFF
        result[pos + 1] = (pr_length >> 8) & 0xFF

    relocation_expressions.clear()
    pr_length_cmds.clear()

def process_program(args, program_lines, overflow_initial_sp):
    global result, labels, address_requests
    global relocation_expressions, pr_length_cmds, home
    global string_vars, in_comment, note
    global deferred_evals, vars_dict

    result = []
    labels = {}
    address_requests = []
    relocation_expressions = []
    pr_length_cmds = []
    deferred_evals = []
    home = None
    string_vars = {}
    in_comment = False
    vars_dict = {}
    
    final_lines_to_process = []
    
    defined_functions = {}

    program_iter = iter(enumerate(program_lines))
    for line_index, raw_line in program_iter:
        line = canonicalize(del_inline_comment(raw_line))
        
        if line.strip().startswith("func "):
            handle_function_definition(line, program_iter, defined_functions)
            continue

        m = re.match(r'(\w+)\s*\((.*?)\)', line.strip())
        if m:
            called_func_name = m.group(1)
            if called_func_name in defined_functions:
                func = defined_functions[called_func_name]
                call_args_str = m.group(2)
                call_args = re.findall(r'("(?:[^"\\]|\\.)*"|[^,]+)', call_args_str)
                call_args = [arg.strip() for arg in call_args]
                if call_args == [''] and not call_args_str:
                    call_args = []

                func_params_full = func["args"]
                if len(call_args) != len(func_params_full):
                    raise ValueError(f"Error calling function {line}: has {len(call_args)} arguments, but function definition {called_func_name} requires {len(func_params_full)}")

                for param_def, arg_val in zip(func_params_full, call_args):
                    parts = param_def.split()
                    if len(parts) != 2:
                        raise ValueError(f"Invalid function parameter definition: {param_def}")
                    param_type, param_name = parts[0], parts[1]
                    assignment_line = f"{param_type} {param_name} = {arg_val}"
                    final_lines_to_process.append(assignment_line)
                
                for line_in_func in func["body"]:
                    final_lines_to_process.append(line_in_func)
                
                continue

        final_lines_to_process.append(line)

    for line in final_lines_to_process:
        line_strip = canonicalize(del_inline_comment(line))

        if not line_strip.lower().startswith("str"):
            line_to_process = to_lowercase(line_strip)
        else:
            line_to_process = line_strip

        if not line_to_process:
            continue

        note_log = ''
        original_note_func = note

        def local_note_func(st):
            nonlocal note_log
            note_log += st
        
        note = local_note_func
        old_len_result = len(result)
        try:
            process_line(line_to_process)
        except:
            original_note_func(f'While processing line\n{line}\n')
            raise

        if args.format == 'key' and \
                any(x != 0 and get_npress(x) > 100 for x in result[old_len_result:]):
            local_note_func('Line generates many keypresses\n')

        note = original_note_func
        if note_log:
            note(f'While processing line\n{line}\n')
            note(note_log)

    eval_scope = {}
    for k, v in vars_dict.items():
        if isinstance(v, list):
             eval_scope[k] = int.from_bytes(bytes(v), 'little')
        else:
             eval_scope[k] = v

    for label_name in labels.keys():
         if label_name not in eval_scope:
            eval_scope[label_name] = label_name

    def adr_eval(label, offset=0):
        if not isinstance(label, str):
             raise ValueError(f"Label in adr() must be a string, but got {label} (type {type(label)})")
        if label not in labels:
            raise ValueError(f'Label not found during deferred eval: {label}')
        return (labels[label] + offset)

    eval_scope['adr'] = adr_eval
    home_dependent_evals = [] 
    temp_deferred_evals = list(deferred_evals)
    deferred_evals.clear() 
    
    for pos, expr in temp_deferred_evals:
        try:
            val = eval(expr, {}, eval_scope)
        except Exception as e:
            try:
                temp_scope = eval_scope.copy()
                for k, v in temp_scope.items():
                    if isinstance(v, str) and v.startswith("eval("):
                         temp_scope[k] = eval(v[5:-1], {}, temp_scope)
                val = eval(expr, {}, temp_scope)
            except Exception as e2:
                 raise ValueError(f"Deferred eval error in expression {expr!r}: {e2}")
        
        if not isinstance(val, int):
            raise ValueError(f"Deferred eval {expr!r} did not return an integer")
        
        is_absolute_address = expr.count('adr(') > 1
        
        if is_absolute_address:
            val = val & 0xFFFF
            if result[pos] != 0 or result[pos+1] != 0:
                print(f"[WARN] eval_abs overwrite at {pos:04X}")
            result[pos] = val & 0xFF
            result[pos + 1] = (val >> 8) & 0xFF
        else:
            home_dependent_evals.append((pos, val))
            
    finalize_processing()
    
    resolved_adr_cmds = []
    for source_adr, offset, target_label in address_requests:
        if target_label not in labels:
             raise ValueError(f'Label not found: {target_label} (for adr() at pos {source_adr})')
        resolved_adr_cmds.append((source_adr, labels[target_label] + offset))
    
    address_requests.clear()
    if args.target in ('none', 'overflow'):
        if args.target == 'overflow':
            assert len(result) <= 100, 'Program too long'

        if home is None:
            home = overflow_initial_sp
            if 'home' in labels:
                home -= labels['home']
            if home + len(result) > 0x8E00:
                note(f'Warning: Program length after home = {len(result)} bytes'
                     f' > {0x8E00 - home} bytes\n')

            min_home = home
            while min_home >= 0x8154 + 200:
                min_home -= 100
            while home + len(result) <= 0x8E00:
                home += 100
            
            all_home_dependencies = resolved_adr_cmds + home_dependent_evals
            
            home = min(range(min_home, home, 100), key=lambda home_val:
                        (
                            sum(
                                get_npress_adr(home_val + home_offset) >= 100
                                for source_adr, home_offset in all_home_dependencies
                            ),
                            -home_val
                        )
                        )

    elif args.target == 'loader':
        if home is None:
            home = 0x85b0 - len(result)
            entry = home + labels.get('home', 0) - 2
            result.extend((0x6a, 0x4f, 0, 0, entry & 255, entry >> 8, 0x68, 0x4f, 0, 0))
            while home + len(result) < 0x85d7:
                result.append(0)
            result.extend((0xff, 0xae, 0x85))
            home2 = 0
            assert (home - home2) >= 0x8501, 'Program too long'
            while get_npress_adr(home - home2) >= 100:
                home2 += 1

    else:
        assert False, 'Internal error'

    assert home is not None

    for source_adr, home_offset in resolved_adr_cmds:
        target_adr = home + home_offset
        if result[source_adr] != 0 or result[source_adr + 1] != 0:
            print(f"[WARN] adr overwrite at {source_adr:04X}, old={result[source_adr]:02X}{result[source_adr+1]:02X}")
        result[source_adr] = target_adr & 0xFF
        result[source_adr + 1] = target_adr >> 8

    for source_adr, home_offset in home_dependent_evals:
        target_adr = home + home_offset
        if result[source_adr] != 0 or result[source_adr + 1] != 0:
            print(f"[WARN] eval_adr overwrite at {source_adr:04X}, old={result[source_adr]:02X}{result[source_adr+1]:02X}")
        result[source_adr] = target_adr & 0xFF
        result[source_adr + 1] = target_adr >> 8

    for label, home_offset in labels.items():
        note(f'Label {label} is at address {home + home_offset:04X}\n')
            
    if args.target == 'overflow':
        hackstring = list(map(ord, '1234567890' * 10))
        for home_offset, byte in enumerate(result):
            assert isinstance(byte, int), (home_offset, byte)
            hackstring_pos = (home + home_offset - 0x8154) % 100
            hackstring[hackstring_pos] = byte

    if args.target == 'overflow' and args.format == 'hex':
        print(''.join(f'{byte:0{2}x}' for byte in hackstring))
    elif args.target == 'none' and args.format == 'hex':
        print('0x%04x:' % home, *map('%02x'.__mod__, result))
    elif args.target == 'none' and args.format == 'key':
        print(f'{home:#06x}:', ' '.join(
            byte_to_key(byte) for byte in result
        ))
    elif args.target == 'loader' and args.format == 'key':
        print('Address to load: %s %s' % (byte_to_key((home - home2) & 255), byte_to_key((home - home2) >> 8)))
        for i in range(home2):
            result.insert(0, 0)
        import keypairs
        print(keypairs.format(result))
    elif args.target == 'overflow' and args.format == 'key':
        print(' '.join(byte_to_key(x) for x in hackstring))
    else:
        raise ValueError('Unsupported target/format combination')

rom = None

def get_rom(x):
    global rom

    if isinstance(x, str):
        with open(x, 'rb') as f:
            rom = f.read()
    elif isinstance(x, bytes):
        rom = x
    else:
        raise TypeError

def find_equivalent_addresses(rom_data: bytes, address_queue: set):
    # xử lý BL / POP PC, BC AL, B
    from collections import defaultdict
    comefrom = defaultdict(list)

    for i in range(0, len(rom_data), 2):  # BC AL
        if rom_data[i + 1] == 0xce:
            offset = rom_data[i]
            if offset >= 128:
                offset -= 256
            target_addr = i >> 16 | ((i + (offset + 1) * 2) & 0xffff)
            comefrom[target_addr].append(i)

    for i in range(0, len(rom_data) - 2, 2):  # B
        if (
                rom_data[i] == 0x00 and
                (rom_data[i + 1] & 0xf0) == 0xf0):
            target_addr = (rom_data[i + 1] & 0x0f) << 16 | rom_data[i + 3] << 8 | rom_data[i + 2]
            comefrom[target_addr].append(i)

    for i in range(0, len(rom_data) - 4, 2):  # BL / POP PC
        if (
                rom_data[i] == 0x01 and
                (rom_data[i + 1] & 0xf0) == 0xf0 and
                (rom_data[i + 4] & 0xf0) == 0x8e and
                (rom_data[i + 5] & 0xf0) == 0xf2):
            target_addr = (rom_data[i + 1] & 0x0f) << 16 | rom_data[i + 3] << 8 | rom_data[i + 2]
            comefrom[target_addr].append(i)

    ans = set()
    while address_queue:
        adr = address_queue.pop()
        if adr in ans:
            continue
        ans.add(adr)

        if adr in comefrom:
            address_queue.update(comefrom[adr])

    return ans

def optimize_gadget_from_rom(rom_data: bytes, gadget_bytes: bytes) -> set:
    assert len(gadget_bytes) % 2 == 0
    pending_addresses = set()
    
    for i in range(0, len(rom_data) - len(gadget_bytes) + 1, 2):
        if rom_data[i:i + len(gadget_bytes)] == gadget_bytes:
            pending_addresses.add(i)

    return find_equivalent_addresses(rom_data, pending_addresses)

def optimize_gadget(gadget_bytes: bytes) -> set:
    global rom
    return optimize_gadget_from_rom(rom, gadget_bytes)

def print_addresses(adrs, n_preview: int):
    adrs = list(map(optimize_adr_for_npress, adrs))
    for adr in sorted(adrs, key=get_npress_adr):
        keys = ' '.join(map(byte_to_key,
                            (adr & 0xff, (adr >> 8) & 0xff, 0x30 | adr >> 16)
                            ))
        print(f'{adr:05x}  {get_npress_adr(adr):3}    {keys:20}')

        i = adr & 0xffffe
        for _ in range(n_preview):
            if i < len(disasm) and disasm[i]:
                print(' ' * 4 + disasm[i])
            i += 2
            while i < len(disasm) and not disasm[i]:
                i += 2
            if i >= len(disasm):
                break