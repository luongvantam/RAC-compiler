# -*- coding: utf-8 -*-
# Created by luongvantam last created: 02:45 PM 11-01-2025(GMT+7)
from ast import expr
import re, sys, os
from functools import lru_cache

max_call_adr = 0x3ffff
char_to_hex = dict(zip(
    '''0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzÁáÀàẢảÃãẠạĂăẮắẰằẲẳẴẵẶặÂâẤấẦầẨẩẪẫẬậÉéÈèẺẻẼẽẸẹÊêẾếỀềỂểỄễỆệÍíÌìỈỉĨĩỊịÓóÒòỎỏÕõỌọÔôỐốỒồỔổỖỗỘộƠơỚớỜờỞởỠỡỢợÚúÙùỦủŨũỤụƯưỨứỪừỬửỮữỰựÝýỲỳỶỷỸỹỴỵĐđ~@_&-+()/*':!?|√÷×^°{}[]%.,''',
    [
        '30', '31', '32', '33', '34', '35', '36', '37', '38', '39',
        '41', '42', '43', '44', '45', '46', '47', '48', '49', '4A',
        '4B', '4C', '4D', '4E', '4F', '50', '51', '52', '53', '54',
        '55', '56', '57', '58', '59', '5A', '61', '62', '63', '64',
        '65', '66', '67', '68', '69', '6A', '6B', '6C', '6D', '6E',
        '6F', '70', '71', '72', '73', '74', '75', '76', '77', '78',
        '79', '7A', 'F451', 'F471', 'F450', 'F470', 'F454', 'F474',
        'F453', 'F473', 'F410', 'F465', 'F455', 'F475', 'F411', 'F431',
        'F412', 'F432', 'F490', 'F456', 'F491', 'F457', 'F413', 'F433',
        'F452', 'F472', 'F414', 'F434', 'F415', 'F435', 'F416', 'F436',
        'F492', 'F477', 'F417', 'F437', 'F459', 'F479', 'F458', 'F478',
        'F45B', 'F47B', 'F418', 'F438', 'F419', 'F439', 'F45A', 'F47A',
        'F41A', 'F43A', 'F41B', 'F43B', 'F41C', 'F43C', 'F41D', 'F43D',
        'F41E', 'F43E', 'F45D', 'F47D', 'F45C', 'F47C', 'F42B', 'F47F',
        'F45E', 'F47E', 'F428', 'F448', 'F463', 'F483', 'F462', 'F482',
        'F429', 'F486', 'F430', 'F485', 'F42A', 'F487', 'F464', 'F484',
        'F41F', 'F43F', 'F420', 'F440', 'F421', 'F441', 'F422', 'F442',
        'F423', 'F445', 'F444', 'F44D', 'F425', 'F44E', 'F426', 'F446',
        'F427', 'F447', 'F443', 'F46E', 'F424', 'F48E', 'F46A', 'F48A',
        'F469', 'F489', 'F42C', 'F48C', 'F42D', 'F48B', 'F42E', 'F488',
        'F44F', 'F46F', 'F44A', 'F461', 'F44B', 'F467', 'F44C', 'F468',
        'F48F', 'F476', 'F449', 'F481', 'F46D', 'F48D', 'F42F', 'F45F',
        'F493', 'F466', 'F494', 'F46B', 'F495', 'F46C', 'F460', 'F480',
        '20', '40', '5F', '1A', '2D', '2B', '28', '29', '2F',
        '2A', '27', '3A', '21', '3F', '7C', '98', '26',
        '24', '5E', '85', '7B', '7D', '5B', '5D', '25',
        '2E', '2C'
    ]
))

PYTHON_FUNCTIONS = {}

class PyNamespace:
    def __init__(self, functions):
        for name, func in functions.items():
            setattr(self, name, func)
    def __getattr__(self, name):
        raise AttributeError(f"Python function '{name}' not found")

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
        
def get_key_map(filename):
    global KEY_MAP
    KEY_MAP = {}
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
        KEY_MAP[key_name] = f"0x{hex_raw[:2]}, 0x{hex_raw[2:]}"

def get_disassembly(filename):
	'''Try to parse a disasm file with annotated address.

	Each line should look like this:

		mov r2, 1                      ; 0A0A2 | 0201
	'''
	global disasm
	with open(filename, 'r', encoding='u8') as f:
		data = f.read().splitlines()

	line_regex = re.compile(r'\t(.*?)\s*; ([0-9a-fA-F]*) \|')
	disasm = []
	for line in data:
		match = line_regex.match(line)  # match prefix
		if match:
			addr = int(match[2], 16)
			while addr >= len(disasm): disasm.append('')
			disasm[addr] = match[1]

def load_extensions(path):
    if not os.path.exists(path):
        print(f"[WARN] No extension file found: {path}")
        return []

    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    pattern = r"---syntax---\s*(.*?)\s*---logic---\s*(.*?)\s*---output---\s*(.*?)\s*(?=---syntax---|$)"
    matches = re.findall(pattern, content, re.DOTALL)

    extensions = []
    for syntax_block, logic_block, output_block in matches:
        extensions.append({
            "syntax": syntax_block.strip(),
            "logic": logic_block.strip(),
            "output": [ln.strip() for ln in output_block.strip().splitlines() if ln.strip()]
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
        line = line.split('---')[0].strip()
        if not line: continue
        
        current_line = line
        matched_full = False
        
        for ext in sorted(extensions, key=lambda x: len(x["syntax"]), reverse=True):
            pattern_str = re.escape(ext["syntax"]).replace(r"\{", "(?P<").replace(r"\}", ">.+?)")
            
            match = re.fullmatch(pattern_str, current_line)
            is_inline = False
            
            if not match:
                match = re.search(pattern_str, current_line)
                is_inline = True
            
            if match:
                local_env = match.groupdict()
                if ext.get("logic"):
                    try:
                        import random, string, re as re_mod
                        env = {**local_env, "random": random, "string": string, "re": re_mod}
                        exec(ext["logic"], {}, env)
                        local_env.update(env)
                    except: pass
                
                output_lines = []
                for out in ext["output"]:
                    temp = out
                    for k, v in local_env.items():
                        temp = temp.replace(f"{{{k}}}", str(v))
                    output_lines.append(temp)
                
                if is_inline and len(output_lines) == 1:
                    current_line = current_line[:match.start()] + output_lines[0] + current_line[match.end():]
                else:
                    expanded.extend(output_lines)
                    matched_full = True
                    break
        
        if not matched_full:
            expanded.append(current_line)
    return expanded

def read_rename_list(filename):
    '''Try to parse a rename list.

    If the rename list is ambiguous without disassembly, it raises an error.
    '''
    global commands, datalabels
    with open(filename, 'r', encoding='u8') as f:
        data = f.read().splitlines()

    line_regex   = re.compile(r'^\s*([\w_.]+)\s+([\w_.]+)')
    global_regex = re.compile(r'f_([0-9a-fA-F]+)')
    local_regex  = re.compile(r'.l_([0-9a-fA-F]+)')
    data_regex   = re.compile(r'd_([0-9a-fA-F]+)')
    hexadecimal  = re.compile(r'[0-9a-fA-F]+')

    last_global_label = None
    for line_index0, line in enumerate(data):
        match = line_regex.match(line)
        if not match: continue
        raw, real = match[1], match[2]
        if real.startswith('.'):
            # we don't get local labels.
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
            # because we don't know whether this label is global or local
        else:
            match = global_regex.match(raw)
            if match:
                addr = int(match[1], 16)
                if len(match[0]) == len(raw):  # global_regex.fullmatch
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
                while not any(disasm[a1].startswith(x) for x in ('push lr', 'pop pc', 'rt')): a1 += 2
                if not disasm[a1].startswith('rt'):
                    tags = tags + ('del lr',)

            if real in commands:
                if 'override rename list' in commands[real][1]:
                    continue
                if commands[real] == (addr, tags):
                    note(f'Warning: Duplicated command {real}\n')
                    continue

            add_command(commands, addr, real, tags=tags,
                    debug_info=f'at {filename}:{line_index0+1}')
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
KEY_MAP = {}

def handle_label_definition(line):
    """
    Syntax: lbl <label>
    Special: If the label is 'home', it specifies the point to
    start program execution. By default it's at the begin.
    """
    global labels, result
    label = to_lowercase(line.strip()[4:].strip())
    assert label not in labels, f'Duplicate label: {label}'
    labels[label] = len(result)
    
def handle_function_definition(line, program_iter, defined_functions):
    m = re.match(r'func\s+(\w+)\s*\((.*?)\)\s*\{', line.strip())
    if not m: raise ValueError(f"Invalid func definition syntax: {line}")
    func_name, args_str = m.group(1), m.group(2).strip()
    func_args = [arg.strip() for arg in args_str.split(',')] if args_str else []
    
    body = []
    for _, raw_line in program_iter:
        stripped = raw_line.split('---')[0].strip()
        if stripped == '}': break
        if stripped: body.append(stripped)
    defined_functions[func_name] = {"args": func_args, "body": body}

def handle_python_def(line, program_iter, python_functions):
    # Parse header to get function name and arguments
    m = re.match(r'def\s+(\w+)\s*\((.*?)\)\s*\{', line.strip())
    if not m:
        raise ValueError(f"Invalid def syntax: {line}")
    func_name, args_str = m.group(1), m.group(2).strip()
    func_args = [arg.strip() for arg in args_str.split(',')] if args_str else []
    
    # Collect all body lines, tracking brace depth for nested blocks
    # depth=1 because we already opened the function's {
    raw_body = []
    depth = 1
    for _, raw_line in program_iter:
        content = raw_line.split('---')[0].strip()
        if not content:
            continue
        
        # Count braces in this line
        open_count = content.count('{')
        close_count = content.count('}')
        
        # If line is just "}", it closes a block
        if content == '}':
            depth -= 1
            if depth <= 0:
                break
            raw_body.append(content)
            continue
        
        depth += open_count - close_count
        raw_body.append(content)
    
    # Now convert the brace-based syntax into valid Python source
    # Process raw_body into Python lines with proper indentation
    def convert_block(lines, start_idx):
        """Convert lines with { } blocks into Python indented code.
        Returns (python_lines, next_index)"""
        py_lines = []
        idx = start_idx
        while idx < len(lines):
            line = lines[idx].strip()
            
            if line == '}':
                # End of current block
                return py_lines, idx + 1
            
            if line.endswith('{'):
                # Start of a sub-block: "if condition {" or "else {"  or "for x in y {"
                header = line[:-1].strip()  # remove the {
                
                # Collect inner block lines until matching }
                inner_lines, idx = convert_block(lines, idx + 1)
                
                if inner_lines:
                    # Join inner lines with ; for single-line block
                    inner_joined = '; '.join(inner_lines)
                    py_lines.append(f"{header}: {inner_joined}")
                else:
                    py_lines.append(f"{header}: pass")
            else:
                py_lines.append(line)
                idx += 1
        
        return py_lines, idx
    
    # Normalize raw_body to ensure } are on their own lines for correct block parsing
    normalized_body = []
    for line in raw_body:
        s = line.strip()
        # Handle } at the start (e.g. "} elif ... {" -> "}", "elif ... {")
        while s.startswith('}'):
            normalized_body.append('}')
            s = s[1:].strip()
        
        if not s:
            continue
            
        # Handle } at the end (e.g. "stmt; }" -> "stmt;", "}")
        # Only if it's not a one-liner block start like "if { }" which we don't fully support yet,
        # but safely splitting "abc }" into "abc", "}" works for standard block ends.
        if s.endswith('}') and not s.startswith('{'):
            # Avoid splitting "}" if it is just "}" (already handled by startswith but good for safety)
            if len(s) > 1:
                normalized_body.append(s[:-1].strip())
                normalized_body.append('}')
                continue
        
        normalized_body.append(s)

    converted_lines, _ = convert_block(normalized_body, 0)
    
    # Build final Python source with proper indentation
    func_src = f"def {func_name}({', '.join(func_args)}):\n"
    if not converted_lines:
        func_src += '    pass\n'
    else:
        for l in converted_lines:
            func_src += '    ' + l + '\n'
    
    try:
        local_ns = {}
        exec(func_src, {"re": re, "os": os, "sys": sys}, local_ns)
        python_functions[func_name] = local_ns[func_name]
    except Exception as e:
        raise ValueError(f"Error compiling Python function {func_name}:\n{e}\nSource:\n{func_src}")

def handle_python_call(line):
    """
    Execute a Python call from assembly.
    If the function returns a string or list of strings, they are processed as assembly lines.
    """
    local_vars = vars_dict.copy()
    local_vars['py'] = PyNamespace(PYTHON_FUNCTIONS)
    try:
        res = eval(line, {"py": local_vars['py']}, local_vars)
        if isinstance(res, str):
            process_line(res)
        elif isinstance(res, int):
            # For integers, convert to hex and process (usually adds bytes)
            process_line(hex(res))
        elif isinstance(res, list):
            for item in res:
                if isinstance(item, str): process_line(item)
                elif isinstance(item, int): process_line(hex(item))
    except Exception as e:
        raise ValueError(f"Error in Python call {line!r}: {e}")

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
    expr = line[5:-1].strip()

    # Step 1: Expand variables from vars_dict into the expression
    expanded_expr = expr
    for var_name, var_value in vars_dict.items():
        pattern = r'\b' + re.escape(var_name) + r'\b'
        expanded_expr = re.sub(pattern, str(var_value), expanded_expr)

    # Step 2: If expression contains adr(), defer evaluation to later
    if 'adr(' in expanded_expr:
        deferred_evals.append((len(result), expanded_expr))
        result.extend((0, 0))
        return

    # Step 3: Build eval scope with special values
    eval_scope = {}
    eval_scope['pr_length'] = len(result)
    eval_scope['py'] = PyNamespace(PYTHON_FUNCTIONS)

    # Step 4: Evaluate the expanded expression
    try:
        val = eval(expanded_expr, {"py": eval_scope.get('py')}, eval_scope)
    except Exception as e:
        raise ValueError(f"Eval error in '{expr}' (expanded: '{expanded_expr}'): {e}")

    # Step 5: Process the result back through process_line
    if isinstance(val, int):
        process_line(f'0x{val:x}')
    elif isinstance(val, str):
        process_line(f'"{val}"')
    elif isinstance(val, list):
        for item in val:
            if isinstance(item, int):
                process_line(f'0x{item:x}')
            elif isinstance(item, str):
                process_line(f'"{item}"')
    else:
        raise ValueError(f"Unsupported eval result type: {type(val)}")


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
    # process_line(f'0x{adr + 0x30300000:0{8}x}')
    process_line(f'0x{adr + 0x00000000:0{8}x}')

def handle_goto_command(line):
    """Syntax: `goto <label>`"""
    label = to_lowercase(line[4:])
    process_line(f'er14 = eval(adr({label}) - 0x02);call sp=er14,pop er14')

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
    global datalabels
    line=datalabels[line.strip()]
    process_line(f'0x{line:x}')

def handle_builtin_command(line):
    """`<built-in>`. Equivalent to `call <built-in>`."""
    line = to_lowercase(line)
    process_line('call ' + line)

def handle_assignment_command(line):
    i = line.index('=')
    left, right = line[:i].strip(), line[i+1:].strip()

    def try_eval(expr):
        try:
            local_vars = vars_dict.copy()
            local_vars['py'] = PyNamespace(PYTHON_FUNCTIONS)
            res = eval(expr, {"py": local_vars['py']}, local_vars)
            return res
        except:
            return expr

    if left.startswith("var "):
        var_name = left[4:].strip()
        val = right
        vars_dict[var_name] = val
    elif left.startswith("reg ") or (left[0] in 'rexq' and any(left.startswith(prefix) for prefix in ['r', 'er', 'xr', 'qr'])):
        register = left[4:].strip() if left.startswith("reg ") else left
        val = try_eval(right)
        if isinstance(val, int):
            value = hex(val)
        elif isinstance(val, list):
            # If it's a list, we might need a way to process it. 
            # For now, let's assume it's converted to a hex string or handled by process_line if supported.
            value = str(val) 
        else:
            value = str(val)
        
        value = value.replace(',', ';')
        process_line(f'call pop {register}')
        l1 = len(result)
        process_line(value)
        assert len(result) - l1 == sizeof_register(register), f'Line {line!r} source/destination target mismatches'
    else:
        # Non-prefixed variable assignment
        val = try_eval(right)
        vars_dict[left] = val

def handle_variable_expansion(line):
    expanded = line

    for var_name, var_value in vars_dict.items():
        pattern = r'\b' + re.escape(var_name) + r'\b'
        expanded = re.sub(pattern, str(var_value), expanded)

    process_line(expanded)

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
    keyname = line.strip().upper()
    if keyname not in KEY_MAP:
        raise ValueError(f"Unknown key constant: {keyname}. KEY_MAP size: {len(KEY_MAP)}")
    value = KEY_MAP[keyname]
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

def process_string_to_hex(text):
    processed_text = text.replace(" ", "~")
    for c in processed_text:
        if c in char_to_hex:
            hx = char_to_hex[c]
            if len(hx) == 2:
                result.append(int(hx, 16))
            elif len(hx) == 4:
                result.extend([int(hx[:2], 16), int(hx[2:], 16)])
        else:
            result.append(ord(c))

def handle_any_string_command(line):
    line_strip = line.strip()
    match = re.search(r'"(.*)"', line_strip)
    if not match:
        return
    content = match.group(1)
    # Replace {var} with value from context.vars_dict
    def replace_var(m):
        var_name = m.group(1)
        if var_name in vars_dict:
            return str(vars_dict[var_name])
        else:
            raise ValueError(f"Undefined variable: {var_name}")
    content = re.sub(r'\{([a-zA-Z_]\w*)\}', replace_var, content)
    process_string_to_hex(content)

def dispatch_command_handler(line, program_iter=None, defined_functions=None):
    line_strip = line.strip()
    if line.strip().lower().startswith('lbl '):
        handle_label_definition(line)
    elif line_strip.startswith("def ") and line_strip.endswith('{'):
        if program_iter is None:
            raise ValueError("Python def handling requires program_iter")
        handle_python_def(line_strip, program_iter, PYTHON_FUNCTIONS)
    elif line_strip.startswith("func "):
        if program_iter is None or defined_functions is None:
            raise ValueError("Function handling requires program_iter and defined_functions")
        handle_function_definition(line, program_iter, defined_functions)
    elif line_strip.startswith('py.'): handle_python_call(line_strip)
    elif line.startswith('0x'): handle_hex_data(line)
    elif (line.startswith('eval(') or line.startswith('calc(')) and line.endswith(')'): handle_eval_expression(line)
    elif line.startswith('hex') and 'hex_' not in line: handle_long_hex_data(line)
    elif line.startswith('call'): handle_call_command(line)
    elif line.startswith('goto'): handle_goto_command(line)
    elif line.startswith('adr'): handle_address_command(line)
    elif line in datalabels: handle_data_label(line)
    elif line in commands: handle_builtin_command(line)
    elif line in vars_dict: handle_variable_expansion(line)
    elif '=' in line: handle_assignment_command(line)
    elif line.startswith('org'): handle_org_command(line)
    elif line.startswith('pr_length'): handle_pr_length_command(line)
    elif line.strip().upper().startswith('KEY_'): handle_key_constant(line)
    elif line_strip.startswith('"'): handle_any_string_command(line_strip)
    else:
        assert False, f'Unrecognized command: {line!r}'

def process_line(line):
    global result, labels, address_requests, relocation_expressions, pr_length_cmds
    global home, string_vars, in_comment, vars_dict, deferred_evals
    line = line.split('---')[0].strip()

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
    
    final_execution_plan = []
    
    final_lines_to_process = []
    
    defined_functions = {}
    
    orig_line_map = []
    for idx, raw_line in enumerate(program_lines):
        orig_line_map.append(idx + 1)  # 1-based line number

    program_iter = iter(enumerate(program_lines))
    for line_index, raw_line in program_iter:
        line = canonicalize(del_inline_comment(raw_line))

        line_strip = line.strip()
        if line_strip.startswith("func "):
            handle_function_definition(line, program_iter, defined_functions)
            continue

        if line_strip.startswith("def ") and line_strip.endswith('{'):
            handle_python_def(line_strip, program_iter, PYTHON_FUNCTIONS)
            continue

        m = re.match(r'(\w+)\s*\((.*?)\)', line.strip())
        if m and m.group(1) in defined_functions:
            called_func_name = m.group(1)
            func = defined_functions[called_func_name]
            call_args_str = m.group(2)
            call_args = re.findall(r'("(?:[^"\\]|\\.)*"|[^,]+)', call_args_str)
            call_args = [arg.strip() for arg in call_args]
            if call_args == [''] and not call_args_str: call_args = []

            if len(call_args) != len(func["args"]):
                raise ValueError(f"Error calling function {line}: args mismatch")

            for param_def, arg_val in zip(func["args"], call_args):
                if param_def.strip():
                    final_lines_to_process.append({
                        "exec": f"{param_def.strip()} = {arg_val}",
                        "raw": raw_line, "num": orig_line_map[line_index], "ctx": f"passing args to '{called_func_name}'"
                    })
            for line_in_func in func["body"]:
                final_lines_to_process.append({"exec": line_in_func, "raw": line_in_func, "num": orig_line_map[line_index], "ctx": f"inside '{called_func_name}'"})
            continue

        final_lines_to_process.append({"exec": line, "raw": raw_line, "num": orig_line_map[line_index], "ctx": ""})

    for item in final_lines_to_process:
            if isinstance(item, dict):
                line = item["exec"]
                raw_origin = item["raw"]
                line_num = item["num"]
                context = item.get("ctx", "")
            else:
                line = item
                raw_origin = item
                line_num = "?"
                context = ""

            line_strip = canonicalize(del_inline_comment(line))

            if not line_strip.startswith('"'):
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
            except Exception as e:
                print(f"\nTraceback (most recent call last):")
                ctx_info = f", {context}" if context else ""
                fname = os.path.basename(args.input_file) if hasattr(args, 'input_file') else "?"
                if fname != "?":
                    print(f"  File \"{fname}\", line {line_num}{ctx_info}")
                else:
                    print(f"  In line {line_num}{ctx_info}")
                print(f"    {raw_origin.strip()}")
                print(f"    {"^" * len(raw_origin.strip())}")
                print(f"CompilerError: {str(e)}")
                sys.exit()

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
    global disasm 
    
    adrs = list(map(optimize_adr_for_npress, adrs))
    for adr in sorted(adrs, key=get_npress_adr):
        keys = ' '.join(map(byte_to_key,
                            (adr & 0xff, (adr >> 8) & 0xff, 0x30 | adr >> 16)
                            ))
        print(f'{adr:05x}  {get_npress_adr(adr):3}    {keys:20}')

        i = adr & 0x3FFFE
        count = 0
        while count < n_preview and i < len(disasm):
            opcode = disasm[i]
            if opcode != 0:
                label_name = globals().get('labels', {}).get(i, "")
                label_str = f" <{label_name}>" if label_name else ""
                
                print(f'    {i:05x}: {opcode:04x}{label_str}')
                count += 1
            i += 2