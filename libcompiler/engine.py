# -*- coding: utf-8 -*-
import sys, os, re
from . import context, consts
from .utils import canonicalize, del_inline_comment, to_lowercase, note
from .hardware import optimize_adr_for_npress, get_npress, get_npress_adr, byte_to_key
from .loader import sizeof_register

in_comment = False

def handle_label_definition(line):
    label = to_lowercase(line.strip()[4:].strip())
    assert label not in context.labels, f'Duplicate label: {label}'
    context.labels[label] = len(context.result)
    
def handle_function_definition(line, program_iter, defined_functions):
    m = re.match(r'func\s+(\w+)\s*\((.*?)\)\s*\{', line.strip())
    if not m: raise ValueError(f"Invalid func definition syntax: {line}")
    func_name, args_str = m.group(1), m.group(2).strip()
    func_args = [arg.strip() for arg in args_str.split(',')] if args_str else []
    
    body = []
    for _, raw_line in program_iter:
        stripped = raw_line.strip()
        if stripped == '}': break
        if stripped: body.append(stripped)
    defined_functions[func_name] = {"args": func_args, "body": body}

def handle_hex_data(line):
    hex_str = line[2:]
    if len(hex_str) % 2 != 0: hex_str = '0' + hex_str
    n_byte = len(hex_str) // 2
    data = int(hex_str, 16)
    for _ in range(n_byte):
        context.result.append(data & 0xFF)
        data >>= 8

def handle_eval_expression(line):
    expr = line[5:-1].strip()
    if 'adr(' in expr:
        context.deferred_evals.append((len(context.result), expr))
        context.result.extend((0, 0))
    else:
        local_vars = context.vars_dict.copy()
        try:
            val = eval(expr, {}, local_vars)
        except Exception as e:
            raise ValueError(f"Eval error in line {line!r}: {e}")
        
        new_bytes_list = []
        if isinstance(val, int):
            hex_str = f"{val:x}"
            if len(hex_str) % 2 != 0: hex_str = '0' + hex_str
            val_bytes = val.to_bytes((val.bit_length() + 7) // 8, 'little', signed=val<0)
            if not val_bytes: val_bytes = b'\x00'
            new_bytes_list.extend(list(val_bytes))
        elif isinstance(val, str):
            for c in val:
                hx = consts.char_to_hex.get(c)
                if not hx: raise ValueError(f"Character '{c}' not found in char_to_hex")
                if len(hx) == 2:
                    new_bytes_list.append(int(hx, 16))
                elif len(hx) == 4:
                    new_bytes_list.extend([int(hx[:2],16), int(hx[2:],16)])
        elif isinstance(val, list):
            new_bytes_list.extend(val)
        else:
            raise ValueError(f"Unsupported eval result type: {type(val)}")
        context.result.extend(new_bytes_list)

def handle_long_hex_data(line):
    data_str = line[3:].strip()
    assert len(data_str.replace(" ", "")) % 2 == 0, f'Invalid data length'
    context.result.extend(bytes.fromhex(data_str))

def handle_call_command(line):
    try:
        adr = int(line[4:], 16)
    except ValueError:
        func_name = line[4:].strip()
        adr, tags = context.commands[func_name]
        for tag in tags:
            if tag.startswith('warning'): note(tag + '\n')
    assert 0 <= adr <= context.max_call_adr, f'Invalid address: {adr}'
    adr = optimize_adr_for_npress(adr)
    process_line(f'0x{adr + 0x30300000:0{8}x}')

def handle_goto_command(line):
    label = to_lowercase(line[4:])
    process_line(f'er14 = eval(adr({label}) - 0x02)')
    process_line('call sp=er14,pop er14')

def handle_address_command(line):
    line_strip = line.strip()
    if line_strip.startswith('adr(') and line_strip.endswith(')'):
        inner_content = line_strip[4:-1].strip()
        if ',' in inner_content: raise ValueError(f"Invalid adr(...) syntax: {line}")
        label_name = inner_content
        expr = f'adr("{label_name}")'
        context.deferred_evals.append((len(context.result), expr))
        context.result.extend((0, 0))
    else:
        raise ValueError(f"Unrecognized adr command: {line}")

def handle_data_label(line):
    process_line(f'adr({line}, 0)')

def handle_builtin_command(line):
    process_line('call ' + to_lowercase(line))

def handle_assignment_command(line):
    i = line.index('=')
    left, right = line[:i].strip(), line[i+1:].strip()

    if left.startswith("var "):
        var_name = left[4:].strip()
        val = right.strip()
        # Try int (dec/hex), else string
        try:
            if val.startswith('0x') or val.startswith('0X'):
                context.vars_dict[var_name] = int(val, 16)
            else:
                context.vars_dict[var_name] = int(val)
        except ValueError:
            # Remove quotes if present
            if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                val = val[1:-1]
            context.vars_dict[var_name] = val
    elif left.startswith("reg "):
        register = left[4:].strip()
        value = right.replace(',', ';')
        process_line(f'call pop {register}')
        l1 = len(context.result)
        process_line(value)
        assert len(context.result) - l1 == sizeof_register(register), f'Line {line!r} source/destination target mismatches'
    else:
        register, value = left, right
        if register[0] in 'rexq' and any(register.startswith(prefix) for prefix in ['r', 'er', 'xr', 'qr']):
            value = value.replace(',', ';')
            process_line(f'call pop {register}')
            l1 = len(context.result)
            process_line(value)
            assert len(context.result) - l1 == sizeof_register(register), f'Line {line!r} source/destination target mismatches'
        else:
            try:
                import ast
                context.vars_dict[left] = ast.literal_eval(right)
            except:
                context.vars_dict[left] = right

def handle_variable_expansion(line):
    def expand_vars_in_line(s):
        expanded_s = s
        vars_found = re.findall(r'\{([a-zA-Z_]\w*)\}', s)
        changed = False
        for var_name in vars_found:
            if var_name not in context.vars_dict:
                raise ValueError(f"Undefined variable: {var_name}")
            var_value = context.vars_dict[var_name]
            # If the variable is a string, process as string literal (hex), else as number
            if isinstance(var_value, str):
                # Recursively expand variables inside the string value
                expanded_val = expand_vars_in_line(var_value) if '{' in var_value else var_value
                # Replace the variable in the string, then process as string literal
                expanded_s = expanded_s.replace(f'{{{var_name}}}', expanded_val)
            else:
                expanded_s = expanded_s.replace(f'{{{var_name}}}', str(var_value))
            changed = True
        if changed and '{' in expanded_s:
            return expand_vars_in_line(expanded_s)
        return expanded_s
    expanded = expand_vars_in_line(line)
    # If the result is a string literal, process as string, else as command
    if expanded == line:
        # No variable expansion, process as normal
        process_line(line)
    elif re.fullmatch(r'[\w~ ]+', expanded):
        # Only word/tilde/space: treat as string literal
        process_string_to_hex(expanded)
    else:
        process_line(expanded)

def handle_org_command(line):
    hx = eval(line[3:])
    new_home = hx - len(context.result)
    assert context.home is None or context.home == new_home, 'Inconsistent value of `home`'
    context.home = new_home

def handle_pr_length_command(line):
    context.pr_length_cmds.append(len(context.result))
    context.result.extend((0, 0))

def handle_key_constant(line):
    keyname = line.strip().upper()
    if keyname not in context.KEY_MAP:
        raise ValueError(f"Unknown key constant: {keyname}. KEY_MAP size: {len(context.KEY_MAP)}")
    value = context.KEY_MAP[keyname]
    new_bytes_list = []
    if isinstance(value, str):
        for part in value.split(','):
            part = part.strip()
            new_bytes_list.append(int(part, 0) & 0xFF)
    elif isinstance(value, (list, tuple)):
        new_bytes_list = [int(x) & 0xFF for x in value]
    else:
        raise ValueError(f"Invalid KEY_MAP entry for {keyname}: {value!r}")
    context.result.extend(new_bytes_list)

def process_string_to_hex(text):
    processed_text = text.replace(" ", "~")
    for c in processed_text:
        if c in consts.char_to_hex:
            hx = consts.char_to_hex[c]
            if len(hx) == 2:
                context.result.append(int(hx, 16))
            elif len(hx) == 4:
                context.result.extend([int(hx[:2], 16), int(hx[2:], 16)])
        else:
            context.result.append(ord(c))

def handle_any_string_command(line):
    line_strip = line.strip()
    match = re.search(r'"(.*)"', line_strip)
    if not match:
        return
    content = match.group(1)
    # Replace {var} with value from context.vars_dict
    def replace_var(m):
        var_name = m.group(1)
        if var_name in context.vars_dict:
            return str(context.vars_dict[var_name])
        else:
            raise ValueError(f"Undefined variable: {var_name}")
    content = re.sub(r'\{([a-zA-Z_]\w*)\}', replace_var, content)
    process_string_to_hex(content)

def dispatch_command_handler(line, program_iter=None, defined_functions=None):
    line_strip = line.strip()
    if line.strip().lower().startswith('lbl '):
        handle_label_definition(line)
    elif line_strip.startswith("func "):
        if program_iter is None or defined_functions is None:
            raise ValueError("Function handling requires program_iter and defined_functions")
        handle_function_definition(line, program_iter, defined_functions)
    elif line.startswith('0x'): handle_hex_data(line)
    elif line.startswith('eval(') and line.endswith(')'): handle_eval_expression(line)
    elif line.startswith('hex') and 'hex_' not in line: handle_long_hex_data(line)
    elif line.startswith('call'): handle_call_command(line)
    elif line.startswith('goto'): handle_goto_command(line)
    elif line.startswith('adr'): handle_address_command(line)
    elif line in context.datalabels: handle_data_label(line)
    elif line in context.commands: handle_builtin_command(line)
    elif '=' in line: handle_assignment_command(line)
    elif '{' in line and '}' in line: handle_variable_expansion(line)
    elif line.startswith('org'): handle_org_command(line)
    elif line.startswith('pr_length'): handle_pr_length_command(line)
    elif line.strip().upper().startswith('KEY_'): handle_key_constant(line)
    elif line_strip.startswith('f"') or line_strip.startswith('"'): handle_any_string_command(line_strip)
    else:
        assert False, f'Unrecognized command: {line!r}'

def process_line(line):
    global in_comment
    line = line.split('---')[0].strip()
    if not line or line.isspace(): return
    if line.startswith('/*'):
        in_comment = True
        return
    if '*/' in line:
        in_comment = False
        return
    if in_comment: return

    if ';' in line:
        for command in line.split(';'):
            cmd = command
            # Only lowercase if not a string literal
            if not cmd.strip().startswith('"'):
                cmd = to_lowercase(cmd)
            process_line(cmd)
    else:
        dispatch_command_handler(line)

def finalize_processing():
    for pos, left_offset, left_label, right_offset, right_label, op in context.relocation_expressions:
        if left_label not in context.labels or right_label not in context.labels:
            raise ValueError(f'Label not found in adr: {left_label}, {right_label}')
        left_addr = context.labels[left_label] + left_offset
        right_addr = context.labels[right_label] + right_offset
        result_addr = (left_addr + right_addr) & 0xFFFF if op == '+' else (left_addr - right_addr) & 0xFFFF
        if context.result[pos] != 0 or context.result[pos+1] != 0:
             print(f"[WARN] adr overwrite at {pos:04X}")
        context.result[pos] = result_addr & 0xFF
        context.result[pos + 1] = (result_addr >> 8) & 0xFF

    for pos in context.pr_length_cmds:
        pr_length = len(context.result)
        if context.result[pos] != 0 or context.result[pos+1] != 0:
            print(f"[WARN] pr_length overwrite at {pos:04X}")
        context.result[pos] = pr_length & 0xFF
        context.result[pos + 1] = (pr_length >> 8) & 0xFF

    context.relocation_expressions.clear()
    context.pr_length_cmds.clear()

def process_program(args, program_lines, overflow_initial_sp):
    # Reset State
    context.result = []
    context.labels = {}
    context.address_requests = []
    context.relocation_expressions = []
    context.pr_length_cmds = []
    context.deferred_evals = []
    context.home = None
    context.string_vars = {}
    context.vars_dict = {}
    global in_comment
    in_comment = False
    
    final_lines_to_process = []
    defined_functions = {}

    # Track original file line numbers for accurate debug
    orig_line_map = []
    for idx, raw_line in enumerate(program_lines):
        orig_line_map.append(idx + 1)  # 1-based line number

    program_iter = iter(enumerate(program_lines))
    for line_index, raw_line in program_iter:
        line = canonicalize(del_inline_comment(raw_line))

        if line.strip().startswith("func "):
            handle_function_definition(line, program_iter, defined_functions)
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
        line = item["exec"]
        raw_origin = item["raw"]
        line_num = item["num"]
        context_str = item.get("ctx", "")
        
        line_strip = canonicalize(del_inline_comment(line))
        # Do not lowercase string literals
        if line_strip.startswith('"'):
            line_to_process = line_strip
        else:
            line_to_process = to_lowercase(line_strip)
        if not line_to_process:
            continue

        old_len_result = len(context.result)
        try:
            process_line(line_to_process)
        except Exception as e:
            print(f"\nTraceback (most recent call last):")
            print(f"  Line {line_num} {context_str}: {raw_origin.strip()}")
            print(f"CompilerError: {str(e)}")
            # VS Code: try to open file and go to line
            import os
            import sys
            # If running in VS Code and file is known, open it at the error line
            if hasattr(args, 'source_file') and os.path.exists(args.source_file):
                # Print VS Code URI for quick jump
                print(f"::open::{args.source_file}:{line_num}")
            sys.exit(1)

        if args.format == 'key' and any(x != 0 and get_npress(x) > 100 for x in context.result[old_len_result:]):
             note(f'Line generates many keypresses\n')

    # Deferred Eval Handling
    eval_scope = context.vars_dict.copy()
    for k, v in context.vars_dict.items():
        if isinstance(v, list): eval_scope[k] = int.from_bytes(bytes(v), 'little')
    for label_name in context.labels.keys():
         if label_name not in eval_scope: eval_scope[label_name] = label_name

    def adr_eval(label, offset=0):
        if not isinstance(label, str): raise ValueError(f"Label must be string")
        if label not in context.labels: raise ValueError(f'Label not found: {label}')
        return (context.labels[label] + offset)
    eval_scope['adr'] = adr_eval

    home_dependent_evals = [] 
    for pos, expr in context.deferred_evals:
        try:
            val = eval(expr, {}, eval_scope)
        except Exception:
            # Retry with expanded scope logic if needed (simplified here)
            temp_scope = eval_scope.copy()
            val = eval(expr, {}, temp_scope)
        
        if not isinstance(val, int): raise ValueError("Deferred eval not int")
        
        if expr.count('adr(') > 1: # Absolute
             val = val & 0xFFFF
             context.result[pos], context.result[pos+1] = val & 0xFF, (val >> 8) & 0xFF
        else:
             home_dependent_evals.append((pos, val))
            
    finalize_processing()
    
    resolved_adr_cmds = []
    for source_adr, offset, target_label in context.address_requests:
        if target_label not in context.labels: raise ValueError(f'Label not found: {target_label}')
        resolved_adr_cmds.append((source_adr, context.labels[target_label] + offset))
    context.address_requests.clear()

    # Target Logic
    if args.target == 'overflow':
        assert len(context.result) <= 100, 'Program too long'
        if context.home is None:
            context.home = overflow_initial_sp
            if 'home' in context.labels: context.home -= context.labels['home']
            # Simple heuristic for home finding (simplified from original)
            context.home = overflow_initial_sp # Default fallback

    elif args.target == 'loader':
        if context.home is None:
            context.home = 0x85b0 - len(context.result)
            entry = context.home + context.labels.get('home', 0) - 2
            context.result.extend((0x6a, 0x4f, 0, 0, entry & 255, entry >> 8, 0x68, 0x4f, 0, 0))
            while context.home + len(context.result) < 0x85d7: context.result.append(0)
            context.result.extend((0xff, 0xae, 0x85))
            home2 = 0
            while get_npress_adr(context.home - home2) >= 100: home2 += 1
            # Note: Logic assumes home2 usage for loader output

    # Write unresolved addresses
    assert context.home is not None
    for source_adr, home_offset in resolved_adr_cmds + home_dependent_evals:
        target_adr = context.home + home_offset
        context.result[source_adr] = target_adr & 0xFF
        context.result[source_adr + 1] = target_adr >> 8

    # Output
    if args.target == 'overflow':
        hackstring = list(map(ord, '1234567890' * 10))
        for home_offset, byte in enumerate(context.result):
            hackstring_pos = (context.home + home_offset - 0x8154) % 100
            hackstring[hackstring_pos] = byte
        if args.format == 'hex': print(''.join(f'{byte:0{2}x}' for byte in hackstring))
        elif args.format == 'key': print(' '.join(byte_to_key(x) for x in hackstring))

    elif args.target == 'none':
        if args.format == 'hex': print('0x%04x:' % context.home, *map('%02x'.__mod__, context.result))
        elif args.format == 'key': print(f'{context.home:#06x}:', ' '.join(byte_to_key(byte) for byte in context.result))
        
    elif args.target == 'loader' and args.format == 'key':
        print('Address to load: %s %s' % (byte_to_key((context.home - home2) & 255), byte_to_key((context.home - home2) >> 8)))
        # Assuming keypairs module exists or logic handled elsewhere
        print(f"Loader key sequence generated (len {len(context.result)})")