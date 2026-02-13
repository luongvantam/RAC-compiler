
import re

# Mocks
vars_dict = {'N': 5}
PYTHON_FUNCTIONS = {}
class PyNamespace:
    def __init__(self, functions): pass

def process_line(line, program_iter=None):
    print(f"Processed: {line}")
    if line.startswith("repeat"):
         handle_repeat_command(line, program_iter)

def handle_repeat_command(line, program_iter):
    print(f"DEBUG: handle_repeat_command called with '{line}'")
    m = re.match(r'repeat\s+(.+?)\s*\{', line.strip())
    if not m:
        raise ValueError(f"Invalid repeat syntax: {line}")
    
    count_expr = m.group(1).strip()
    try:
        # Evaluate expr using vars_dict
        eval_scope = vars_dict.copy()
        # eval_scope['py'] = PyNamespace(PYTHON_FUNCTIONS)
        count = eval(count_expr, {}, eval_scope) # simplified eval for test
        if not isinstance(count, int):
             raise ValueError(f"Repeat count must evaluate to int, got {type(count)}")
    except Exception as e:
        raise ValueError(f"Error evaluating repeat count '{count_expr}': {e}")
    
    # Collect lines until matching }
    body_items = []
    depth = 1
    
    if program_iter is None: 
         raise ValueError("repeat command requires an iterator")

    for item in program_iter:
        # Determine content type
        if isinstance(item, tuple) and len(item) == 2: # enumerate
             _, raw_line = item
             content = raw_line
        elif isinstance(item, dict):
             content = item["exec"]
        elif isinstance(item, str):
             content = item
        else:
             content = str(item)

        content_strip = content.split('---')[0].strip()
        if not content_strip:
            continue
        
        open_count = content_strip.count('{')
        close_count = content_strip.count('}')
        
        if content_strip == '}':
            depth -= 1
            if depth <= 0:
                break
            body_items.append(item)
            continue
        
        depth += open_count - close_count
        body_items.append(item)
    
    # Process the body lines 'count' times
    for i in range(count):
        # Create a fresh iterator for the body for each repetition
        body_iter = iter(body_items)
        for item in body_iter:
            if isinstance(item, tuple) and len(item) == 2:
                _, raw_line = item
                line_to_proc = raw_line
            elif isinstance(item, dict):
                line_to_proc = item["exec"]
            elif isinstance(item, str):
                line_to_proc = item
            else:
                line_to_proc = str(item)
            
            process_line(line_to_proc, body_iter)

print("Testing 'repeat 2 {'")
lines = ["  line 1", "}"]
try:
    process_line("repeat 2 {", iter(lines))
    print("Success 1")
except Exception as e:
    print(f"Failed 1: {e}")

print("\nTesting 'repeat N+1 {'")
lines = ["  line 2", "}"]
try:
    process_line("repeat N+1 {", iter(lines))
    print("Success 2")
except Exception as e:
    print(f"Failed 2: {e}")

print("\nTesting nested repeat 'repeat 2 { repeat 2 { ... } }'")
lines = ["  repeat 2 {", "    line nested", "  }", "}"]
try:
    process_line("repeat 2 {", iter(lines))
    print("Success 3")
except Exception as e:
    print(f"Failed 3: {e}")
