# -*- coding: utf-8 -*-
import os, re, random, string

GLOBAL_ENV = {}

def load_extensions(path):
    """ Load extensions from file """
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


def match_extension(line, ext):
    """ Return match object if line matches extension syntax """
    pattern = re.escape(ext["syntax"])
    pattern = re.sub(r'\\\{(\w+)\\\}', r'(?P<\1>.+?)', pattern)
    return re.fullmatch(pattern, line.strip())


def expand_extensions_in_program(program_lines, extensions):
    """ Expand program using loaded extensions """
    expanded = []

    for line in program_lines:
        line = line.split('---')[0].strip()
        if not line:
            continue

        current_line = line
        matched_full = False

        for ext in sorted(extensions, key=lambda x: len(x["syntax"]), reverse=True):
            match = match_extension(current_line, ext)
            for line in program_lines:
                line = line.split('---')[0].strip()
                if not line:
                    continue

                current_line = line
                matched_full = False

                for ext in sorted(extensions, key=lambda x: len(x["syntax"]), reverse=True):
                    match = match_extension(current_line, ext)
                    is_inline = False

                    if not match:
                        match = re.search(
                            re.escape(ext["syntax"]).replace(r"\{", "(?P<").replace(r"\}", ">.+?)"),
                            current_line
                        )
                        is_inline = True

                    if match:
                        local_env = match.groupdict()
                        # Execute extension logic with shared GLOBAL_ENV
                        if ext.get("logic"):
                            try:
                                env = GLOBAL_ENV
                                env.update(local_env)
                                env.update({"random": random, "string": string, "re": re})
                                exec(ext["logic"], env, env)
                                local_env.update(env)
                            except Exception as e:
                                print(f"[ERROR] extension logic: {e}")

                        # Prepare output
                        output_lines = []
                        merged_env = {}
                        merged_env.update(GLOBAL_ENV)
                        merged_env.update(local_env)

                        for out in ext["output"]:
                            temp = out
                            for k, v in merged_env.items():
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
