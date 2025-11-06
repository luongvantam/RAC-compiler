# RAC Compiler — Usage Guide

### **Syntax Overview**

#### **Comments**
```text
# Single-line comment
/* Multi-line
   comment block */
```

#### **Org Directive**
Set the base code mapping address:
```text
org <expr>
```

#### **Labels**
Define a label for jumps or references:
```text
lbl label
```

#### **Hexadecimal Data**
Insert raw hexadecimal data:
```text
0x<hex_digits>
hex <hex_digits>
```

#### **Calls**
Call an address or built-in function:
```text
call <address>
call <builtin>
```

#### **Goto**
Jump to a specific label:
```text
goto <label>
```

#### **Address Of**
Get the address of a label (with optional offset):
```text
adr(<label>)
```

#### **Register Assignment**
Assign values to registers:
```text
register = <value> [, adr(<label>)] [, ...]
xr0 = 0x1234, 0x4321
```

#### **Program Length**
Trigger program length calculation:
```text
pr_length
```

#### **String Handling**
Define or use text strings:
```text
str "<string>"
```

#### **Function Definition**
Define reusable code blocks:
```text
func function_name(<type_var><var>, <type_var2><var2>):
  {var2}
  {var1}
  xr0 = 0x30303030
```

Call the function:
```text
function_name(<value_var>,<value_var2>)
```

Parameters are replaced inline when called.
#### **Eval**
Evaluate a math or address expression:

```text
eval(<expression>)
```

#### **Define**
Define constants, strings, gadgets, or registers:
```text
int <name> = <value>
str <name_str> = <string>
rel <name_gadget> = <gadget>
reg [r/er/xr/qr] = <value>
[r/er/xr/qr] = <value>
```

#### **Compound Statements**
Combine multiple statements in one line:
```text
call 0x1234 ; goto label
```

---

## **Examples**

### **Example 1 — Simple Program**
```text
home:
  0x1234
  call 0x56789
  goto end
end:
```

### **Example 2 — Labels & Address Of**
```text
start:
  adr(label1)
  goto label1
label1:
  0x9ABC
```

### **Example 3 — String Handling**
```text
str var "Hello, World!"
str var
str "Goodbye, World!"
```

### **Example 4 — Eval**
```text
eval(adr(loop1) - adr(loop2))
eval({a} + {b})
eval("hello" * 3)
```

---

## **Key Mapping**
Syntax:
```text
KEY_<NAME>
```

Example:
```text
KEY_SHIFT
KEY_ALPHA
```

Please read and learn at `compiler_.py`

---

##### Written by: **luongvantam**