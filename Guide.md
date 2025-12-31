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
hex <hex_digits_reversed>
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

#### **Program Length**
Trigger program length calculation:
```text
pr_length
```

#### **String Handling**
Define or use text strings:
```text
"<string>"
f"<string and %cmd%>"
```

#### **Function Definition**
Define reusable code blocks:
```text
func function_name(<var>, <var2>):
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
Define variables or registers:
```text
var <var_name> = <value>
reg <reg> = <value>
<reg/var name> = <value>
```
reg is Rn, ERn, XRn, QRn, where n is any number.

#### **Compound Statements**
Combine multiple statements in one line:
```text
call 0x1234 ; goto label
```

#### **Key Mapping**
Syntax:
```text
KEY_<NAME>
```
Key map for fx580vnx:
```
KEY_SHIFT   8001
KEY_ALPHA   8002
KEY_MENU    8010
KEY_UP      8004
KEY_DOWN    4008
KEY_LEFT    4004
KEY_RIGHT   8008
KEY_OPTN    4001
KEY_CALC    4002
KEY_INTG    4010
KEY_X       4020
KEY_FRAC    2001
KEY_SQRT    2002
KEY_SQR     2004
KEY_POWER   2008
KEY_LOGB    2010
KEY_INX     2020
KEY_NEG     1001
KEY_DEG     1002
KEY_INV     1004
KEY_SIN     1008
KEY_COS     1010
KEY_TAN     1020
KEY_STO     0801
KEY_ENG     0802
KEY_LPAR    0804
KEY_RPAR    0808
KEY_STD     0810
KEY_ADDM    0820
KEY_0       1040
KEY_1       0101
KEY_2       0102
KEY_3       0104
KEY_4       0201
KEY_5       0202
KEY_6       0204
KEY_7       0401
KEY_8       0402
KEY_9       0404
KEY_DOT     0840
KEY_DEL     0408
KEY_AC      0410
KEY_EXE     0140
KEY_ANS     0240
KEY_EXP     0440
KEY_ADD     0108
KEY_SUB     0110
KEY_MUL     0208
KEY_DIV     0210
```

---

## **Examples**

### **Example 1 — Simple Program**
```text
lbl home
  0x1234
  call 0x56789
  goto end
lbl end
```

### **Example 2 — Labels & Address Of**
```text
lbl start
  adr(label1)
  goto label1
lbl label1
  0x9ABC    # or `hex BC 9A`
```

### **Example 3 — String Handling**
```text
"Hello~World!"
var name = "Nguyen Van A"
f"Hello~%{name}%.How~are~you?"
```

### **Example 4 — Eval**
```text
eval(adr(loop1) - adr(loop2))
eval({a} + {b})
eval("hello" * 3)
```

---

##### Written by: **luongvantam**