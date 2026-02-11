org 0xe9e0

lbl start
    "hello"
    hex 00 00
    eval(adr(start) - 0x2)
    hex 00 00
    pr_length
    hex 00 00
    var a = 0x1
    var b = 0x2
    var c = eval(a + b)
    "n {c}"
    KEY_SHIFT