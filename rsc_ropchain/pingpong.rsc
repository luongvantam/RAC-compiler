org 0xd730

lbl start
    setlr
    setsfr
    di,rt
    clear()

lbl set_paddle
    pop xr0
    lbl position_paddle
        hex 0a 18
    adr(text_paddle)
    smallprint

lbl set_ball
    xr0 = 0x60, 0x1f, adr(text_ball)
    line_print
    render.ddd4

lbl get_key
    er0 = adr(key)
    getkey
    xr12 = eval(adr(table) - 0xa), eval(adr(table) - 0xa)
    setlr
    call 17CA6
    pop er0
    lbl key
        hex 00 00
    call 09C20
    call 1C64A
    sp = er6, pop er8

lbl paddle_up
    er4 = eval(adr(position_paddle) + 0x12b1)
    [er4] += 1,rt
    er6 = eval(adr(loop_ball)-0x2)
    sp = er6, pop er8

lbl paddle_down
    er4 = eval(adr(position_paddle) + 0x12b1)
    [er4] -= 1,rt

lbl loop_ball
    # idk... =)))

lbl restore
    xr0 = 0xd184d630
    BL strcpy
    er14 = 0xd62e
    sp = er14,pop er14
    hex 00 00

lbl table
    KEY_UP
    eval(adr(paddle_up) - 0x2)
    KEY_DOWN
    eval(adr(paddle_down) - 0x2)
    hex 00 00
    eval(adr(loop_ball) - 0x2)

lbl text_ball
    hex 40 00

lbl text_paddle
    hex 20 7c 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 7c 00 00