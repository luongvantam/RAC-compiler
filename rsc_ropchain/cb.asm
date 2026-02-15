org 0xd730
display:
    setlr_pc
    setsfr
    di,rt
brk:
    xr0 = hex 0a f0 03 00
    [er0]=r2
home:
counter:
    er2 = 0x0001
    er8 = adr_of [+4784] counter_adr
    [er8]+=er2,pop xr8
    adr_of [+4784] counter_adr
    0x3030
    er0 = er8
    r0 = [er0]
    setlr_pc
    r1 = 0,rt
    ea = adr_of counter_table
    cmp_ea
    er6 = [ea]
    sp = er6, pop er8
next:
    xr0 = adr_of [+4784] counter_adr, 0x0000
    [er0]=r2
print:
    buffer_clear
    xr0 = 0x010a, adr_of text_1
    smallprint
    xr0 = 0x110a, adr_of [+4784] text_pass
    smallprint
    render.ddd4
key_num:
    er0 = adr_of keycode
    getkey
check_if_press:
    pop er0
keycode:
    0x0000
    er2 =0x0001
    setlr_pc
    er0-=er2,rt
    ea = adr_of uia_table
    cmp_ea
    er6 = [ea]
    sp = er6,pop er8
key:
    xr0 = adr_of keycode, 0x83da
    cvt_key
check_num_key:
    er2 = adr_of cvt_keycode
    setlr_pc
    [er2]=er0,r2=0,pop er4,rt
    0x3030
    er0 = adr_of cvt_keycode
    r0 = [er0]
    r1 = 0,rt
    ea = adr_of num_key_table
    cmp_ea
    sp = er6, pop er8
cursor_pos:
    er0 = adr_of cvt_keycode
    r0 = [er0]
	r2 = r0,pop er0
	adr_of [+4784] text_pass
	[er0]=r2
cursor_increase:
    er4 = adr_of [+4788] cursor_pos
    setlr_pc
    [er4]+=1,rt
checking_typing_done:
    er2 = adr_of [+4788] cursor_pos
    er0 = [er2],r2 = 9,rt
    ea = adr_of table
    cmp_ea
    er6 = [ea]
    sp = er6, pop er8
checking_password_f2n:
    er2 = adr_of [+4784] text_pass
    setlr_pc
    er0 = [er2],r2 = 9,rt
    ea = adr_of password_1
    cmp_ea
    er6 = [ea]
    sp = er6, pop er8
checking_password_s2n:
    er2 = adr_of [+4786] text_pass
    setlr_pc
    er0 = [er2],r2 = 9,rt
    ea = adr_of password_2
    cmp_ea
    er6 = [ea]
    sp = er6, pop er8
if_true:
    xr0 = hex 0a f0 01 00
    [er0]=r2
    xr0 = 0x110a, adr_of [+4784] text_pass
    smallprint
    xr0 = 0x210a, adr_of true_text
    render.ddd4
    brk
if_false:
    xr0 = adr_of [+4784] text_pass, 0x0010
    memzero
    xr0 = 0x110a, adr_of [+4784] text_pass
    smallprint
    xr0 = 0x210a, adr_of false_text
    smallprint
    render.ddd4
    xr0 = adr_of [+4788] cursor_pos, adr_of [+4784] text_pass
    setlr_pc
    [er0]=er2,rt
loop:
    xr0 = adr_of segment, 0x0001
    setlr_pc
    [er0]=er2,rt
    qr0 = pr_length, adr_of [+4784] home, adr_of home, adr_of [-2] home
    hex 32 89
segment:
    adr_arith end - adr_arith segment
    0x000000
    sp = er6, pop er8
uia_table:
    0xffff
    adr_of [-2] loop
    0x0000
    adr_of [-2] key
password_1:
    hex 31 32
    adr_of [-2] checking_password_s2n
    hex 00 00
    adr_of [-2] if_false
password_2:
    hex 33 34
    adr_of [-2] if_true
    hex 00 00
    adr_of [-2] if_false
table:
    adr_of [+4788] text_pass
    adr_of [-2] checking_password_f2n
    0x0000
    adr_of [-2] loop
counter_table:
    hex 04 00
    adr_of [-2] next
    hex 00 00
    adr_of [-2] loop
num_key_table:
    hex 30 00
    adr_of [-2] cursor_pos
    hex 31 00
    adr_of [-2] cursor_pos
    hex 32 00
    adr_of [-2] cursor_pos
    hex 33 00
    adr_of [-2] cursor_pos
    hex 34 00
    adr_of [-2] cursor_pos
    hex 35 00
    adr_of [-2] cursor_pos
    hex 36 00
    adr_of [-2] cursor_pos
    hex 37 00
    adr_of [-2] cursor_pos
    hex 38 00
    adr_of [-2] cursor_pos
    hex 39 00
    adr_of [-2] cursor_pos
    hex 00 00
    adr_of [-2] loop
counter_adr:
    0x0000
cvt_keycode:
    0x0000
text_1:
    str "Enter~your~password:"
    0X00
false_text:
    str "Password~is~incorrect."
    0x00
true_text:
    str "Password~is~correct."
    0x0000
end:
text_pass: