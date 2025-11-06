# -*- coding: utf-8 -*-
import sys, os, itertools, argparse

BASE_DIR = os.path.dirname(__file__)
os.chdir(BASE_DIR)
sys.path.append('..')

import libcompiler
from libcompiler import (
    set_font, set_npress_array, get_disassembly, get_commands,
    read_rename_list, set_symbolrepr, get_rom,
    optimize_gadget, find_equivalent_addresses,
    print_addresses, process_program,
    load_extensions, expand_extensions_in_program
)

# Load ROM & metadata
get_rom('rom.bin')
get_disassembly('disas.txt')
get_commands('gadgets.txt')
for fname in ('labels.txt', '../labels_sfr.txt'):
    read_rename_list(fname)
extensions = load_extensions("../extensions.txt")

# key map
libcompiler.KEY_MAP  = {
    "KEY_SHIFT": "0x80, 0x01",
    "KEY_ALPHA": "0x80, 0x02",
    "KEY_MENU": "0x80, 0x10",
    "KEY_UP": "0x80, 0x04",
    "KEY_DOWN": "0x40, 0x08",
    "KEY_LEFT": "0x40, 0x04",
    "KEY_RIGHT": "0x80, 0x08",
    "KEY_OPTN": "0x40, 0x01",
    "KEY_CALC": "0x40, 0x02",
    "KEY_INTG": "0x40, 0x10",
    "KEY_X": "0x40, 0x20",        # Biến x
    "KEY_FRAC": "0x20, 0x01",
    "KEY_SQRT": "0x20, 0x02",
    "KEY_SQR": "0x20, 0x04",
    "KEY_POWER": "0x20, 0x08",      # Mũ (^)
    "KEY_LOGB": "0x20, 0x10",
    "KEY_INX": "0x20, 0x20",      # ln()
    "KEY_NEG": "0x10, 0x01",      # Dấu âm (-)
    "KEY_DEG": "0x10, 0x02",      # Độ/phút/giây
    "KEY_INV": "0x10, 0x04",      # Nghịch đảo (x^-1)
    "KEY_SIN": "0x10, 0x08",
    "KEY_COS": "0x10, 0x10",
    "KEY_TAN": "0x10, 0x20",
    "KEY_STO": "0x08, 0x01",
    "KEY_ENG": "0x08, 0x02",
    "KEY_LPAR": "0x08, 0x04",     # Mở ngoặc
    "KEY_RPAR": "0x08, 0x08",     # Đóng ngoặc
    "KEY_STD": "0x08, 0x10",      # S<>D
    "KEY_ADDM": "0x08, 0x20",     # M+
    "KEY_0": "0x10, 0x40",
    "KEY_1": "0x01, 0x01",
    "KEY_2": "0x01, 0x02",
    "KEY_3": "0x01, 0x04",
    "KEY_4": "0x02, 0x01",
    "KEY_5": "0x02, 0x02",
    "KEY_6": "0x02, 0x04",
    "KEY_7": "0x04, 0x01",
    "KEY_8": "0x04, 0x02",
    "KEY_9": "0x04, 0x04",
    "KEY_DOT": "0x08, 0x40",      # Dấu thập phân (.)
    "KEY_DEL": "0x04, 0x08",
    "KEY_AC": "0x04, 0x10",
    "KEY_EXE": "0x01, 0x40",      # Phím '=' (giờ là phím EXE)
    "KEY_ANS": "0x02, 0x40",
    "KEY_EXP": "0x04, 0x40",      # *10^x (giờ là KEY_EXP)
    "KEY_ADD": "0x01, 0x08",
    "KEY_SUB": "0x01, 0x10",
    "KEY_MUL": "0x02, 0x08",
    "KEY_DIV": "0x02, 0x10",
}

# char_to_hex
libcompiler.char_to_hex = dict(zip(
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

# font table
FONT=[l.split('\t') for l in '''
															
𝒙	𝒚	𝒛	⋯	▲	▼	▸	 ˍ	$	◁	&	𝑡	ᴛ	ₜ	ₕ	₅
 	!	"	#	×	%	÷	'	(	)	⋅	+	,	—	.	/
0	1	2	3	4	5	6	7	8	9	:	;	<	=	>	?
@	A	B	C	D	E	F	G	H	I	J	K	L	M	N	O
P	Q	R	S	T	U	V	W	X	Y	Z	[	▫	]	^	_
-	a	b	c	d	e	f	g	h	i	j	k	l	m	n	o
p	q	r	s	t	u	v	w	x	y	z	{	|	}	~	⊢
𝐢	𝐞	x	⏨	∞	°	ʳ	ᵍ	∠	x̅	y̅	x̂	ŷ	→	∏	⇒
ₓ	⏨	⏨̄	⌟	≤	≠	≥	⇩	√	∫	ᴀ	ʙ	ᴄ	ₙ	▶	◀	
⁰	¹	²	³	⁴	⁵	⁶	⁷	⁸	⁹	⁻¹	ˣ	¹⁰	₍	₎	±	
₀	₁	₂	₋₁	ꜰ	ɴ	ᴘ	µ	𝐀	𝐁	𝐂	𝐃	𝐄	𝐅	𝐏	▷	
Σ	α	γ	ε	θ	λ	μ	π	σ	ϕ	ℓ	ℏ	█	⎕	₃	▂
𝐟	𝐩	𝐧	𝛍	𝐦	𝐤	𝐌	𝐆	𝐓	𝐏	𝐄	𝑭	ₚ	ₑ	ᴊ	ᴋ
τ	ᵤ	₉	Å	ₘ	ɪ	₄									
															
'''.strip('\n').split('\n')]

assert len(FONT) == 16  # TODO wrong
assert all(len(l) >= 16 for l in FONT)
FONT = [*itertools.chain.from_iterable(l[:16] for l in FONT)]
set_font(FONT)

# npress mapping
NPRESS = (
    99,24,24,24,24,24,24,24,24,24,24,24,24,24,24,24,
    24,24,24,24,24,24,24,24,30,24,24,24,24,24,24,24,
    24,2 ,2 ,2 ,24,24,24,24,24,24,24,24,2 ,1 ,1 ,24,
    1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,24,24,24,24,24,24,
    2 ,1 ,2 ,2 ,2 ,2 ,2 ,2 ,1 ,2 ,2 ,2 ,24,24,24,24,
    2 ,1 ,2 ,2 ,24,24,24,24,24,24,24,24,24,24,24,49,
    1 ,49,49,49,49,49,49,49,2 ,2 ,49,49,3 ,3 ,3 ,3 ,
    3 ,3 ,2 ,2 ,1 ,1 ,2 ,1 ,1 ,1 ,2 ,2 ,2 ,1 ,2 ,2 ,
    49,49,49,2 ,2 ,49,49,2 ,2 ,2 ,49,49,49,49,49,49,
    49,49,49,49,49,49,49,49,49,49,49,49,49,49,49,49,
    49,49,49,49,49,2 ,1 ,1 ,1 ,1 ,2 ,49,49,2 ,2 ,49,
    49,49,49,49,49,49,49,49,49,49,49,49,49,49,49,49,
    1 ,49,49,49,49,49,49,49,1 ,1 ,2 ,49,49,49,49,49,
    1 ,49,49,49,1 ,1 ,2 ,2 ,2 ,3 ,3 ,3 ,1 ,3 ,3 ,3 ,
    3 ,3 ,3 ,3 ,3 ,3 ,3 ,3 ,49,49,49,49,49,49,49,49,
    49,49,49,49,49,49,49,49,49,49,49,49,49,49,49,49,
)
set_npress_array(NPRESS)

# get_char_table
LOOKUP = {
    0x00:(0x2432,0x2612),
    0xfa:(0x2360,0x23E2),
    0xfe:(0x2092,0x2270),
    0xfd:(0x1F72,0x2032),
    0xfb:(0x1E82,0x1F22),
}

ROMWINDOW = 0xd000
with open('rom.bin','rb') as f:
    ROM = f.read()

def fetch(addr):
    assert addr % 2 == 0
    return ROM[addr] | (ROM[addr+1] << 8)

def get_symbol(x):
    low, high = x & 0xff, x >> 8
    if low == 0: return 0, b''
    er2, er4 = LOOKUP.get(high, (None, None))
    if er2 is None: return 0, b''

    er2 = fetch(er2 + low*2)
    r0 = ROM[er4 + low]
    r4 = r0 >> 4
    r0 &= 0xF
    if r0 == 0: return 0, b''

    if r4 != 15: er2 += r4
    result = bytearray()
    count = r0
    while count > 0 and er2 < ROMWINDOW:
        val = ROM[er2]
        result.append(val)
        er2 = (er2 + 1) & 0xFFFF
        if val < 4 or val >= 0xF0: continue
        count -= 1

    if r4 == 15:
        result.append(ord('('))
        r0 += 1
    return r0, bytes(result)

# symbol repr from get_symbol
symbols = [''.join(FONT[b] for b in get_symbol(x)[1]) for x in range(0xf0)] + ['@']*0x10
set_symbolrepr(symbols)

# argparse interface
parser = argparse.ArgumentParser()
parser.add_argument('-t','--target', default='none', choices=('none',))
parser.add_argument('-f','--format', default='key', choices=('hex','key'))
parser.add_argument('-g','--gadget-adr', type=lambda x:int(x,0))
parser.add_argument('-gb','--gadget-bin')
parser.add_argument('-gn','--gadget-nword', type=lambda x:int(x,0), default=0)
parser.add_argument('-p','--preview-count', type=lambda x:int(x,0), default=0)
args = parser.parse_args()

# main logic
if args.gadget_bin:
    print_addresses(optimize_gadget(bytes.fromhex(args.gadget_bin)), args.preview_count)
elif args.gadget_nword > 0:
    print_addresses(optimize_gadget(libcompiler.rom[args.gadget_adr:args.gadget_adr+args.gadget_nword*2]), args.preview_count)
elif args.gadget_adr is not None:
    print_addresses(find_equivalent_addresses(libcompiler.rom, {args.gadget_adr}), args.preview_count)
else:
    program = expand_extensions_in_program(sys.stdin.read().splitlines(), extensions)
    process_program(args, program, overflow_initial_sp=0xE9E0)
