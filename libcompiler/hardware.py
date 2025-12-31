# -*- coding: utf-8 -*-
from functools import lru_cache
from . import context

def set_font(font_):
    context.font = font_
    context.font_assoc = dict((c, i) for i, c in enumerate(context.font))

def from_font(st):
    return [context.font_assoc[char] for char in st]

def to_font(charcodes):
    return ''.join(context.font[charcode] for charcode in charcodes)

def set_npress_array(npress_):
    context.npress = npress_

def set_symbolrepr(symbolrepr_):
    context.symbolrepr = symbolrepr_

@lru_cache(maxsize=256)
def byte_to_key(byte):
    if byte == 0:
        return '<NUL>'

    # TODO hack for classwiz without unstable
    try:
        sym = context.symbolrepr[byte]
    except IndexError:
        return f'<{byte:02x}>' # Fallback

    return f'<{byte:02x}>' if sym in ('@', '') else sym
    
    # Original logic preserved but commented out in source was:
    # offset = 0
    # sym = context.symbolrepr[byte]
    # ... logic ...

def get_npress(charcodes):
    if isinstance(charcodes, int):
        charcodes = (charcodes,)
    return sum(context.npress[charcode] for charcode in charcodes)

def get_npress_adr(adrs):
    if isinstance(adrs, int):
        adrs = (adrs,)
    assert all(0 <= adr <= context.max_call_adr for adr in adrs)
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