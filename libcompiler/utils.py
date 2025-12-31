# -*- coding: utf-8 -*-
import sys, re

def note(st):
    ''' Print st to stderr. Used for additional information (note, warning) '''
    sys.stderr.write(st)

def to_lowercase(s):
    return s.lower()

def canonicalize(st):
    ''' Make (st) canonical. '''
    #st = st.lower()
    st = st.strip()
    # remove spaces around non alphanumeric
    st = re.sub(r' *([^a-z0-9]) *', r'\1', st)
    return st

def del_inline_comment(line):
    return (line + '#')[:line.find('#')].rstrip()