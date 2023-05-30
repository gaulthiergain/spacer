# SPDX-License-Identifier: BSD-3-Clause
#
# Authors: Gaulthier Gain <gaulthier.gain@uliege.be>
#
# Copyright (c) 2020-2023, University of Liège. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of the copyright holder nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import os
import re
import sys
import json
import lief
import argparse

from collections import defaultdict
from capstone import *
from binascii import hexlify
from subprocess import run, PIPE

VERBOSE=False
verbose = VERBOSE

WORKDIR="/home/gain/unikraft/apps/lib-helloworld-remove/build"
FILE="unikernel_kvmfc-x86_64_local_align_aslr.dbg"
JSON_MAPS_FILE='ind_map.json'
PAGE_SIZE=0x1000

def printv(*args, **kwargs):
    if verbose:
        print(*args, **kwargs)

def toSigned(signed_int):
    return signed_int + 2**32

class Unikernel:
    def __init__(self, name):
        self.name = name
        self.binary = None
        self.segments = list()
        self.sections = list()
        self.symbols = list()
        self.map_symbols = defaultdict(list)
        self.dump = None
        self.maps_size_libs = dict()

class Segment:
    def __init__(self, address, offset, size):
        self.address = address
        self.offset = offset
        self.size = size

class Section:
    def __init__(self, name, virtual_address, offset, size, alignment):
        self.name = name
        self.virtual_address = virtual_address
        self.start_align = self.round_mult()
        self.offset = offset
        self.size = size
        self.alignment = alignment
        self.end = virtual_address+size
        self.pages = list()
        self.sectionInd = None
        self.content = None

    def round_mult(self, base=PAGE_SIZE):
        if self.virtual_address % PAGE_SIZE != 0:
            return base * round(self.virtual_address / base)
        return self.virtual_address

class sectionInd:
    def __init__(self, addr):
        self.IndInst = dict()
        self.start_addr = addr
        self.addr = addr
        self.bt = bytearray()

    def addInsBytes(self, op, addr , offset=0x0):
        barray = bytearray()
        diff = -(self.addr-addr)-offset

        printv("(addInsBytes): 0x{:x}- 0x{:x}= 0x{:x} -> {:x}".format(self.addr, addr, diff, toSigned(diff)))
        barray.append(op)
        barray.extend(diff.to_bytes(4, byteorder = 'little', signed=True))

        self.IndInst[self.addr]=barray
        self.addr += 5
        self.bt.extend(barray)

    def optimize_addrs(self):

        printv("(optimize_addrs): Addr before: {:x} - Addr now: {:x}".format(self.addr, self.addr-5))

        self.addr -= 5 #remove the previous jump
        self.bt = self.bt[:-5] #remove the previous jump

    def addIndBytes(self, next_addr, current_addr, ins_bytes, optimized_suit):

        if optimized_suit > 0:
            self.optimize_addrs()

        op = ins_bytes[0]
        if op == 0xe8:


            self.addInsBytes(op, next_addr, 0x5)
            self.addInsBytes(0xe9, current_addr)
        elif op == 0xe9:


            self.addInsBytes(op, next_addr, 0x5)
            self.addInsBytes(0xe9, current_addr+0x5)
        elif op == 0xba or 0xbe or 0xbf:


            self.bt.extend(ins_bytes)
            self.addr += 5
            self.addInsBytes(0xe9, current_addr)
        else:
            printv("(addIndBytes) 0x{:x} :".format(op), end=" ")
            printv(ins_bytes)

        if len(self.bt) > 0 and len(self.bt) % PAGE_SIZE == 0:
            printv("(addIndBytes) EXCEED SIZE {}".format(len(self.bt)))

        return self.addr

    def addIndBytesBigger(self, next_addr, current_addr, ins_bytes, optimized_suit):

        if optimized_suit > 0:
            self.optimize_addrs()

        self.bt.extend(ins_bytes)
        self.addr += len(ins_bytes)
        self.addInsBytes(0xe9, current_addr)

        if len(self.bt) > 0 and len(self.bt) % PAGE_SIZE == 0:
            printv("(addIndBytesBigger) EXCEED SIZE {}".format(len(self.bt)))

    def debug(self, barray):
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True
        for new_ins in md.disasm(barray, self.addr):
            printv("(addIndBytesBigger) Other: 0x{:x} {:<32}{:<20}{:<32}\n".format(new_ins.address, ' '.join(re.findall('..',new_ins.bytes.hex())), new_ins.mnemonic, new_ins.op_str), end="")

    def addIndBytesBiggerRip(self, ins, optimized_suit):

        if optimized_suit > 0:
            self.optimize_addrs()

        x = re.search("rip\s+(?P<op>\+|\-)\s+(?P<addr>0x[A-Fa-f0-9]{2,})", ins.op_str)
        if x != None:
            op = x.group("op")
            if op == "+":
                addr = ins.address + int(x.group("addr"), 16)
            elif op == "-":
                addr = ins.address - int(x.group("addr"), 16)

        # Compute the (old) offset from rip
        previous_offset = addr-ins.address
        previous_offset_bt = previous_offset.to_bytes(4, byteorder = 'little', signed=True)

        # Compute the (new) offset from rip (in the ind)
        offset = addr-self.addr

        # Rewrite the instructions with the new offset
        barray = bytearray()
        index_find = ins.bytes.find(previous_offset_bt)
        barray.extend(ins.bytes[0:index_find])
        barray.extend(offset.to_bytes(4, byteorder = 'little', signed=True))
        reminder = ins.bytes[index_find+len(previous_offset_bt):]
        if len(reminder) > 0:
            barray.extend(reminder)

        # Add the jump instruction
        self.IndInst[self.addr]=barray
        self.addr += len(ins.bytes)
        self.bt.extend(barray)
        self.addInsBytes(0xe9, ins.address)

        if len(self.bt) > 0 and len(self.bt) % PAGE_SIZE == 0:
            printv("(addIndBytesBiggerRip) EXCEED SIZE {}".format(len(self.bt)))

class Symbol:
    def __init__(self, address, name, info):
        self.address = address
        self.name = name
        self.info = info

class Instruction:
    def __init__(self, address, mnemonic, op_str, _bytes):
        self.address = address
        self.mnemonic = mnemonic
        self.op_str = op_str
        self.bytes = self.cut(hexlify(_bytes).decode())

    def cut(self, line, n=2):
        return ' '.join([line[i:i+n] for i in range(0, len(line), n)])

def display_functions(ins, uk, int_addr, m=None):

    if int_addr in uk.map_symbols:
        printv(">> FCT: ", end="")
        for s in uk.map_symbols[int_addr]:
            printv(s.name, end="")
        printv("")
    printv("0x{:x} {:<32}{:<20}{:<32}".format(ins.address, ' '.join(re.findall('..',ins.bytes.hex())), ins.mnemonic, ins.op_str), end="")

    if m != None:
        found = False
        int_addr = int(m, 16)
        if int_addr in uk.map_symbols:
            # Call to a function
            for s in uk.map_symbols[int_addr]:
                printv("\t{} --> call to {}".format(m, s.name))
                found = True
        else:
            # Another section
            for s in uk.sections:
                if s.virtual_address < int_addr < s.end:
                    printv("\t{} --> refer to {}".format(m, s.name))
                    found = True

        if not found:
            printv("")
    else:
        printv("")


def use_absolute_value(addrInt, ins_bytes):
    bstr = ""
    for i, b in enumerate(reversed(ins_bytes)):
        if b == 0x0 and i == 0:
            continue
        bstr = bstr + '{:02x}'.format(b)

        if "{:02x}".format(addrInt) in bstr:
            return True
    return False

def check_addr(uk, addrInt, current_section, ins):

    # Check first if it is an absolute value (in bytes)
    if use_absolute_value(addrInt, ins.bytes):
        return True

    # Check if it is within the same microlib (short relative call)
    if current_section.virtual_address <= addrInt < current_section.end:
        return False

    # Check if it is used addres from other section
    for s in uk.sections:
        if s.virtual_address != 0 and s.virtual_address <= addrInt <= s.end:
            return True

    return False

def process_instructions(uk, ins, s, used_addr, optimized_suit):
    addrInt= int(used_addr, 16)
    if "rip" not in ins.op_str and len(used_addr) < 8:
        return None

    if addrInt == 0xffffff or len(used_addr) > 8:
        return None

    # Check range of address and addressing mode
    if check_addr(uk, addrInt, s, ins) == False:
        printv("(process_instructions) 0x{:x} {:<32}{:<20}{:<32}\n".format(ins.address, ' '.join(re.findall('..',ins.bytes.hex())), ins.mnemonic, ins.op_str), end="")
        return None

    if len(ins.bytes) == 5:
        # Call or jmp instructions
        printv("(process_instructions) Instruction: 0x{:x} {:<32}{:<20}{:<32}\n".format(ins.address, ' '.join(re.findall('..',ins.bytes.hex())), ins.mnemonic, ins.op_str), end="")
        addr = s.sectionInd.addr
        s.sectionInd.addIndBytes(addrInt, ins.address, ins.bytes, optimized_suit)
        barray = bytearray()
        barray.append(0xe9)
        if optimized_suit > 0:
            diff = addr - ins.address - 0x5 - 0x5
        else:
            diff = addr - ins.address - 0x5
        barray.extend(diff.to_bytes(4, byteorder = 'little', signed=True))
    elif len(ins.bytes) > 5:

        # Complex instructions
        addr = s.sectionInd.addr
        if "rip" in ins.op_str:
            s.sectionInd.addIndBytesBiggerRip(ins, optimized_suit)
        else:
            s.sectionInd.addIndBytesBigger(addrInt, ins.address, ins.bytes, optimized_suit)

        # Add the jmp in the current address
        barray = bytearray()
        barray.append(0xe9)
        if optimized_suit > 0:
            diff = addr - ins.address - 0x5 - 0x5
        else:
            diff = addr - ins.address - 0x5


        barray.extend(diff.to_bytes(4, byteorder = 'little', signed=True))

        # padding with Nops
        for _ in range(len(ins.bytes) - 5):
            barray.append(0x90)
    else:
        return None

    return barray

def disassemble(uk, s):

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    nameInd = s.name.replace(".text", ".ind")


    # Add Ind section to current section
    s.sectionInd = sectionInd(uk.binary.get_section(nameInd).virtual_address)
    bt = bytearray()
    optimized_suit = 0 # Incremented if several instructions are follow up (optimize)
    for ins in md.disasm(s.content, s.virtual_address):
        int_addr = int(ins.address)

        x = re.search("0x[A-Fa-f0-9]{4,}", ins.op_str)
        if x != None:
            m = x.group()
            if m.lower() != "0xffffffff":
                # display_functions(ins, uk, int_addr, m)
                ind_bytes = process_instructions(uk, ins, s, m, optimized_suit)
                if ind_bytes:
                    bt.extend(ind_bytes)
                    optimized_suit += 1
                else:
                    bt.extend(ins.bytes)
                    optimized_suit = 0
            else:
                bt.extend(ins.bytes)
                optimized_suit = 0
        else:
                # display_functions(ins, uk, int_addr)
                bt.extend(ins.bytes)
                optimized_suit = 0

    uk.binary.get_section(s.name).content = bt
    uk.binary.get_section(nameInd).content = s.sectionInd.bt
    
    len_ind=len(s.sectionInd.bt)
    if len_ind > 0:
        if s.name in uk.maps_size_libs:
            old_value = int(uk.maps_size_libs[s.name], 16)
            if len_ind > old_value:
                uk.maps_size_libs[s.name] = "0x{:x}".format(len_ind)
                print("Update {} with new value 0x{:x} (old: 0x{:x})".format(s.name,len_ind,old_value))
        else:    
            uk.maps_size_libs[s.name] = "0x{:x}".format(len_ind)
    
    return

def process_symbols(uk, lines):
    for l in lines:
        group = l.split()
        if len(group) == 3:
            symbol = Symbol(int(group[0],16), group[2], group[1])
            uk.map_symbols[symbol.address].append(symbol)
            uk.symbols.append(symbol)
            printv("{} - 0x{:x} - ({} bytes)".format(symbol.name, symbol.address, symbol.info))
        else:
            printv("[WARNING] Ignoring symbol {}".format(l))

def get_symbols(uk):
    p = run( ['nm', '--no-demangle',uk.name], stdout=PIPE, stderr=PIPE, universal_newlines=True)

    if p.returncode == 0 and len(p.stdout) > 0:
        process_symbols(uk, p.stdout.splitlines())
    elif len(p.stderr) > 0:
        printv("[WARNING] stderr:", p.stderr)
    else:
        printv("[ERROR] Failure to run NM")
        sys.exit(1)

def update_uk(uk, filename):
    uk.binary.write(filename)

def process_file(uk):

    uk.binary = lief.parse(uk.name)

    for segment in uk.binary.segments:
        uk.segments.append(Segment(segment.virtual_address, segment.file_offset, segment.virtual_size))

    for section in uk.binary.sections:
        uk_sect = Section(section.name , section.virtual_address, section.offset, section.size, section.alignment)
        bt = bytearray()
        bt.extend(section.content)
        uk_sect.content = bt
        uk.sections.append(uk_sect)

def rewrite_uk(file, json_file, v):
    
    global verbose
    
    verbose = False
    if v:
        verbose=True
        
    uk = Unikernel(file)
    process_file(uk)
    get_symbols(uk)
    
    if os.path.isfile(json_file):
        with open(json_file, 'r') as json_data:
            uk.maps_size_libs = json.load(json_data)
    
    for _, s in enumerate(uk.sections):
        if s.name.startswith(".text.") and "app" not in s.name:
            printv("Update " + s.name)
            disassemble(uk, s)
        elif s.name.startswith(".text."):
            print("- Ignore " + s.name)

    update_uk(uk, file)
    with open(json_file, 'w') as fp:
        json.dump(uk.maps_size_libs, fp, indent=4)
    
def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file',     help='Path to ELF file to analyse', type=str,
                        default=os.path.join(WORKDIR, FILE))
    parser.add_argument('-v', '--verbose',  help='verbose mode', type=bool,  default=VERBOSE)
    parser.add_argument('-j', '--json',     help="Path to the json file which contains size (ind)", type=str, default=JSON_MAPS_FILE)
    args = parser.parse_args()

    rewrite_uk(args.file, args.json, args.verbose)

if __name__ == "__main__":
    main()