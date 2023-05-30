#!/usr/bin/python3

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

import argparse
import logging

from ukManager import UkManager
from utils import CustomFormatter, logger

# Some constants for default arguments values
WORKSPACE   ="/home/gain/unikraft/"

LOC_COUNTER = 0x130000
ALIGN_TEXT  = True
LINK        = True

UKS_INCLUDED = ["lib-helloworld-remove", "lib-hanoi-remove"]

def str2bool(v):
    if isinstance(v, bool):
        return v
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')

def main():

    parser = argparse.ArgumentParser(description='Aligner')
    parser.add_argument('-w', '--workspace',     help='Workspace Directory', type=str, default=WORKSPACE)
    parser.add_argument('-l', '--loc',           help='Location counter', type=int, default=LOC_COUNTER)
    parser.add_argument('-a', '--align',         help='Align text on page boundary instead of compacting common lib', type=str2bool, nargs='?', const=True, default=ALIGN_TEXT)
    parser.add_argument('-r', '--rel',           help='Relink', type=str2bool, nargs='?', const=True, default=LINK)
    parser.add_argument('-v', '--verbose',       help='Verbose', type=str2bool, nargs='?', const=True, default=True)
    parser.add_argument('-u', '--uks',           help='Unikernels to align as a list (-l uks1 uks2 ...)', nargs='+', default=UKS_INCLUDED)
    parser.add_argument('-c', '--custom_loader', help='Move individual lib out of RO space (for custom loader)', type=str2bool, nargs='?', const=True, default=True)
    parser.add_argument('-o', '--copy_objs',     help="Copy object files to keep consistency", type=str2bool, nargs='?', const=True, default=True)
    parser.add_argument('--aslr',                help="Use aslr (0: disabled - 1: fixed indirection table - 2: with ASLR support)", type=int, default=0)
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.ERROR)
        ch = logging.StreamHandler()
        ch.setLevel(logging.ERROR)

    # Create console handler with a higher log level
    ch.setFormatter(CustomFormatter())
    logger.addHandler(ch)

    ukManager = UkManager(args)
    ukManager.process_folder()
    ukManager.process_maps()

    if ukManager.copy_objs:
        ukManager.copy_all_objs()

    ukManager.update_link_file(args.custom_loader)
    
    if ukManager.aslr > 0:
        ukManager.binary_rewrite()

if __name__ == '__main__':
    main()