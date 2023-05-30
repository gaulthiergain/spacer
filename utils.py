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

import math
import logging

SUCCESS = '\033[92m' + "[SUCCESS]" + "\x1b[0m"
logger  = logging.getLogger("Aligner")

LDS_VFSCORE="SECTIONS\n{\n __start_vfs__param_arg = LOADADDR(\n vfs__param_arg);\n vfs__param_arg : {\n  KEEP (*(vfs__param_arg))\n }\n __stop_vfs__param_arg = LOADADDR(\n vfs__param_arg) +\n SIZEOF(\n vfs__param_arg);\n}\nINSERT AFTER .uk_thread_inittab;\n"
LDS_NETDEV="SECTIONS\n{\n__start_netdev__param_arg = LOADADDR(\n netdev__param_arg);\n netdev__param_arg : {\n  KEEP (*(netdev__param_arg))\n }\n __stop_netdev__param_arg = LOADADDR(\n netdev__param_arg) +\n SIZEOF(\n netdev__param_arg);\n}INSERT AFTER .uk_thread_inittab;\n"
LDS_UKS=". = ALIGN((1 << 12)); __eh_frame_start = .; .eh_frame : { *(.eh_frame) *(.eh_frame.*) } __eh_frame_end = .; __eh_frame_hdr_start = .; .eh_frame_hdr : { *(.eh_frame_hdr) *(.eh_frame_hdr.*) } __eh_frame_hdr_end = .;\n. = ALIGN((1 << 12)); uk_ctortab_start = .;"\
        ".uk_ctortab : { KEEP(*(SORT_BY_NAME(.uk_ctortab[0-9]))) } uk_ctortab_end = .;\nuk_inittab_start = .; .uk_inittab : { KEEP(*(SORT_BY_NAME(.uk_inittab[1-6][0-9]))) } uk_inittab_end = .;\n. = ALIGN(0x8); .uk_eventtab : { KEEP(*(SORT_BY_NAME(.uk_event_*))) }"

class CustomFormatter(logging.Formatter):

    blue = '\033[94m'
    green = '\033[92m'
    grey = "\x1b[38;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    format = "[%(levelname)s]"
    body = " %(message)s"

    FORMATS = {
        logging.DEBUG: green + format + reset + body,
        logging.INFO: blue + format + reset+ body,
        logging.WARNING: yellow + format + reset+ body,
        logging.ERROR: red + format + reset+ body,
        logging.CRITICAL: bold_red + format + reset+ body
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

def round_to_n(x, base):
    if base == 0:
        return 0
    return base * math.ceil(x/base)

def global_maps_display(global_maps):
    for k,v in global_maps.items():
        print(k + " (" + str(v.occurence) + "): " + str(v.ukLib.total_size))