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
import time
import shlex
import random
import shutil
import subprocess

from unikernels import *
from aslr import binary_rewriter
from utils import round_to_n, logger, SUCCESS, LDS_VFSCORE, LDS_NETDEV, LDS_UKS
from stringBuilder import StringBuilder

class UkManager:
    def __init__(self, args):
        self.uks = list()
        self.workspace = os.path.join(args.workspace + "apps")
        self.unikraft_path = os.path.join(args.workspace + "unikraft")
        self.must_relink = args.rel
        self.loc_counter = args.loc
        self.uks_included = args.uks
        self.align_text = args.align
        self.copy_objs = args.copy_objs
        self.aslr = args.aslr
        self.common_to_all = dict()
        self.common_subset = dict()
        self.objs_files = dict()
        self.indivial = dict()
        self.global_maps = dict()
        self.loc_sect = dict()
        self.sb_link = dict()

    def process_folder(self):
        for d in os.listdir(self.workspace):
            if d in self.uks_included:
                uk = Unikernel(d, os.path.join(self.workspace, d))
                logger.info("Process {} ".format(d))
                uk.process_build_folder(os.path.join(self.workspace, d, "build/"), self.global_maps, self.objs_files)
                self.uks.append(uk)
        
        if len(self.uks) <= 1:
            logger.fatal("At least 2 unikernels instances are required. Found: {}".format(len(self.uks)))
            sys.exit(1)

    def process_maps(self):
        for k,v in self.global_maps.items():
            if v.occurence == len(self.uks):
                self.common_to_all[k] = v
            elif v.occurence > 1:
                self.common_subset[k] = v
            else:
                self.indivial[k] = v

    def process_common_to_all(self, type_sect):
        sb = StringBuilder()
        for _, ukLib in self.common_to_all.items():

            if ukLib.total_size[type_sect] == 0:
                logger.warning("Skip {} has a size of 0".format(ukLib.name + "(" + type_sect + ")"))
                continue

            if ".text" not in type_sect:
                # Get the alignment of the section (.rodata)
                self.loc_counter = round_to_n(self.loc_counter, ukLib.sections[type_sect].addralign)

            sb.append("  ").append(type_sect).append(".").append(ukLib.name).append(" 0x{:x} : ".format(self.loc_counter)).append("{ ").append(ukLib.name).append(OBJ_EXT).append("(").append(type_sect).append("); }\n")
            
            if  ".text" in type_sect and self.align_text:
                # Align common lib on pages boundary (instead of compacting) -> only for .text
                self.loc_counter = round_to_n(self.loc_counter+ukLib.total_size[type_sect], PAGE_SIZE)
            else:
                self.loc_counter += ukLib.total_size[type_sect]
                
        return sb.to_str()

    def compute_loc(self, type_sect, subset):
        if len(subset) == 0:
            return

        for uk in self.uks:
            uk.loc_counter = self.loc_counter
            uk.update_loc_counter(type_sect, subset)

        if ".text" in type_sect:
            self.loc_counter = round_to_n(max(uk.loc_counter for uk in self.uks), PAGE_SIZE)
        else:
            self.loc_counter = max(uk.loc_counter for uk in self.uks)
            
    def update_link_file(self, use_custom_loader):
        if (self.aslr == 0):
            self.update_link_file_spacer(use_custom_loader)
        elif (self.aslr == 1 or self.aslr == 2):
            self.update_link_file_aslr()
        else:
            logger.fatal("aslr must either be 0, 1 or 2. Found: {}".format(len(self.uks)))
            sys.exit(1)
            
    def update_link_file_aslr(self):
        
        maps_size_libs = dict()
        try:
            with open(os.path.join("aslr", binary_rewriter.JSON_MAPS_FILE)) as json_file:
                maps_size_libs = json.load(json_file)
        except:
            logger.warning("No json file found. Continue with empty map size.")
            
        self.sb_link[".rodata"] = StringBuilder()
        self.sb_link[".rodata"].append(".rodata.common : {\n")
        for _, ukLib in self.common_to_all.items():
            self.sb_link[".rodata"].append("  {}{}(.rodata);\n".format(ukLib.name, OBJ_EXT))
        self.sb_link[".rodata"].append("}\n")
        
        app_lib = None
        logger.info("Processing the mapping for {} unikernels".format(len(self.uks)))
        for uk in self.uks:
            libs = list()
            self.sb_link[".rodata_uk"] = StringBuilder()
            for ukLib in uk.objects:
                
                size_ind = 0x1000
                key = '.text.' + ukLib
                if key in maps_size_libs:
                    size_ind=int(maps_size_libs[key], 16)
                
                if ukLib.startswith("app"):
                    app_lib=ukLib
                else:
                    libs.append(".text.{} : ALIGN(0x1000){{ {}{}(.text); }}\n.ind.{} : ALIGN(0x1000) {{ BYTE(1);. += 0x{:x}-1; }}\n".format(ukLib, ukLib, OBJ_EXT, ukLib, size_ind))
                
                if ukLib in self.common_subset or ukLib in self.indivial:
                    self.sb_link[".rodata_uk"].append(".rodata.{} : ALIGN(0x1000) {{ {}{}(.rodata); }}\n".format(ukLib, ukLib, OBJ_EXT))

            if self.aslr == 2:
                libs = random.sample(libs, len(libs))

            if app_lib != None:
                libs.append(".text.{} : ALIGN(0x1000){{ {}{}(.text); }}\n".format(app_lib, app_lib, OBJ_EXT))
            
            self.sb_link[".text"] = ''.join(libs)
            
            plat = "lib" + uk.kvm_plat + "plat"
            path = os.path.join(self.workspace, uk.name, "build")
            with open(os.path.join(path, plat, "link64.lds"), "r") as file_in, open(os.path.join(path, plat, "link64_out_aslr.lds"), "w") as file_out:
                file_out.write(self.process_link64_spacer_aslr(file_in.read().splitlines(), uk))
                logger.info("Written link64_out_aslr.lds in {}/ ".format(path + "/" + plat))
            if self.must_relink:
                self.relink(path, uk.use_vfscore, uk.kvm_plat)
                
    def binary_rewrite(self):
        
        os.chdir(os.path.dirname(os.path.realpath(__file__)))
        
        for uk in self.uks:
            logger.info("Perform Binary rewriting of {}_aslr".format(uk.name))
            ukname = os.path.join(uk.workspace, "build/unikernel_kvmfc-x86_64_local_align_aslr.dbg")
            try:
                start = time.time()
                binary_rewriter.rewrite_uk(ukname, os.path.join("aslr",binary_rewriter.JSON_MAPS_FILE) , False)
                end = time.time()
                logger.info("Binary rewriting {:<32} (time: {}) {} ".format(uk.name + "_aslr", end-start, SUCCESS))
            except Exception as e:
                logger.error("Binary rewriting failed ({}) - {}".format(uk.name, e))

    def update_link_file_spacer(self, use_custom_loader):

        logger.info("Processing the mapping for {} unikernels".format(len(self.uks)))

        # Common libs (.text)
        self.sb_link[".text"] = self.process_common_to_all(".text")
        
        # Subset libs (.text) and then individual lib (.text)
        self.compute_loc(".text", self.common_subset)
        if not use_custom_loader:
            self.compute_loc(".text", self.indivial)

        # uk sections start
        self.loc_sect["_etext"] = self.loc_counter
        
        # rodata starts
        self.loc_counter += PAGE_SIZE
        self.sb_link[".rodata"] = self.process_common_to_all(".rodata")

        # Subset libs (.rodata) and then individual lib (.rodata)
        self.compute_loc(".rodata", self.common_subset)
        if not use_custom_loader:
            self.compute_loc(".rodata", self.indivial)
        
        # Align to page boundary
        self.loc_counter = round_to_n(self.loc_counter, PAGE_SIZE)

        # Sections after .rodata and before .data
        max_size_sect = dict()
        for s in ["_ctors", ".init_array", "_ectors"]:
            self.loc_sect[s] = self.loc_counter
            self.loc_counter += PAGE_SIZE 

        if use_custom_loader:
            self.compute_loc(".text", self.indivial)
            self.compute_loc(".rodata", self.indivial)
            self.loc_counter = round_to_n(self.loc_counter, PAGE_SIZE)
        
        # Computes max size of data and bss
        for k in [".data", ".bss"]:
            self.loc_sect[k] = self.loc_counter
            # Compute next address for next section
            max_size_sect[k] = max(uk.total_size[k] for uk in self.uks)
            self.loc_counter += round_to_n(max_size_sect[k] , PAGE_SIZE)
        
        # For .intrstack
        self.loc_sect[".intrstack"] = self.loc_counter

        # Read and write to files
        for uk in self.uks:
            plat = "lib" + uk.kvm_plat + "plat"
            path = os.path.join(self.workspace, uk.name, "build")
            with open(os.path.join(path, plat, "link64.lds"), "r") as file_in, open(os.path.join(path, plat, "link64_out.lds"), "w") as file_out:
                file_out.write(self.process_link64_spacer(file_in.read().splitlines(), uk))
                logger.info("Written link64_out.lds in {}/ ".format(path + "/" + plat))
            if self.must_relink:
                self.relink(path, uk.use_vfscore, uk.kvm_plat)

    def relink(self, path, use_vfscore, kvm_plat):           
        os.chdir(path)
        
        aslr = ""
        if self.aslr != 0:
            aslr = "_aslr"

        linker_add=""
        if use_vfscore:
            linker_add="-Wl,-T,{}/lib/vfscore/extra_out64{}.ld".format(self.unikraft_path, aslr)
        
        if os.path.isfile("{}/libvfscore/libparam.lds".format(path)):
            linker_add += " -Wl,-T,{}/libvfscore/libparam.lds".format(path)
            with open("{}/libvfscore/libparam.lds".format(path), "w") as f:
                f.write(LDS_VFSCORE)
        if os.path.isfile("{}/libuknetdev/libparam.lds".format(path)):
            linker_add += " -Wl,-T,{}/libuknetdev/libparam.lds".format(path)
            with open("{}/libuknetdev/libparam.lds".format(path), "w") as f:
                f.write(LDS_NETDEV)
        cmd = 'gcc -nostdlib -Wl,--omagic -Wl,--build-id=none -nostdinc -no-pie -Wl,-m,elf_x86_64 -Wl,-m,elf_x86_64 -Wl,-dT,{}/lib{}plat/link64_out{}.lds -Wl,-T,{}/lib/uksched/extra{}.ld {} -o unikernel_{}-x86_64_local_align{}.dbg'.format(path, kvm_plat, aslr, self.unikraft_path, aslr, linker_add, kvm_plat, aslr)
        logger.info(cmd)
        p = subprocess.run(shlex.split(cmd))
        if p.returncode == 0:
            logger.info("Relinking {:<32} {}".format(path.split("/")[5], SUCCESS))
        else:
            logger.error("Relinking failed ({})".format(path.split("/")[5]))
            
    def process_link64_spacer_aslr(self, lines, uk):
        done = False
        sb = StringBuilder()
        for l in lines:
            if  "*(.text)" in l or "*(.rodata)" in l:
                sb.append(" }\n")
                continue
            elif "*(.text.*)" in l:
                sb.append(self.sb_link[".text"])
                done = True
                continue
            elif done and "}" in l:
                done = False
                continue
            elif "*(.rodata.*)" in l:
                sb.append(self.sb_link[".rodata"].to_str())
                sb.append(self.sb_link[".rodata_uk"].to_str())
                done = True
                continue
            
            sb.append(l).append("\n")
        
        return sb.to_str()

    def process_link64_spacer(self, lines, uk):
        done = False
        sb = StringBuilder()
        for l in lines:
            if  "*(.text)" in l or "*(.rodata)" in l:
                sb.append(" }\n")
                continue
            elif "_etext = .;" in l:
                sb.append(l + "\n")
                sb.append(" . = ").append("0x{:x}".format(self.loc_sect["_etext"])).append(";\n")
                continue
            elif "*(.text.*)" in l:
                sb.append(self.sb_link[".text"])
                sb.append(uk.sb_link[".text"].to_str())
                done = True
                continue
            elif done and "}" in l:
                done = False
                continue
            elif "_ctors = .;" in l or "_ectors = .;" in l:
                sb.append(" . = ").append("0x{:x}".format(self.loc_sect[l.split("=")[0].strip()])).append(";\n")
            elif "*(.rodata.*)" in l:
                sb.append(self.sb_link[".rodata"])
                sb.append(uk.sb_link[".rodata"].to_str())
                done = True
                continue
            elif l in [" .init_array : {", " _data = .;", " __bss_start = .;", " .intrstack :"]:
                x = re.findall(r"[a-z]+", l)

                if len(x) > 1 and "start" not in x:
                    x = '.'+'_'.join(x)
                else:
                    x = '.'+''.join(x[0])
                sb.append(" . = ").append("0x{:x}".format(self.loc_sect[x])).append(";\n")
            sb.append(l).append("\n")
        
        return sb.to_str()

    def copy_all_objs(self):
        
        logger.info("Uniform objects for {} unikernels".format(len(self.uks)))

        use_params = False
        # Check first if one unikernel is using libparam
        for uk in self.uks:
            if uk.use_uklibparam:
                use_params = True
                break

        for uk in self.uks:
            if use_params:
                # Copy libparam.lds
                for l in ["libvfscore", "libuknetdev"]:
                    p, _ = self.objs_files[l]
                    uk.create_param_files(l, p)
            
            # Copy objects files
            for obj in uk.objects:
                if obj in self.objs_files:
                    
                    oldsrc = os.path.join(uk.workspace, "build", obj + OBJ_EXT)
                    newsrc, _ = self.objs_files[obj]
                    
                    if os.path.samefile(newsrc, oldsrc):
                        continue
                    shutil.copyfile(newsrc, oldsrc)
