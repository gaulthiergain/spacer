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
import shutil

from elftools.elf.elffile import ELFFile
from utils import round_to_n, logger
from collections import defaultdict
from stringBuilder import StringBuilder

PAGE_SIZE = 0x1000
OBJ_EXT   = ".o"

class UkSection:
    def __init__(self, name, size, addr, offset, addralign):
        self.name = name
        self.size = size
        self.addr = addr
        self.offset = offset
        self.addralign = addralign

class UkLib:
    def __init__(self, name):
        self.name = name.split(OBJ_EXT)[0]
        self.filetype = None
        self.sections = dict()
        self.total_size = dict()
        self.occurence = 1

    def update(self, ukLib_new):
        self.occurence += 1
        for k,v in ukLib_new.total_size.items():
            if self.total_size[k] < v:
                logger.info("Update {}({}) of {:<5} with {}".format(self.name, k, self.total_size[k] ,v))
                self.sections[k].addralign = ukLib_new.sections[k].addralign
                self.total_size[k] = v
    
    def __repr__(self):
        return str(self.total_size[".rodata"])

class Unikernel:
    def __init__(self, name, workspace):
        self.name = name
        self.workspace = workspace
        self.elf = None
        self.loc_counter = 0x0
        self.use_vfscore = False
        self.use_uklibparam = False
        self.objects = dict()
        self.total_size = dict()
        self.sb_link = dict()
        self.map_symbols = defaultdict(list)
        self.kvm_plat = "kvmq"

    def create_param_files(self, libname, newsrc):

        app_build_path = "/".join(newsrc.split("/")[:-1])
        lds_param = "{}/{}/libparam.lds".format(app_build_path, libname)
        dir_param = os.path.join(self.workspace, "build", libname, "")

        if os.path.isfile(dir_param + "libparam.lds"):
            return
        
        # Create a new directory which contains libparam
        os.makedirs(dir_param, exist_ok=True)
        
        logger.info("Copy {} to {}".format(lds_param, dir_param))
        shutil.copyfile(lds_param, os.path.join(dir_param, "libparam.lds"))

        if os.path.isfile(os.path.join(self.workspace, "build", "libuklibparam" + OBJ_EXT)):
            return
        
        shutil.copyfile(os.path.join(app_build_path, "libuklibparam" + OBJ_EXT), os.path.join(self.workspace, "build", "libuklibparam" + OBJ_EXT))
        
        if os.path.isdir(os.path.join(self.workspace, "build", "libuklibparam/")):
            return
        shutil.copytree(os.path.join(app_build_path, "libuklibparam/"), os.path.join(self.workspace, "build", "libuklibparam/"))
        self.objects["libuklibparam"] = None

    def update_loc_counter(self, type_sect, subset):

        if type_sect not in self.sb_link:
            self.sb_link[type_sect] = StringBuilder()

        for _, ukLib in subset.items():

            if ukLib.total_size[type_sect] == 0:
                logger.warning("Skip {} has a size of 0 ({})".format(ukLib.name + "(" + type_sect + ")", self.name))
                continue

            if ukLib.name in self.objects:
                # Get the alignment of the section
                if ".text" not in type_sect:
                    self.loc_counter = round_to_n(self.loc_counter, ukLib.sections[type_sect].addralign)
                
                self.sb_link[type_sect].append("  ").append(type_sect).append(".").append(ukLib.name).append(" 0x{:x} : ".format(self.loc_counter)).append("{ ").append(ukLib.name).append(OBJ_EXT).append("(").append(type_sect).append("); }\n")
                if ".text" in type_sect:
                    self.loc_counter += round_to_n(ukLib.total_size[type_sect], PAGE_SIZE)
                else:
                    self.loc_counter += ukLib.total_size[type_sect]

    def increment_sect(self, ukSection, ukLib):
    
        if ukLib.filetype == "ET_EXEC":
            self.elf = ukLib
        else:
            if ukSection.name in self.total_size:
                self.total_size[ukSection.name] += ukSection.size
            else:
                self.total_size[ukSection.name] = ukSection.size

            ukLib.total_size[ukSection.name] = ukSection.size
            self.objects[ukLib.name] = ukLib

    def process_file(self, path, libname, s_name):

        ukLib = UkLib(libname)
        with open(path + libname, 'rb') as f:
            elf =  ELFFile(f)
            ukLib.filetype = elf["e_type"]
            for s in s_name:
                sec = elf.get_section_by_name(s)
                if sec is not None:
                    ukSection = UkSection(sec.name, sec["sh_size"], sec["sh_addr"], sec["sh_offset"], sec["sh_addralign"])
                else:
                    ukSection = UkSection(s, 0x0, 0x0, 0x0, 0x0)
                    logger.warning("{} does not contain {}".format(libname, s))
                
                ukLib.sections[s] = ukSection
                self.increment_sect(ukSection, ukLib)
        
        return ukLib

    def process_build_folder(self, path, global_maps, objs_files, update=True):

        sec_name = [".data", ".rodata", ".text", ".bss"]
        for lib in sorted(os.listdir(path)):
            if "x86_64" not in lib and OBJ_EXT in lib:
                
                if ".ld.o" in lib:
                    continue

                # Map object files (take the biggest one)
                libname = lib.replace(OBJ_EXT, "")
                if libname in objs_files:
                    path_map, size = objs_files[libname]
                    if size < os.path.getsize(os.path.join(path, lib)):
                        objs_files[libname] = (os.path.join(path, lib), os.path.getsize(os.path.join(path, lib)))
                else:
                    objs_files[libname] = (os.path.join(path, lib), os.path.getsize(os.path.join(path, lib)))
            
                ukLib = self.process_file(path, lib, sec_name)
                if "vfscore" in lib:
                    self.use_vfscore = True
                elif "libkvmfcplat" in lib:
                    self.kvm_plat = "kvmfc"
                elif "libuklibparam" in lib:
                    self.use_uklibparam = True
                    
                # Skip update (for process ASLR script)
                if not update:
                    continue
                
                if ukLib.name not in global_maps:
                    global_maps[ukLib.name] = ukLib
                else:
                    global_maps[ukLib.name].update(ukLib)