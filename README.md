# Spacer: A tool to align unikernels

Unikernels are on the rise in the cloud. These lightweight virtual machines (VMs) specialized to a single application offer the same level of isolation as full-blown VMs, while providing performance superior to standard Linux-based VMs or even to containers. However, their inherent specialization renders memory deduplication ineffective, causing unikernels, in practice, to consume more memory than their small memory footprint would suggest. This makes them less advantageous when thousands of SaaS and/or FaaS unikernels instances have to run on the same server.

We introduce a novel approach to build the next generation of networked services and lambda functions by improving unikernel's memory layout so that it is more likely to share identical pages with other unikernels deployed on the system. Our approach supports SaaS and FaaS architectures and can be used with ASLR. Our experiments show that our approach can reduce the amount of physical memory used by a set of unikernels running on the same server by as much as 3x, with next to no overhead on applications performance.

## Installation:

*Spacer* requirements:
 - [python 3.8.1](https://www.python.org)
 - [lief](https://github.com/lief-project/LIEF) (`pip3 install lief`)
 - [pyelftools](https://github.com/eliben/pyelftools/) (`pip3 install pyelftools`)


## Usage:

You can use *Spacer* with [Unikraft](https://github.com/unikraft/). All your unikernels (application) must be located in the `WORKSPACE` repository. Once done, use the `aligner.py` script to align the unikernels within this workspace.


```
usage: aligner.py [-h] [-w WORKSPACE] [-l LOC] [-a [ALIGN]] [-r [REL]] [-v [VERBOSE]] [-u UKS [UKS ...]] [-c [CUSTOM_LOADER]] [-g [GROUP]] [-o [COPY_OBJS]] [--use-id USE_ID] [--relink-only [RELINK_ONLY]] [--aslr ASLR] [--aslr_map [ASLR_MAP]] [--aslr_same_mapping [ASLR_SAME_MAPPING]]

Aligner

optional arguments:
  -h, --help            show this help message and exit
  -w WORKSPACE, --workspace WORKSPACE
                        Workspace Directory
  -l LOC, --loc LOC     Location counter
  -a [ALIGN], --align [ALIGN]
                        Align text on page boundary instead of compacting common lib
  -r [REL], --rel [REL]
                        Relink
  -v [VERBOSE], --verbose [VERBOSE]
                        Verbose
  -u UKS [UKS ...], --uks UKS [UKS ...]
                        Unikernels to align as a list (-l uks1 uks2 ...)
  -c [CUSTOM_LOADER], --custom_loader [CUSTOM_LOADER]
                        Move individual lib out of RO space (for custom loader)
  -g [GROUP], --group [GROUP]
                        Group common libraries to an aggregated section
  -o [COPY_OBJS], --copy_objs [COPY_OBJS]
                        Copy object files to keep consistency
  --aslr ASLR           Use aslr (0: disabled - 1: fixed indirection table - 2: with ASLR support)
  --aslr_map [ASLR_MAP]
                        Use a map of rodata for aslr (increase the sharing)
  --aslr_same_mapping [ASLR_SAME_MAPPING]
                        Use same mapping that Normal uks (libs order)
```

