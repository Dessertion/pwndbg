#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import subprocess

import pwndbg.commands

parser = argparse.ArgumentParser(description='Launches rizin',
                                 epilog="Example: rizin -- -S -AA")
parser.add_argument('--no-seek', action='store_true',
                    help='Do not seek to current pc')
parser.add_argument('arguments', nargs='*', type=str,
                    help='Arguments to pass to radare')


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWithFile
def rizin(arguments, no_seek=False):
    filename = pwndbg.file.get_file(pwndbg.proc.exe)

    # Build up the command line to run
    cmd = ['rizin']
    if pwndbg.proc.alive:
        addr = pwndbg.regs.pc
        if pwndbg.elf.get_elf_info(filename).is_pie:
            addr -= pwndbg.elf.exe().address
        if not no_seek:
            cmd.extend(['-s', hex(addr)])
    cmd += arguments
    cmd.extend([filename])

    try:
        subprocess.call(cmd)
    except Exception:
        print("Could not run rizin. Please ensure it's installed and in $PATH.")
