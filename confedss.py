#!/usr/bin/env python3

from qiling.exception import QlMemoryMappedError
from qiling.const import *
from qiling import Qiling
from ghidra_connect import Ghidra
from collections import namedtuple as _nt
from argparse import ArgumentParser
from enum import Enum
import importlib.util
import logging
import unicorn
import pickle
import json
import os

PAGE_SZ = 0x1000

class GhidraEmu(object):
    _uc_arch_translation = {
        'ARM': 'arm',
        'AARCH64': 'arm64'
    }

    extra_mappings = {}
    breakpoints = []

    def __init__(self, entry_point=False, hooks=None, mappings=None, snapshot=None):
        self.ghidra = Ghidra()
        self.ghidra.bridge.client.response_timeout = 10
        self.arch = self.ghidra.get_arch()

        self.logger = logging.getLogger()
        self.logger.setLevel(logging.INFO)
        self.logger.addHandler(logging.StreamHandler())
        self.f_hooks = hooks

        if not entry_point:
            f_entry = self.ghidra.symbol_manager.getLabelOrFunctionSymbols('_start', None)
            if not f_entry:
                f_entry = self.ghidra.symbol_manager.getLabelOrFunctionSymbols('_entry', None)
            if not f_entry:
                logging.debug(
                    f'No function named _start or _entry found, using current cursor offset ({hex(self.ghidra.cursor)})')
                self.entry_point = self.ghidra.cursor
            else:
                f_entry = f_entry[0]
                self.entry_point = f_entry.getProgramLocation().address.offset
                logging.debug(f'Function {f_entry.name} found! Using entry point {hex(self.entry_point)}')
        else:
            self.entry_point = entry_point

        blk_code = self.ghidra.ns.currentProgram.memory.getBlock(self.ghidra._jaddr(self.entry_point))
        self.code_size = blk_code.size

        self.ql = Qiling(code=self.ghidra.read_mem_block(blk_code, chunk_size=128*1024),
                         archtype=self._uc_arch_translation[self.arch.isr],
                         ostype='linux',
                         verbose=QL_VERBOSE.DEFAULT
                         )

        while self.ql.mem.map_info:
            self.ql.mem.unmap_all()

        if snapshot:
            with open(snapshot, 'rb') as f_snap:
                self.ql.restore(pickle.load(f_snap))
        else:
            self.load_ghidra_mem_segments()
            if mappings:
                self.load_extra_mappings(mappings)

        # Map some mem for the stack
        if max([ x[1] for x in self.ql.mem.map_info ]) < 0x7f000000:
            self.ql.mem.map(0x7f000000, 0xf00000, info='stack')
        else:
            self.ql.mem.map(max([ x[1] for x in self.ql.mem.map_info ]), 0xf00000)

        # Give the stack enough room on both sides
        self.ql.arch.regs.sp = max([ x[1] for x in self.ql.mem.map_info ]) - 0x10000
        self.ql.map_region = self.map_region

        # Load Python file containing Qiling hooks
        self.ql.entry_point = self.entry_point
        if self.f_hooks:
            spec = importlib.util.spec_from_file_location("unicorn_hooks", self.f_hooks)
            self.hooks_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(self.hooks_module)
            self.hooks_module.insert_hooks(self.ql, self.ghidra)

        self.ql.debugger = True
        self.ql.arch.regs.sp = 0x7fe00000

        if self.ghidra.is_thumb(self.entry_point):
            # Set CPU to Thumb
            self.ql.arch.regs.cpsr |= (1<<5)
            self.ql.hook_address(self.hook_start_thumb, self.entry_point)

        self.ql._targetname = self.ghidra.ns.currentProgram.name
        self.ql._path = self.ghidra.ns.currentProgram.name
        self.ql.argv[0] = self.ghidra.ns.currentProgram.name
        self.start()

    def start(self):
        self.ql.os.entry_point = self.entry_point

        try:
            self.ql.run(begin=self.entry_point)

        except unicorn.UcError as unicorn_error:
            # If Qiling encouters an exception while running an error handler
            # (for example for an unmapped read), Qiling saves the exception in
            # an internal field and tries to close unicorn. However, unicorn sees
            # that it still has an error (in the example an unmapped read error)
            # and raises an exception for that error.

            # Qiling does not catch this exception, so we should.
            internal_exception = self.ql.internal_exception
            if internal_exception is not None:
                raise internal_exception from unicorn_error  # pylint: disable=raising-bad-type

            print(f"[!] ERROR IN UNICORN")
            print(f"[i] pc: {self.ql.arch.regs.arch_pc:08x} lr: {self.ql.arch.regs.lr:08x}")
            raise unicorn_error

    def load_ghidra_mem_segments(self):
        for segment in self.ghidra.ns.currentProgram.memory.blocks:
            start = segment.getStart().offset
            end = segment.getEnd().offset
            size = segment.getSize()
            map_size = size + (0x1000 - ((size) % 0x1000)) if size % 0x1000 else size

            logging.info('Mapping segment {} at 0x{:02x} with size 0x{:02x} (Map size 0x{:02x})'.format(
                segment.name,
                start,
                size,
                map_size))

            # TODO Make a pull request for the ret-sync Ghidra implementation to recognize the right segment name
            # If the segment contains our entrypoint use the name of the program for it, this makes retsync recognize it for now
            self.map_region(start, map_size, name=segment.name if self.entry_point not in range(start, end) else self.ghidra.ns.currentProgram.name)
            if segment.isInitialized():
                self.ql.mem.write(start, self.ghidra.read_mem_block(segment))

    def map_region(self, offset, size, name=None):
        try:
            self.ql.mem.map(offset, size, info=name)
        except QlMemoryMappedError:
            self._map_region(offset, size, name)


    def _map_region(self, offset, size, name=None):
        if offset % PAGE_SZ:
            size += offset - (offset // PAGE_SZ) * PAGE_SZ
            offset = (offset // PAGE_SZ) * PAGE_SZ

        if size % PAGE_SZ:
            size = (-(-size // PAGE_SZ)) * PAGE_SZ

        for blk in range(offset, offset + size, PAGE_SZ):
            d_start = None
            d_end = None
            b_start = None
            b_end = None
            b_allocated = False

            for start, end, perms, info, is_mmio in self.ql.mem.map_info:
                if blk == start or (blk >= start and blk + PAGE_SZ <= end + 1):
                    b_allocated = True
                elif blk == end:
                    b_start = (start, end - start)

                elif blk + PAGE_SZ == start:
                    b_end = (start, end - start)

            if b_start and b_end:
                if self.ql.mem.read(*b_start) != b'\00'*b_start[1]:
                    d_start = bytes(self.ql.mem.read(*b_start))
                self.ql.mem.unmap(*b_start)
                if self.ql.mem.read(*b_end) != b'\00'*b_end[1]:
                    d_end = bytes(self.ql.mem.read(*b_end))
                self.ql.mem.unmap(*b_end)
                self.ql.mem.map(b_start[0], (b_end[0] + b_end[1]) - b_start[0], info=name)
                if d_start:
                    self.ql.mem.write(b_start[0], d_start)
                if d_end:
                    self.ql.mem.write(b_end[0], d_end)
            elif b_start:
                if self.ql.mem.read(*b_start) != b'\00'*b_start[1]:
                    d_start = bytes(self.ql.mem.read(*b_start))
                self.ql.mem.unmap(*b_start)
                self.ql.mem.map(b_start[0], (blk + PAGE_SZ) - b_start[0], info=name)
                if d_start:
                    self.ql.mem.write(b_start[0], d_start)
            elif b_end:
                if self.ql.mem.read(*b_end) != b'\00'*b_end[1]:
                    d_end = bytes(self.ql.mem.read(*b_end))
                self.ql.mem.unmap(*b_end)
                self.ql.mem.map(blk, (b_end[0] + b_end[1]) - blk, info=name)
                if d_end:
                    self.ql.mem.write(b_end[0], d_end)
            elif b_allocated:
                continue
            else:
                self.ql.mem.map(blk, PAGE_SZ, info=name)

    def hook_start_thumb(self, ql):
        ql.arch.regs.cpsr |= (1<<5)

    def load_extra_mappings(self, mappings):
        for offset,size in mappings.items():
            logging.debug('Mapping region for {} at 0x{:02x} (size: {:02x})'.format(offset, size))
            self.map_region(offset, size)

def main():
    args = ArgumentParser()
    args.add_argument('--entry_point', help='The entry point to start execution', default=False)
    args.add_argument('--hooks', help='The python file containing the hooks for the emulator', default=False)
    args.add_argument('--mappings', help='Extra memory mappings in JSON dict format', default=False)
    args.add_argument('--snapshot', help='A snapshot containing a previous state for the emulator',
                      default=None)
    args = args.parse_args()

    # Entry point can be 0
    if args.entry_point != False:
        entry_point = int(args.entry_point, 16)
    else:
        entry_point = False

    if args.mappings:
        with open(args.mappings, 'r', encoding='utf-8') as f_mappings:
            args.mappings = json.load(f_mappings)

    GhidraEmu(**vars(args))

if __name__ == '__main__':
    main()
