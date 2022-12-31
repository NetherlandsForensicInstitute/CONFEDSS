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
        'ARM': QL_ARCH.ARM,
        'AARCH64': QL_ARCH.ARM64,
    }

    def __init__(self, entry_point=None, hooks=None, mappings=None, snapshot=None):
        self.ghidra = Ghidra()
        self.ghidra.bridge.client.response_timeout = 10
        self.arch = self.ghidra.get_arch()

        self.logger = logging.getLogger()
        self.logger.setLevel(logging.INFO)
        self.logger.addHandler(logging.StreamHandler())
        self.f_hooks = hooks

        if entry_point is None or isinstance(entry_point, str):
            for name in (entry_point, "_start", "_entry"):
                if name is None:
                    continue

                f_entry = self.ghidra.symbol_manager.getLabelOrFunctionSymbols(name, None)
                if f_entry:
                    f_entry = f_entry[0]
                    self.entry_point = f_entry.getProgramLocation().address.offset
                    logging.debug(
                        'Function %s found! Using entry point %08x',
                        f_entry.name, self.entry_point
                    )
                    break
            else:
                if entry_point is None:
                    logging.debug(
                        'No function named _start or _entry found, using current '
                        'cursor offset (%08x)', self.ghidra.cursor
                    )
                else:
                    logging.debug(
                        'No function named %s, _start or _entry found, using '
                        'current cursor (%08x)', entry_point, self.ghidra.cursor
                    )

                self.entry_point = self.ghidra.cursor
        else:
            self.entry_point = entry_point

        # Get the block that needs to be executed
        blk_code = self.ghidra.ns.currentProgram.memory.getBlock(
            self.ghidra._jaddr(self.entry_point)
        )
        self.code_size = blk_code.size

        code = self.ghidra.read_mem_block(blk_code, chunk_size=128*1024)
        if code == b"":
            raise ValueError(
                f"No data found in block containing entry point {self.entry_point:08x}"
            )

        # TODO: Make this Ghidra -> Qiling arch conversion more generic
        if self.arch.isr == "ARM" and self.arch.version == "Cortex":
            qiling_arch = QL_ARCH.CORTEX_M
        else:
            qiling_arch = self._uc_arch_translation[self.arch.isr]

        self.ql = qiling.Qiling(
            code=code,
            archtype=qiling_arch,
            ostype='linux',
            verbose=QL_VERBOSE.DEFAULT,
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
        # Calculate the starts and sizes of the memory blocks in Ghidra to reduce
        # the performance overhead of the ghidra bridge
        block_positions = self.ghidra.bridge.remote_eval(
            "[(seg.name, seg.getStart().getOffset(), seg.getSize(), seg.getPermissions(), seg.getData() if seg.isInitialized() else None) for seg in currentProgram.memory.blocks]"
        )

        for seg_name, start, size, perms, data in block_positions:
            if data is None and not seg_name.startswith('imem:'):
                continue

            if data is not None:
                datas = [(start, self.ql.mem.align_up(size, PAGE_SZ), data)]
            else:
                datas = []

            # Make sure the permissions are set properly
            # See: https://ghidra.re/ghidra_docs/api/ghidra/program/model/mem/MemoryBlock.html
            uc_perms = \
                (unicorn.UC_PROT_READ if perms & 1 else 0) | \
                (unicorn.UC_PROT_WRITE if perms & 2 else 0) | \
                (unicorn.UC_PROT_EXEC if perms & 4 else 0)

            assert not perms & 8, "Attempting to write volatile Ghidra memory region to non-volatile Qiling segment."

            # TODO: Make a pull request for the ret-sync Ghidra implementation
            # to recognize the right segment name.
            # If the segment contains our entrypoint use the name of the program
            # for it, this makes retsync recognize it for now.
            if start <= self.entry_point < end:
                seg_name = self.ghidra.ns.currentProgram.name

            self.map_region(start, size, perms=perms, name=seg_name)

            for data_start, data_size, data in datas:
                self.ql.mem.write(data_start, self.ghidra.read_mem_data(data, data_size))

    def map_region(self, offset, size, perms=unicorn.UC_PROT_ALL, name=None):
        # Align the offset and size to the page size, and try to map that.
        aligned_offset = self.ql.mem.align(offset, PAGE_SZ)
        size = self.ql.mem.align_up(size + offset - aligned_offset, PAGE_SZ)
        offset = aligned_offset

        if self.ql.mem.is_available(offset, size):
            self.ql.mem.map(offset, size, perms, info=name)
            return

        # The requested region apparently overlaps with an existing region, we
        # need to merge this with an existing block.
        cur_begin = offset
        cur_end = offset + size
        cur_perms = perms

        # 1. Find out which chunks(s) to merge this with
        intersect_maps = []
        intersect_data = []
        for begin, end, perms, *_ in self.ql.mem.map_info:
            # Check if this map entry intersects with (begin, end)
            if not ((begin <= cur_begin < end) or (begin < cur_end <= end) or (cur_begin <= begin < end <= cur_end)):
                continue

            cur_perms |= perms

            # There is an intersection
            intersect_maps.append((begin, end))
            intersect_data.append(self.ql.mem.read(begin, end - begin))

        # 2. Unmap those
        for begin, end in intersect_maps:
            self.ql.mem.unmap(begin, end - begin)

        # 3. Remap bigger chunk
        # TODO: Don't throw away the names
        first_addr = min(min(begin for begin, _ in intersect_maps), cur_begin)
        last_addr = max(max(end for _, end in intersect_maps), cur_end)

        self.ql.mem.map(first_addr, last_addr - first_addr, perms=perms)

        # 4. Rewrite unmapped data
        for (start, _), data in zip(intersect_maps, intersect_data):
            self.ql.mem.write(start, bytes(data))

    def hook_start_thumb(self, ql):
        ql.arch.regs.cpsr |= (1<<5)

    def load_extra_mappings(self, mappings):
        for offset,size in mappings.items():
            logging.debug('Mapping region for {} at 0x{:02x} (size: {:02x})'.format(offset, size))
            self.map_region(offset, size)

def main():
    args = ArgumentParser()
    args.add_argument('--entry_point', help='The entry point to start execution', default=None)
    args.add_argument('--hooks', help='The python file containing the hooks for the emulator', default=False)
    args.add_argument('--mappings', help='Extra memory mappings in JSON dict format', default=False)
    args.add_argument('--snapshot', help='A snapshot containing a previous state for the emulator',
                      default=None)
    args = args.parse_args()

    if args.mappings:
        with open(args.mappings, 'r', encoding='utf-8') as f_mappings:
            args.mappings = json.load(f_mappings)

    GhidraEmu(**vars(args))

if __name__ == '__main__':
    main()
