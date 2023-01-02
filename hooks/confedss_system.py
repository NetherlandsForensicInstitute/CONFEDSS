
import collections
import os

import hooks.symbolic as symbolic

class LoopDetector:
    # This value might need to be tuned further. Setting it lower might lead to
    # quicker loop detection, but also more false positives, while increasing
    # this threshold will cause loops to take longer to be detected.
    INSN_THRESHOLD: int = 0x1_0000

    def __init__(self):
        self.counter = collections.Counter()

    def insn_hook(self, ql, address: int, size: int) -> None:

        # TODO: Find a more generic way to avoid loops
        # if 0x324024 <= address <= 0x3240e8 or 0x323f40 <= address <= 0x324020:
        #     # memset and memcpy - skip these loops
        #     return

        # TODO: This might use a lot of memory if there are many unique addresses
        # that are visited by the program counter.
        # Maybe use some function to group addresses (i.e. address >> 4), at the
        # cost of accuracy.
        self.counter[address] += 1

        if self.counter[address] > LoopDetector.INSN_THRESHOLD:
            print(f"[i] LOOP DETECTED at {address:08x}! {self.counter[address]}")
            handle_wrong_turn(ql, address, size)


def mmio_mem_write(*args):
    # Nothing to do at a memory write - this memory is volatile, so saving the
    # value seems useless...
    return


def invalid_mem_read(base: int):
    """
    Returns a peripheral read handler function.
    """
    def f(ql, offset, size):
        # Keep track of the total number of peripheral reads that occurred
        global NUM_READS
        NUM_READS += 1

        value = symbolic.find_memory_value(ql, ql.arch.regs.arch_pc, offset + base, size)
        if value is None:
            return 0
        return value

    return f


def handle_wrong_turn(ql, address, size):
    """
    We took a wrong turn somewhere - backtrack!
    """
    # FIXME: 'ql.arch.regs.lr' is not arch-independent. Unfortunately, the link
    # register does not exist on some architectures, which means we might have
    # to resort to reading stack frames...
    print(f"[!] Wrong turn at 0x{address:08x} <- {ql.arch.regs.lr:08x}")
    symbolic.backtrack(ql)

    # FIXME: We should probably reset the loop detection as well...


def init(ql, ghidra, handle_interrupt=None, debug=None):
    # initialise the symbolic execution
    symbolic.init(ql, ghidra)

    if handle_interrupt is None:
        # Provide a default interrupt handler
        def handle_interrupt(ql: qiling.Qiling, intno: int):
            """
            Default interrupt handler - log unknown instructions and ignore all
            interrupts. This implementation assumes that instructions are 4
            bytes long.
            """
            if intno == 1:
                # FIXME: Increase the maximum instruction length, since some
                # architectures have much longer instructions...
                MAX_INSN_LEN = 4  # bytes

                insn_data = ql.mem.read(ql.arch.regs.arch_pc, MAX_INSN_LEN)
                disassembled = next(ql.disassembler.disasm(insn_data, ql.arch.regs.arch_pc, count=1))

                # TODO: Manually emulate these instructions
                print(f"[!] Interrupt 1 (unknown instruction?) happened at {ql.arch.regs.arch_pc:08x}: {disassembled}")
            else:
                print(f"[!] Unknown interrupt {intno} happened at {ql.arch.regs.arch_pc:08x}")

            # FIXME: This assumes the current instruction is 4 bytes long. This
            # is clearly not always the case.
            ql.arch.regs.arch_pc += 4

    ql.hook_intr(handle_interrupt)

    # Find the regions that are not already mapped and fill them with peripheral
    # regions.
    last_end = 0
    for (begin, end, *_) in sorted(ql.mem.map_info):
        if begin == last_end:  # consecutive
            last_end = end
            continue

        # unmapped region [last_end, begin) - make all reads and writes use
        ql.mem.map_mmio(addr=last_end, size=begin - last_end, read_cb=invalid_mem_read(last_end), write_cb=mmio_mem_write)
        ql.hook_code(handle_wrong_turn, begin=last_end, end=begin - 1)
        last_end = end

    # HACK: This assumes 32 bit address space
    if last_end != 0x1_0000_0000:
        ql.mem.map_mmio(addr=last_end, size=0x1_0000_0000 - last_end, read_cb=invalid_mem_read(last_end), write_cb=mmio_mem_write)
        ql.hook_code(handle_wrong_turn, begin=last_end, end=0x1_0000_0000 - 1)

    ############################################################################
    # General setup for the part that is to be emulated
    ###

    # TODO: Make this more generic - i.e. get all non-executable addresses
    # ql.hook_code(handle_wrong_turn, begin=0, end=0x2f_ffff)
    # ql.hook_code(handle_wrong_turn, begin=0x33_0000, end=0xffff_ffff)

    for addr in symbolic.get_avoid_addrs(ql):
        print(f"[i] Avoiding {addr:08x}")
        ql.hook_code(handle_wrong_turn, begin=addr, end=addr)

    ############################################################################
    # Setup for loop detection
    ####
    print(f"[i] Setting up loop detection")
    global loop_detector

    loop_detector = LoopDetector()

    ql.hook_code(loop_detector.insn_hook)
