import qiling
import angr
import claripy
import archinfo

import collections
import logging
import typing
import os
import tempfile

from util import Tactic, DummyTactic, GoalTactic, ReturnTactic, StepsTactic, copy_state_to_angr

# This is structured as a script with functions. In retrospect, it might have
# been nicer if this was a class instead. Then the global variables could just
# become instance variables.

# The ghidra object that can be used to communicate with Ghidra
GLOB_GHIDRA = None
# The number of peripheral reads that occurred, or None if not yet initialised
NUM_READS = None
# The angr project that can be used for symbolic execution
ANGR_PROJECT = None
# This 'TEMP_MESSAGE' field is used by the backtracker to set a one-time message
# for the read resolver. TODO: Refactor this into something nicer.
TEMP_MESSAGE = None
# The history stack
HISTORY = collections.deque()

# Make sure angr logging is quiet
logging.getLogger('angr').setLevel("CRITICAL")
logging.getLogger('cle').setLevel("CRITICAL")
logging.getLogger('pyvex').setLevel("CRITICAL")
logging.getLogger('pyvex.lifting.libvex').setLevel("CRITICAL")

def init(ql: qiling.core.Qiling, ghidra):
    global ANGR_PROJECT, GLOB_GHIDRA, NUM_READS
    GLOB_GHIDRA = ghidra

    # Load the executable memory block into angr
    mem_map = GLOB_GHIDRA.ns.currentProgram.getMemory()
    for block in mem_map.getBlocks():
        if block.isExecute():
            break
    else:
        print("[!] No executable block found in Ghidra!")
        sys.exit(1)

    print(f"[i] Loading block {block.getName()!r}")

    # Unfortunately, it seems the fastest way to set up angr is write the code
    # to an external file, and then give angr the file path. As such, we write
    # the executable block to a temporary file and then give that file to angr.
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(GLOB_GHIDRA.read_mem_block(block))
        rom_path = f.name

    print(f"[i] Saved block to temp path {rom_path!r}")

    # Guess the architecture that angr should use based on the architecture that
    # qiling is using
    arch = get_architecture(ql)

    print(f"[i] Got architecture {arch}")

    ANGR_PROJECT = angr.Project(
        rom_path,
        load_options={
            'main_opts': {
                'backend': 'blob',
                'arch': arch,
                'base_addr': block.getStart().getOffset(),
            },
            'auto_load_libs': False,  # EXPLORE_OPT["auto_load_libs"]
        }
    )

    # Keep track of the total number of peripheral reads
    NUM_READS = 0

###############################################################################
################################# VALUE FINDER ################################
###############################################################################

def find_memory_value(ql: qiling.core.Qiling, pc_addr: int, read_addr: int, read_size: int) -> int:
    """
    Returns a good memory value for the read that happens at address {pc_addr}.
    If this returns None, we have backtracked.
    """

    print(f"[i] Peripheral read from address {pc_addr:08x} to address {read_addr:08x}")

    # Keep track of the total number of peripheral reads
    global NUM_READS
    NUM_READS += 1

    global GLOB_GHIDRA

    if GLOB_GHIDRA is None:
        raise ValueError(f"Ghidra instance was not set!")

    # We need to know the current function for the ReturnTactics. This could
    # probably only be
    cur_func = GLOB_GHIDRA.get_function_name_by_address(pc_addr)
    if cur_func is None:
        print(f"[!] ERROR: Not in any function (according to Ghidra)")
        os._exit(1)

    # Get the used tactics and values from the backtracking if there are any.
    message = get_message()
    if message is None:
        used_tactics = []
        used_values = []
    else:
        used_tactics, used_values = message

    ############################################################################

    global ANGR_PROJECT

    # TODO: Improve handling multiple symbolic memory reads at the same time.
    # Currently, angr resolves all reads it comes across symbolically, but we
    # only use the information it finds about the first read. It might be a good
    # idea to somehow cache these results.
    angr_state = ANGR_PROJECT.factory.blank_state()

    # Copy over the qiling state to angr. This copies over all register values and
    # all (relevant) memory values.
    copy_state_to_angr(angr_state, ql, ANGR_PROJECT)

    # Set memory value to a symbolic value
    memory_value = claripy.BVS("memory_location", read_size * 8)
    angr_state.memory.store(read_addr, memory_value, endness=archinfo.Endness.LE)

    # Make sure we return a different value (the used value[s] lead to some bad
    # state)
    for used_value in used_values:
        angr_state.solver.add( memory_value != used_value )

    value = None
    while value is None:
        tactic = select_tactic(ql, pc_addr, read_addr, used_tactics, cur_func)

        if tactic is None:
            print(f"[i]   Tactic is None -> Backtrack")
            backtrack(ql)
            return None

        # Avoid doing any symbolic execution when the chosen tactic is a
        # DummyTactic.
        if not isinstance(tactic, DummyTactic):
            sim_mgr = ANGR_PROJECT.factory.simulation_manager(angr_state)
            result = sim_mgr.explore(
                find=tactic.get_find_addrs(ANGR_PROJECT, GLOB_GHIDRA, cur_func, pc_addr, ql),
                avoid=get_avoid_addrs(ql),
            )

            value = select_value(result, tactic, memory_value)
        else:
            # If we don't care about the value, just use 0
            value = 0

        if value is None:
            # Could not find any states that satisfy the constraints. Select a
            # different tactic, and exclude the currently selected tactic.
            print(f"[!]   Unsat: avoid tactic and try again")
            used_tactics.append(tactic)

    add_to_history(ql, used_tactics + [tactic], used_values + [value])
    return value

def select_value(result: angr.sim_manager.SimulationManager, tactic: Tactic, memory_value: claripy.BV) -> typing.Optional[int]:
    """
    Returns a possible value for memory_value or None if no value is possible.
    """
    for state in result.found:
        # Check if we can constrain return value to 0
        if not tactic.check_if_state_is_ok(state):
            continue

        # TODO: Maybe use a different way to select a value. Another way could
        # be to have multiple tactics and check what values are in their
        # intersection.
        values = state.solver.eval_upto(memory_value, 1)

        return values[0]

    return None

# sliding window
recent_reads = [()] * 10

def select_tactic(ql: qiling.core.Qiling, pc_addr: int, read_addr: int, used_tactics: [Tactic], cur_func) -> Tactic:
    """
    Select a good tactic. Different tactics:
    - ReturnTactic(x): Set return value to x
    - GoalTactic(addr): Get to addr
    - DistanceTactic(goal): Get closest to addr goal
    - DummyTactic(): Don't do symbolic execution and just return 0
    - StepsTactic(depth): Explore for a depth of 'depth' steps
    """

    global recent_reads

    # It keeps asking for this address... time to escalate
    escalating = all([x[:2] == (pc_addr, read_addr) for x in recent_reads])

    if not escalating:
        # If we're not stuck, read user comments in Ghidra to determine the
        # right tactic.

        # TODO: The communication with Ghidra causes some overhead - this might
        # be reduced by caching the comments in the 'init' function and caching
        # those results.

        # Adapted from: https://github.com/HackOvert/GhidraSnippets#get-specific-comment-types-for-all-functions
        global GLOB_GHIDRA

        listing = GLOB_GHIDRA.ns.currentProgram.getListing()

        # See: https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/CodeUnit.html
        EOL_COMMENT = 0
        PLATE_COMMENT = 3
        for comment_type, addr, used_func in ((EOL_COMMENT, GLOB_GHIDRA._jaddr(pc_addr), False), (PLATE_COMMENT, cur_func.getEntryPoint(), True)):
            comment = listing.getComment(comment_type, addr)
            if comment is None:
                continue

            # A tactic was manually specified - try to parse it. These
            # patterns are supported:
            #
            # 'return == <value> .*' -> ReturnTactic(value)
            # 'return' -> ReturnTactic(None)
            # 'step <n> .*' -> StepsTactic(n)
            # 'goto (0x)?<addr> .*' -> GoalTactic(addr)

            candidate = None
            if comment.startswith("return == "):  # 'return == <value> .*'
                try:
                    retval = int(comment.split("return == ", 1)[1].split()[0])
                except ValueError:
                    # int() failed - The value was not an integer in base 10
                    pass
                else:
                    candidate = ReturnTactic(value = retval)
                    print(f"[d] Manual comment parsed: return {retval}: {candidate}")

            if comment == "return":  # 'return'
                candidate = ReturnTactic(value = None)
                print(f"[d] Manual comment parsed: return {candidate}")

            if comment.startswith("goto "):  # 'goto (0x)?<addr> .*'
                try:
                    goal_addr = int(comment.split("goto ", 1)[1].split()[0], 16)
                except ValueError:
                    # int() failed - The value was not an integer in base 16
                    # A '0x' prefix is optional
                    pass
                else:
                    candidate = GoalTactic(addr = goal_addr)
                    print(f"[d] Manual comment parsed: {candidate}")

            if comment.startswith("step "):
                try:
                    goal_addr = int(comment.split("step ", 1)[1].split()[0])
                except ValueError:
                    # int() failed - The value was not an integer
                    pass
                else:
                    candidate = StepsTactic(addr = goal_addr)
                    print(f"[d] Manual comment parsed: {candidate}")


            if candidate is not None:
                # FIXME: This sliding window implementation is quite inefficient
                recent_reads = recent_reads[1:] + [(pc_addr, read_addr, candidate)]
                return candidate

            print(f"[d] Manual comment ignored: {comment!r}")

    # The possible tactics that can be employed. Every read should be able
    # to be solved with a tactic from this list.
    # The escalation code makes several assumptions:
    # - This list is not longer than 'recent_reads'
    # - This list is sorted on increasing 'difficulty', whatever that means.
    # - Tactics are tried in order - trying index 1 implies we tried index 0
    #   before (or we can be absolutely sure that the previous tactic is unable
    #   to solve this read).
    candidates = [
        DummyTactic(),
        StepsTactic(max_depth = 5),
        StepsTactic(max_depth = 10),
        ReturnTactic(value = 0),
        ReturnTactic(value = 1),
        ReturnTactic(value = None),
    ]

    if escalating:
        # If we're escalating, make sure we use an even heavier tactic than
        # the one we applied previously. If we used a manual tactic, that might
        # not be in the 'candidates' list, so just discard those.
        escalating_used_tactics = [
            candidates.index(c)
            for (a, b, c) in recent_reads
            if (a, b) == (pc_addr, read_addr) and c in candidates
        ]

        if not escalating_used_tactics:  # We only used manual tactics
            max_tactic_idx = 0
        else:
            max_tactic_idx = max(escalating_used_tactics)
    else:
        max_tactic_idx = None

    for candidate_idx, candidate in enumerate(candidates):
        # check that this candidate is not in the used_tactics
        if candidate in used_tactics:
            continue

        if (not escalating) or candidate_idx > max_tactic_idx:
            # use this candidate
            break

    else:
        print(f"[!] All tactics were used. Backtracking...")
        return None

    # Don't update 'recent_reads' when we're inside the sleep function. If we
    # do update the 'recent_reads' variable, this will avoid the escalation of
    # surrounding reads.
    # TODO: This should be caught in a more generic way. Maybe by asking Ghidra
    # what function is named 'sleep'?
    # This is a broader issue anyway, that seems inherent to this method. It
    # might even be impossible to solve without resorting to full symbolic
    # execution.

    # if ...:
    #    return ReturnTactic(value = None)

    print(f"[i]   i: {candidate_idx} e: {escalating}")
    candidate = candidates[candidate_idx]

    # FIXME: This sliding window implementation is quite inefficient - a fixed
    # array with a sliding index is a more memory-efficient way to do this
    recent_reads = recent_reads[1:] + [(pc_addr, read_addr, candidate)]

    return candidate

def get_architecture(ql):
    """
    Returns the angr archinfo architecture that Qiling is running on. Raises
    NotImplementedError if angr doesn't support the Qiling arch (RISCV[64] and
    EVM). Raises ValueError if an unknown Qiling arch is passed.
    """
    endness = {
        qiling.const.QL_ENDIAN.EL: archinfo.Endness.LE,
        qiling.const.QL_ENDIAN.EB: archinfo.Endness.BE,
    }[ql.arch.endian]

    if ql.arch.type in (qiling.const.QL_ARCH.X86, qiling.const.QL_ARCH.A8086, qiling.const.QL_ARCH.X8664):
        arch = archinfo.ArchX86(endness)
    elif ql.arch.type == qiling.const.QL_ARCH.ARM:
        arch = archinfo.ArchARM(endness)
    elif ql.arch.type == qiling.const.QL_ARCH.ARM64:
        arch = archinfo.ArchAArch64(endness)
    elif ql.arch.type == qiling.const.QL_ARCH.MIPS:
        class_ = {32: archinfo.ArchMIPS32, 64: archinfo.ArchMIPS64}[ql.arch.bits]
        arch = class_(endness)
    elif ql.arch.type == qiling.const.QL_ARCH.CORTEX_M:
        arch = archinfo.ArchARMCortexM(endness)
    elif ql.arch.type == qiling.const.QL_ARCH.PPC:
        class_ = {32: archinfo.ArchPPC32, 64: archinfo.ArchPPC64}[ql.arch.bits]
        arch = class_(endness)
    elif ql.arch.type == qiling.const.QL_ARCH.RISCV:
        raise NotImplementedError("angr does not support RISCV, so CONFEDSS doesn't either")
    elif ql.arch.type == qiling.const.QL_ARCH.RISCV64:
        raise NotImplementedError("angr does not support RISCV64, so CONFEDSS doesn't either")
    elif ql.arch.type == qiling.const.QL_ARCH.EVM:
        raise NotImplementedError("angr does not support EVM, so CONFEDSS doesn't either")
    else:
        raise ValueError(f"Unknown Qiling arch: {ql.arch!r} (type: {ql.arch.type!r})")

    return arch

def get_loop_instructions(ql, pc_addr) -> [bytes]:
    """
    Returns a bytes object containing the assembled loop instruction for the
    current architecture.
    """
    arch = get_architecture(ql)
    is_thumb = bool(pc_addr & 1)
    is_big_endian = ql.arch.endian == qiling.const.QL_ENDIAN.EB

    BE_thumb_map = {
        '<Arch ARMCortexM (BE)>':    [b'\xe7\xfe'],  # _0: b _0
        '<Arch ARMEL (BE)>':         [b'\xfe\xe7'],  # _0: b _0
        '<Arch ARMHF (BE)>':         [b'\xfe\xe7'],  # _0: b _0
    }

    LE_thumb_map = {
        '<Arch ARMCortexM (LE)>':    [b'\xfe\xe7'],  # _0: b _0
        '<Arch ARMEL (LE)>':         [b'\xfe\xe7'],  # _0: b _0
        '<Arch ARMHF (LE)>':         [b'\xfe\xe7'],  # _0: b _0
    }

    BE_map = {
        '<Arch ARMCortexM (BE)>':    [b'\xe7\xfe'],  # _0: b _0
        '<Arch ARMEL (BE)>':         [b'\xea\xff\xff\xfe'],  # _0: b _0
        '<Arch ARMHF (BE)>':         [b'\xea\xff\xff\xfe'],  # _0: b _0
        '<Arch PPC32 (BE)>':         [b'H\x00\x00\x00'],  # _0: b _0
        '<Arch PPC64 (BE)>':         [b'H\x00\x00\x00'],  # _0: b _0
        '<Arch MIPS32 (BE)>':        [b'\x10\x00\xff\xff\x00\x00\x00\x00'],  # _0: b _0
        '<Arch MIPS64 (BE)>':        [b'\x10\x00\xff\xff\x00\x00\x00\x00'],  # _0: b _0
        '<Arch S390X (BE)>':         [],  # S390X has no relative jump
    }

    LE_map = {
        '<Arch AARCH64 (LE)>':       [b'\x00\x00\x00\x14'],  # _0: b _0
        '<Arch AMD64 (LE)>':         [b'\xeb\xfe'],  # _0: jmp _0
        '<Arch ARMCortexM (LE)>':    [b'\xfe\xe7'],  # _0: b _0
        '<Arch ARMEL (LE)>':         [b'\xfe\xff\xff\xea'],  # _0: b _0
        '<Arch ARMHF (LE)>':         [b'\xfe\xff\xff\xea'],  # _0: b _0
        '<Arch AVR8 (LE)>':          [b'\xff\xef'],  # _0: rjmp _0
        '<Arch MIPS32 (LE)>':        [b'\xff\xff\x00\x10\x00\x00\x00\x00'],  # _0: b _0
        '<Arch MIPS64 (LE)>':        [b'\xff\xff\x00\x10\x00\x00\x00\x00'],  # _0: b _0
        # '<Arch PPC32 (LE)>':         [],  # ???
        '<Arch PPC64 (LE)>':         [b'\x00\x00\x00H'],  # _0: b _0
        # '<Arch Soot (LE)>':          [],  # ???
        '<Arch X86 (LE)>':           [b'\xeb\xfe'],  # _0: jmp _0
    }

    if is_thumb and is_big_endian:
        insn_map = BE_thumb_map
    elif is_thumb and not is_big_endian:
        insn_map = LE_thumb_map
    elif not is_thumb and is_big_endian:
        insn_map = BE_map
    else:
        insn_map = LE_map

    # HACK: This sucks and might break if archinfo is updated, but idk how to do
    # it in a better way...
    key = str(arch)
    return insn_map[key]

def get_avoid_addrs(ql: qiling.core.Qiling) -> [int]:
    """
    Returns a list of addresses that should be avoided.
    """
    # Get addresses of all the 'b <self>' instructions. We're probably also
    # hitting some (misaligned?) data, but the PC shouldn't be there anyway, so
    # we don't need to filter these out.
    loop_insns = get_loop_instructions(ql, ql.arch.regs.arch_pc)

    inf_loop_addrs = []
    for loop_insn in loop_insns:
        inf_loop_addrs += ql.mem.search(loop_insn)

    # Get addresses of panic handler functions
    global GLOB_GHIDRA

    prog = GLOB_GHIDRA.ns.currentProgram
    listing = prog.getListing()

    # We avoid all addresses with an EOL comment set to 'avoid'
    panic_addrs = []

    # Adapted from: https://github.com/HackOvert/GhidraSnippets#get-specific-comment-types-for-all-functions
    # See: https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/CodeUnit.html
    EOL_COMMENT = 0
    for addr in listing.getCommentAddressIterator(EOL_COMMENT, prog.getMemory(), True):
        comment = listing.getComment(EOL_COMMENT, addr)
        if comment == "avoid":
            panic_addrs.append(addr.getOffset())

    bad_addrs = inf_loop_addrs + panic_addrs

    return bad_addrs

###############################################################################
################################### HISTORY ###################################
###############################################################################

def set_message(x):
    global TEMP_MESSAGE
    # Make sure 'TEMP_MESSAGE' is empty
    assert TEMP_MESSAGE is None
    TEMP_MESSAGE = x

def get_message():
    global TEMP_MESSAGE
    x, TEMP_MESSAGE = TEMP_MESSAGE, None
    return x

def add_to_history(ql: qiling.core.Qiling, tactics: [Tactic], values: [int]) -> None:
    """
    This function adds a (qiling, tactic, value) tuple to the history
    """
    qiling_state = ql.save(reg=True, mem=True, cpu_context=True)
    HISTORY.append((
        qiling_state, tactics, values
    ))

def pop_from_history() -> (dict, [Tactic], [int]):
    """
    Pops the last history entry from history stack
    """
    return HISTORY.pop()

###############################################################################
################################ BACKUP SYSTEM ################################
###############################################################################

def backtrack(ql: qiling.core.Qiling):
    """
    Backtracks to latest symbolic execution point and tries a different
    strategy.
    """
    print(f"[i] Backtracking...")
    # 1. Pop data from history
    # TODO: Handle case of empty history
    ql_state, tactics, values = pop_from_history()

    # HACK: Clear mmio from the state. This is a workaround for https://github.com/qilingframework/qiling/issues/1136
    # The MMIO part of the state doesn't change anyway, and an error occurs when
    # we try to load a state with MMIO.
    ql_state["mem"]["mmio"] = []

    # 2. Restore emulator (re-resolves read)
    ql.restore(ql_state)

    # 3. Set up message to avoid the same tactic / value being used
    set_message((tactics, values))
