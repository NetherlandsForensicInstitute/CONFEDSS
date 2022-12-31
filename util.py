import angr
import qiling
import unicorn

import typing

from qiling.arch.arm import QlArchARM
from qiling.arch.arm64 import QlArchARM64
from qiling.arch.cortex_m import QlArchCORTEX_M

class Tactic:
    """
    The abstract base class for all tactics. This class defines three functions
    that all subclasses must implement. The first function is the equality
    operator. The second function is named 'get_find_addrs' and its return value
    is passed on to angr as the goal addresses for the symbolic execution.
    Finally, there is the 'check_if_state_is_ok', which returns whether the
    tactic considers the passed state a 'good' state.
    """
    def __eq__(self, other):
        """
        Returns whether this tactic and 'other' are "the same".
        """
        raise NotImplementedError("Tactic should implement '__eq__'")

    def get_find_addrs(self, angr_project: angr.project.Project, ghidra: 'GhidraEmu', cur_func: 'ghidra.*.FunctionDB', code_addr: int, ql: 'Qiling') -> [int]:
        """
        Returns a list of addrs that this heuristic wants to go towards.
        """
        raise NotImplementedError("Tactic should implement 'get_find_addrs'")

    def check_if_state_is_ok(self, state: angr.sim_state.SimState) -> bool:
        """
        Checks if a state is okay for this heuristic. Note that this can change
        the state by adding constraints.
        """
        raise NotImplementedError("Tactic should implement 'check_if_state_is_ok'")

class GoalTactic(Tactic):
    def __init__(self, addr):
        self._goal_addr = addr

    def __eq__(self, other):
        return type(other) == type(self) and self._goal_addr == other._goal_addr

    def get_find_addrs(self, angr_project: angr.project.Project, ghidra: 'GhidraEmu', cur_func: 'ghidra.*.FunctionDB', code_addr: int, ql: 'Qiling') -> [int]:
        return [self._goal_addr]

    def check_if_state_is_ok(self, state: angr.sim_state.SimState) -> bool:
        return True

    def __str__(self):
        return f"Get to addr {self._goal_addr:08x}"

class ReturnTactic(Tactic):
    def __init__(self, value: typing.Optional[int]):
        self._return_value = value
        self._angr_project = None
        self._cur_entry = None

    def __eq__(self, other):
        return type(other) == type(self) and self._return_value == other._return_value

    def get_find_addrs(self, angr_project: angr.project.Project, ghidra: 'GhidraEmu', cur_func: 'ghidra.*.FunctionDB', code_addr: int, ql: 'Qiling') -> [int]:
        """
        Returns the address of the end of the function that contains code_addr.
        """
        # Save angr project for use in state check function
        self._angr_project = angr_project
        self._cur_entry = cur_func.getEntryPoint().getOffset()

        def last_addr_of_block(block):
            nonlocal ql

            # Use Qiling to get a disassembler that's configured properly and
            # the data that belongs to this basic block.
            md = ql.arch.disassembler
            block_data = ql.mem.read(block.addr, block.size)

            # Get the address of the last instruction (the return) of block
            *_, (last_insn_addr, *_) = md.disasm_lite(block_data, block.addr)
            return last_insn_addr


        def get_exits_of_function(addr: int) -> {int}:
            """
            Recursively calculates the set of all 'ret' instructions that return to
            this function's caller. This includes 'ret' instructions of tail calls
            :addr: has to be an entrypoint
            """
            # TODO: Make sure this works with functions that tail-call themselves.

            nonlocal angr_project, last_addr_of_block, ghidra

            try:
                angr_func = angr_project.kb.functions[addr]
            except KeyError:  # angr does not yet know about this function
                # Ask ghidra about the function
                cur_func = ghidra.get_function_name_by_address(addr)
                func_addrs = cur_func.getBody()
                min_addr = func_addrs.getMinAddress().getOffset()
                max_addr = func_addrs.getMaxAddress().getOffset()

                # Ask angr about the exit points
                _ = angr_project.analyses.CFGFast(regions=[(min_addr, max_addr)])
                try:
                    angr_func = angr_project.kb.functions[addr]
                except KeyError:
                    return set()

            # Normal returns
            ret_addrs = {last_addr_of_block(ret_site) for ret_site in angr_func.ret_sites}

            # Support tail calls (jumpouts)
            for tail_jump_block in angr_func.jumpout_sites:
                for tail_jump_target in tail_jump_block.successors():
                    ret_addrs |= get_exits_of_function(tail_jump_target.addr)

            # callout_sites: These functions never return, so they don't need to
            # be included.

            # TODO: Support retout_sites (what code pattern causes these?)
            return ret_addrs

        ret_addrs = list(get_exits_of_function(cur_func.getEntryPoint().getOffset()))

        return ret_addrs

    def check_if_state_is_ok(self, state: angr.sim_state.SimState) -> bool:
        if self._return_value is None:
            return True

        # TODO: We're assuming that the current function returns an integer. Is
        # this a problem?
        calling_convention = self._angr_project.kb.functions[self._cur_entry].calling_convention

        if calling_convention is None:
            calling_convention = self._angr_project.factory.cc()

        long_type = angr.types.parse_type('long')
        loc = calling_convention.return_val(long_type, perspective_returned=False)

        state.solver.add(loc == self._return_value)

        return state.solver.satisfiable()

    def __str__(self):
        return f"Return value {self._return_value}"

class DummyTactic(Tactic):

    def __eq__(self, other):
        return type(other) == type(self)

    def get_find_addrs(self, angr_project: angr.project.Project, ghidra: 'GhidraEmu', cur_func: 'ghidra.*.FunctionDB', code_addr: int, ql: 'Qiling') -> [int]:
        return [code_addr]

    def check_if_state_is_ok(self, state: angr.sim_state.SimState) -> bool:
        return True

    def __str__(self):
        return "Get to next address"

class StepsTactic(Tactic):
    """
    A tactic that tries to get N steps ahead. This functions similarly to the
    process described in Laelaps, Figure 2.
    Paper: https://dl.acm.org/doi/10.1145/3427228.3427280
    '_max_depth' is called 'Forward_Depth' by Laelaps.
    """

    def __init__(self, max_depth: int):
        self._max_depth = max_depth

    def __eq__(self, other):
        return type(other) == type(self) and self._max_depth == other._max_depth

    def get_find_addrs(self, angr_project: angr.project.Project, ghidra: 'GhidraEmu', cur_func: 'ghidra.*.FunctionDB', code_addr: int, ql: 'Qiling') -> [int]:
        # HACK: This returns a function instead of a list of addresses, but
        # angr's 'find' method can handle a function as well, so it's fine...
        # FIXME: This breaks the type signature
        return lambda s: s.history.depth >= self._max_depth

    def check_if_state_is_ok(self, state: angr.sim_state.SimState) -> bool:
        return True

    def __str__(self):
        return f"Look {self._max_depth} steps ahead"

def copy_state_to_angr(angr_state: angr.sim_state.SimState, ql: qiling.core.Qiling, p) -> None:
    """
    Copies the state of qiling over to angr.
    """

    if type(ql.arch) == QlArchARM64:  # ARM64
        # The registers are set in the order in which they appear in the 'arch_aarch64.py'
        # file in angr/archinfo:
        # https://github.com/angr/archinfo/blob/master/archinfo/arch_aarch64.py#L74
        # NOTE: Some registers are missing (mainly some special purpose registers)
        # because Unicorn doesn't support them...
        for i in range(31):
            setattr(angr_state.regs, f"x{i}", ql.arch.regs.read(f"x{i}"))

        angr_state.regs.xsp = ql.arch.regs.arch_sp
        angr_state.regs.pc = ql.arch.regs.arch_pc

        for i in range(32):
            setattr(angr_state.regs, f"q{i}", ql.arch.regs.read(f"q{i}"))

    elif type(ql.arch) == QlArchARM:
        # https://github.com/angr/archinfo/blob/master/archinfo/arch_arm.py#L265
        for i in range(13):
            setattr(angr_state.regs, f"r{i}", ql.arch.regs.read(f"r{i}"))

        angr_state.regs.sp = ql.arch.regs.arch_sp  # r13
        angr_state.regs.lr = ql.arch.regs.lr
        angr_state.regs.pc = ql.arch.regs.arch_pc  # r15

        for i in range(32):
            setattr(angr_state.regs, f"d{i}", ql.arch.regs.read(f"d{i}"))

        # angr_state.regs.fpscr = ql.arch.regs.read("fpscr")

        # Registers Qiling knows but angr doesn't:
        # - fpexc
        # - cpsr
        # - c1_c0_2
        # - c13_c0_3

        # Registers angr knows but Qiling doesn't:
        # - cc_op
        # - cc_dep1
        # - cc_dep2
        # - cc_ndep
        # - qflag32
        # - geflag0
        # - geflag1
        # - geflag2
        # - geflag3
        # - emnote
        # - cmstart
        # - cmlen
        # - nraddr
        # - ip_at_syscall
        # - tpidruro
        # - itstate

    elif type(ql.arch) == QlArchCORTEX_M:  # Cortex M
        for i in range(13):
            setattr(angr_state.regs, f"r{i}", ql.arch.regs.read(f"r{i}"))

        angr_state.regs.sp = ql.arch.regs.arch_sp
        angr_state.regs.lr = ql.arch.regs.lr
        angr_state.regs.pc = ql.arch.regs.arch_pc

        for i in range(16):
            setattr(angr_state.regs, f"d{i}", ql.arch.regs.read(f"d{i}"))

        angr_state.regs.primask = ql.arch.regs.primask
        angr_state.regs.faultmask = ql.arch.regs.faultmask
        angr_state.regs.basepri = ql.arch.regs.basepri
        angr_state.regs.control = ql.arch.regs.control

        # Non-artificial registers angr knows, but Qiling doesn't:
        # - fpscr
        # - iepsr
    else:
        raise NotImplementedError(f"{ql.arch!r} is not yet supported for copying state from qiling to angr.")

    # TODO: Optimise this - removing everything might not be necessary every time.
    # The removal process is quite inefficient - it loops over the memory
    # backers twice for every removal, making this loop quadratic in the number
    # of backers.

    # Remove current memory backers
    for start, _ in p.loader.memory.backers():
        p.loader.memory.remove_backer(start)

    # Copy over all mapped segments
    for begin, end, _, _, is_mmio in sorted(ql.mem.map_info):
        # Don't copy over MMIO segments.
        # We do copy over the ROM (even though it is already there) because its
        # pages might overlap with non-ROM.
        if is_mmio:
            continue

        p.loader.memory.add_backer(begin, ql.mem.read(begin, end - begin))
