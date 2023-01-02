import pickle

import hooks.confedss_system as confedss_system

def print_hook(ql):
    print(f'Address hit: {ql.arch.regs.arch_pc:x}')

def invalid_mem_write(ql, access, addr, size, value):
    print(f'[W] Invalid mem write at {addr:x}!')

def invalid_mem_read(ql, access, addr, size, value):
    print(f'[W] Invalid mem read at {addr:x}')

def create_snapshot(ql):
    with open('snapshot_0x100090.bin', 'wb') as f_snapshot:
        pickle.dump(ql.save(), f_snapshot)

def insert_hooks(ql, ghidra):
    # Initialise the CONFEDSS system
    # This automatically fills all unmapped memory with MMIO regions that use
    # symbolic execution to resolve a value is read from them.
    confedss_system.init(ql, ghidra)

    # Write some address before starting
    ql.mem.write(0x100020, int.to_bytes(0x40, 4, 'little'))

    # Hook a certain address in execution
    ql.hook_address(print_hook, 0x100000)
    ql.hook_address(create_snapshot, 0x100090)

    # When using the CONFEDSS system, these hooks will only produce extra
    # logging output. As such, it might be desirable to remove these hooks
    ql.hook_mem_write_invalid(invalid_mem_write)
    ql.hook_mem_read_invalid(invalid_mem_read)
