import pickle

def print_hook(ql):
    print(f'Address hit: {hex(ql.arch.regs.pc)}')

def invalid_mem_write(ql, access, addr, size, value):
    print(f'[W] Invalid mem write at {hex(addr)}!')

def invalid_mem_read(ql, access, addr, size, value):
    print(f'[W] Invalid mem read at {hex(addr)}')

def create_snapshot(ql):
    with open('snapshot_0x100090.bin', 'wb') as f_snapshot:
        pickle.dump(ql.save(), f_snapshot)

def insert_hooks(ql, ghidra):
    # Write some address before starting
    ql.mem.write(0x100020, int.to_bytes(0x40, 4, 'little'))

    # Hook a certain address in execution
    ql.hook_address(print_hook, 0x100000)
    ql.hook_address(create_snapshot, 0x100090)

    ql.hook_mem_write_invalid(invalid_mem_write)
    ql.hook_mem_read_invalid(invalid_mem_read)

