import ghidra_bridge
from tqdm import tqdm
from io import BytesIO
from enum import Enum
from collections import namedtuple as _nt

class AttrDict(dict):
    def __init__(self, *args, **kwargs):
        super(AttrDict, self).__init__(*args, **kwargs)
        self.__dict__ = self

class Endianness(Enum):
        LE = 'little'
        BE = 'big'

_nt_arch_params = _nt('ArchParams', 'isr endianness bits version')

class Ghidra:

    def __init__(self):
        self.ns = AttrDict()  # Create our own namespace to keep junk out of the global one
        self.bridge = ghidra_bridge.GhidraBridge(namespace=self.ns)
        self.tool = self.ns.state.getTool()
        self.codevwr_svc = self.tool.getService(self.ns.ghidra.app.services.CodeViewerService)
        self.listing_pnl = self.codevwr_svc.getListingPanel()
        self.function_mgr = self.ns.currentProgram.getFunctionManager()
        self.symbol_manager = self.ns.currentProgram.getSymbolTable()
        self.arch = self.get_arch()
        self._reg_tmode = self.ns.currentProgram.getLanguage().getRegister('tmode') if self.arch.isr in ['ARM', 'AARCH64'] and self.arch.bits == 32 else None

    def _jaddr(self, addr):
        return self.ns.toAddr(addr)

    def get_arch(self):
        arch, endianness, bits, version = self.ns.currentProgram.getCompilerSpec().getLanguage().toString().split('/')
        return _nt_arch_params(arch, Endianness(endianness), int(bits), version)

    @property
    def cursor(self):
        return self.listing_pnl.getCursorLocation().address.offset

    @cursor.setter
    def cursor(self, addr, goto=True):
        self.listing_pnl.setCursorPosition(self.ns.ghidra.program.util.ProgramLocation(self.ns.currentProgram,
                                                                                       self._jaddr(addr)))
        if goto:
            self.listing_pnl.goTo(self._jaddr(addr))

    def get_function_name_by_address(self, addr):
        addr = self._jaddr(addr) if type(addr) == int else addr
        return self.function_mgr.getFunctionContaining(addr)

    def _jarray2bytes(self, jarray):
        return bytes(map(ord, jarray.tostring()))

    def read_mem_block(self, blk, chunk_size=128*1024):
        return self.read_mem_data(blk.getData(), blk.getSize(), chunk_size)

    def read_mem_data(self, h_data, sz, chunk_size=128*1024):
        b_data = BytesIO()
        p = tqdm(total=sz, unit_scale=1, unit=' bytes')
        for _ in range(0, sz, chunk_size):
            b_data.write(self._jarray2bytes(h_data.readNBytes(chunk_size)))
            p.update(chunk_size)
        p.refresh()
        b_data.seek(0)
        return b_data.read()

    def is_thumb(self, addr):
        if self._reg_tmode:
            tmode_val = self.ns.currentProgram.programContext.getRegisterValue(self._reg_tmode, self.ns.toAddr(addr))
            return bool(tmode_val.unsignedValueIgnoreMask)
        else:
            return False




