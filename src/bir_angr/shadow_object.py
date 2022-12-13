import logging

from cle.backends import Backend, Symbol, Segment, SymbolType
from cle.backends.relocation import Relocation
from cle.utils import ALIGN_UP
from cle.errors import CLEOperationError, CLEError
from cle.address_translator import AT

l = logging.getLogger(name=__name__)



class ShadowObject(Backend):
    def __init__(self, loader, map_size=0x10000):
        super().__init__('cle##shadow', None, loader=loader)
        self.map_size = map_size
        self.set_arch(loader.main_object.arch)
        self.memory.add_backer(0, bytes(map_size))
        self.provides = 'shadow space'
        self.pic = True

    def add_name(self, name, addr):
        self._symbol_cache[name] = Symbol(self, name, AT.from_mva(addr, self).to_rva(), 1, SymbolType.TYPE_FUNCTION)

    @property
    def max_addr(self):
        return AT.from_rva(self.map_size - 1, self).to_mva()
