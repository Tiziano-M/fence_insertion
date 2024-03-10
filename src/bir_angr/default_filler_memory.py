import logging
import angr

from angr.storage.memory_mixins import DefaultMemory
from angr.errors import SimMemoryMissingError

l = logging.getLogger(__name__)


DEFVAL_FILL_UNCONSTRAINED_MEMORY = "DEFVAL_FILL_UNCONSTRAINED_MEMORY"
angr.sim_state_options.SimStateOptions.register_bool_option(DEFVAL_FILL_UNCONSTRAINED_MEMORY)

class DefaultMemoryFiller(DefaultMemory):
    def __init__(self, defval=None, **kwargs):
        super().__init__(**kwargs)
        self._defval = defval

    def _default_value(self, addr, size, name=None, inspect=True, events=True, key=None, fill_missing: bool=True, **kwargs):
        if self.state.project and self.state.project.concrete_target:
            mem = self.state.project.concrete_target.read_memory(addr, size)
            endness = kwargs["endness"]
            bvv = self.state.solver.BVV(mem)
            return bvv if endness == 'Iend_BE' else bvv.reversed

        if fill_missing is False:
            raise SimMemoryMissingError(addr, size)

        bits = size * self.state.arch.byte_width

        if type(addr) is int:
            if self.category == 'mem' and angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY in self.state.options:
                return self.state.solver.BVV(0, bits)
            elif self.category == 'reg' and angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS in self.state.options:
                return self.state.solver.BVV(0, bits)
            elif self.category == 'mem' and DEFVAL_FILL_UNCONSTRAINED_MEMORY in self.state.options:
                assert self._defval is not None
                if 8 <= bits <= 64 and bits % 8 == 0:
                    num_bytes = bits // 8
                    def_val_pattern = (self._defval & 0xFF).to_bytes(1, byteorder='little') * num_bytes
                    val = self.state.solver.BVV(def_val_pattern, bits)
                else:
                    raise Exception(f"Unexpected memory load of: {bits}")
                return val

        if self.category == 'reg' and type(addr) is int and addr == self.state.arch.ip_offset:
            # short-circuit this pathological case
            return self.state.solver.BVV(0, self.state.arch.bits)

        raise Exception("DefaultMemoryFiller failure")

    def copy(self, memo):
        o = super().copy(memo)
        o._defval = self._defval
        return o

