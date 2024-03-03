import logging
import angr

from angr.storage.memory_mixins import DefaultMemory
from angr.errors import SimMemoryMissingError

l = logging.getLogger(__name__)


ONE_FILL_UNCONSTRAINED_MEMORY = "ONE_FILL_UNCONSTRAINED_MEMORY"


class DefaultMemoryFiller(DefaultMemory):
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
            elif self.category == 'mem' and ONE_FILL_UNCONSTRAINED_MEMORY in self.state.options:
                if bits == 8:
                     val = self.state.solver.BVV(0x01, bits)
                elif bits == 16:
                    val = self.state.solver.BVV(0x0101, bits)
                elif bits == 24:
                    val = self.state.solver.BVV(0x010101, bits)
                elif bits == 32:
                    val = self.state.solver.BVV(0x01010101, bits)
                elif bits == 40:
                    val = self.state.solver.BVV(0x0101010101, bits)
                elif bits == 48:
                    val = self.state.solver.BVV(0x010101010101, bits)
                elif bits == 56:
                    val = self.state.solver.BVV(0x01010101010101, bits)
                elif bits == 64:
                    val = self.state.solver.BVV(0x0101010101010101, bits)
                else:
                    raise Exception(f"Unexpected memory load of: {bits}")
                return val

        if self.category == 'reg' and type(addr) is int and addr == self.state.arch.ip_offset:
            # short-circuit this pathological case
            return self.state.solver.BVV(0, self.state.arch.bits)

        raise Exception("DefaultMemoryFiller failure")

