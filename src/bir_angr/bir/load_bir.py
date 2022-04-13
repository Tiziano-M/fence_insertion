from cle.backends import Blob, register_backend
from cle.backends.elf import ELF
from archinfo import arch_from_id
import logging

l = logging.getLogger("cle.blob")

__all__ = ('BIR',)

class BIR(ELF):
    """
    Representation of a binary blob, i.e. an executable in an unknown file format.
    """
    is_default = True

    def __init__(self, *args, offset=0, **kwargs):
        """
        Loader backend for BIR programs
        :param path: The file path
        :param offset: Skip this many bytes from the beginning of the file.
        """
        super(BIR, self).__init__(*args,
                arch=arch_from_id("bir"),
                offset=None,
                entry_point=0,
                **kwargs)
        self.os = "BIR"

    @staticmethod
    def is_compatible(stream):
        return True

register_backend("bir", BIR)
