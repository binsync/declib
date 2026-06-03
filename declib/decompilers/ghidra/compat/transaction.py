from functools import wraps
import typing

if typing.TYPE_CHECKING:
    from ..interface import GhidraDecompilerInterface


class Transaction:
    def __init__(self, flat_api, msg="BinSync transaction"):
        self._trans_msg = msg
        self._flat_api = flat_api
        self.trans_id = None

    def __enter__(self):
        self.trans_id = self._flat_api.currentProgram.startTransaction(self._trans_msg)

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._flat_api.currentProgram.endTransaction(self.trans_id, True)


def ghidra_transaction(f):
    @wraps(f)
    def _ghidra_transaction(self: "GhidraDecompilerInterface", *args, **kwargs):
        with Transaction(flat_api=self.flat_api, msg=f"BS::{f.__name__}(args={args})"):
            ret_val = f(self, *args, **kwargs)

        return ret_val

    return _ghidra_transaction

