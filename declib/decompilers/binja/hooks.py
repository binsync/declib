from collections import defaultdict
from typing import Dict
import logging

from .interface import BinjaInterface, BN_AVAILABLE, VALID_FUNC_SYM_TYPES
if BN_AVAILABLE:
    import binaryninja
    from binaryninja.types import StructureType, EnumerationType
    from binaryninja import SymbolType
    from binaryninja.binaryview import BinaryDataNotification

from declib.artifacts import (
    FunctionHeader, FunctionArgument, GlobalVariable, StackVariable, Comment
)

l = logging.getLogger(__name__)


#
# Hooks (callbacks)
#

class DataMonitor(BinaryDataNotification):
    def __init__(self, view, interface):
        super().__init__()
        self._bv = view
        self._interface: BinjaInterface = interface
        self._changing_func_addr = None
        self._changing_func_pre_change = None
        self._seen_comments = defaultdict(dict)

    def function_updated(self, view, func_):
        # Updates that occur without a service request are requests for comment changes
        if self._changing_func_pre_change is None:
            #
            # comments
            #

            func_addr = func_.start
            current_comments = dict(func_.comments)
            prev_comments = self._seen_comments[func_addr]
            # Changes have only occurred when the comments we see before the change request are different
            # from the comments we see now (after the change request)
            if current_comments != prev_comments:

                # Find all the comments that may have been:
                # 1. Updated in-place
                # 2. Deteted
                for addr, prev_comment in prev_comments.items():
                    curr_comment = current_comments.get(addr, None)
                    # no change for this comment
                    if curr_comment == prev_comment:
                        continue

                    self._interface.comment_changed(
                        Comment(
                            addr,
                            str(curr_comment) if curr_comment else "",
                            decompiled=True,
                            func_addr=func_addr
                        ),
                        deleted=curr_comment is None,
                    )

                # Find any comment which was newly added in this change
                for addr, curr_comment in current_comments.items():
                    if addr in prev_comments:
                        continue

                    if curr_comment:
                        self._interface.comment_changed(
                            Comment(addr, str(curr_comment), decompiled=True, func_addr=func_addr)
                        )

                self._seen_comments[func_addr] = current_comments

        # service requested function only
        if self._changing_func_pre_change is not None and self._changing_func_addr == func_.start:
            l.debug("Update on %s being processed...", hex(self._changing_func_addr))
            self._changing_func_addr = None

            # convert to declib Function type for diffing
            bn_func = view.get_function_at(func_.start)
            bs_func = BinjaInterface.bn_func_to_bs(bn_func)
            current_comments = dict(bn_func.comments)

            #
            # header
            #

            # check if the headers differ
            # NOTE: function name done inside symbol update hook
            if self._changing_func_pre_change.header.diff(bs_func.header):
                old_header: FunctionHeader = self._changing_func_pre_change.header
                new_header: FunctionHeader = bs_func.header

                old_args = old_header.args or {}
                for off, old_arg in old_args.items():
                    new_arg = new_header.args.get(off, None)
                    if new_arg is None:
                        # TODO: support deleting args
                        continue

                    if old_arg == new_arg:
                        continue

                    diff_arg = FunctionArgument(off, None, None, None)
                    if old_arg.name != new_arg.name:
                        diff_arg.name = str(new_arg.name)

                    if old_arg.type != new_arg.type:
                        diff_arg.type = str(new_arg.type)

                    if old_arg.size != new_arg.size:
                        diff_arg.size = int(new_arg.size)

                    self._interface.function_header_changed(
                        FunctionHeader(None, old_header.addr, args={off: diff_arg})
                    )

                # new func args added to header
                for off, new_arg in bs_func.args.items():
                    if off in old_args:
                        continue

                    self._interface.function_header_changed(
                        FunctionHeader(None, old_header.addr, args={
                            off: FunctionArgument(off, str(new_arg.name), str(new_arg.type), int(new_arg.size))
                        })
                    )

            #
            # stack vars
            #

            header_args_names = set([arg.name for arg in bs_func.header.args.values()])
            if self._changing_func_pre_change.stack_vars != bs_func.stack_vars:
                old_svs: Dict[int, StackVariable] = self._changing_func_pre_change.stack_vars
                new_svs: Dict[int, StackVariable] = bs_func.stack_vars

                for off, old_sv in old_svs.items():
                    new_sv = new_svs.get(off, None)
                    if new_sv is None or new_sv.name in header_args_names:
                        continue

                    if old_sv == new_sv:
                        continue

                    diff_sv = StackVariable(off, None, None, old_sv.size, bs_func.addr)
                    if old_sv.name != new_sv.name:
                        diff_sv.name = str(new_sv.name)

                    if old_sv.type != new_sv.type:
                        diff_sv.type = str(new_sv.type)

                    self._interface.stack_variable_changed(diff_sv)

                for off, new_sv in new_svs.items():
                    if off in old_svs or new_sv.name in header_args_names:
                        continue

                    self._interface.stack_variable_changed(
                        StackVariable(off, str(new_sv.name), str(new_sv.type), new_sv.size, bs_func.addr)
                    )

            self._changing_func_pre_change = None

    def function_update_requested(self, view, func):
        if self._changing_func_addr is None:
            l.debug("Update on %s requested...", func)
            self._changing_func_addr = func.start
            self._changing_func_pre_change = BinjaInterface.bn_func_to_bs(func)
    
    def symbol_updated(self, view, sym):
        l.debug("Symbol update Requested on %s...", sym)
        if sym.type in VALID_FUNC_SYM_TYPES:
            l.debug("   -> Function Symbol")
            func = view.get_function_at(sym.address)
            bs_func = BinjaInterface.bn_func_to_bs(func)
            self._interface.function_header_changed(
                FunctionHeader(bs_func.name, bs_func.addr)
            )
        elif sym.type == SymbolType.DataSymbol:
            l.debug("   -> Data Symbol")
            var: binaryninja.DataVariable = view.get_data_var_at(sym.address)
            self._interface.global_variable_changed(
                GlobalVariable(int(sym.address), str(var.name), type_=str(var.type), size=int(var.type.width))
            )
        else:
            print(f"   -> Other Symbol: {sym.type}")
            pass

    def type_defined(self, view, name, type_):
        l.debug("Type Defined: %s %s", name, type_)
        name = str(name)
        if isinstance(type_, StructureType):
            bs_struct = BinjaInterface.bn_struct_to_bs(name, type_)
            self._interface.struct_changed(bs_struct)
        elif isinstance(type_, EnumerationType):
            bs_enum = BinjaInterface.bn_enum_to_bs(name, type_)
            self._interface.enum_changed(bs_enum)
