import threading
import functools
from collections import defaultdict
from typing import Dict, Optional, Any, List
import hashlib
import logging

BN_AVAILABLE = True
try:
    import binaryninja
except ImportError:
    BN_AVAILABLE = False

BN_UI_AVAILABLE = True
try:
    import binaryninjaui
except Exception:
    BN_UI_AVAILABLE = False

if BN_AVAILABLE:
    from binaryninja import SymbolType, PluginCommand, lineardisassembly
    from binaryninja.function import DisassemblySettings
    from binaryninja.enums import DisassemblyOption, LinearDisassemblyLineType, InstructionTextTokenType
    from binaryninja.enums import VariableSourceType
    from binaryninja.types import StructureType, EnumerationType
if BN_UI_AVAILABLE:
    from binaryninjaui import UIContext


import declib
from declib.api.decompiler_interface import DecompilerInterface
from declib.artifacts import (
    Function, FunctionHeader, StackVariable,
    Comment, GlobalVariable, Patch, StructMember, FunctionArgument,
    Enum, Struct, Artifact, Decompilation, Context, Typedef
)

from .artifact_lifter import BinjaArtifactLifter

l = logging.getLogger(__name__)

#
# Helpers
#

VALID_FUNC_SYM_TYPES = {SymbolType.FunctionSymbol, SymbolType.LibraryFunctionSymbol}

def background_and_wait(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        output = [None]

        def thunk():
            output[0] = func(*args, **kwargs)
            return 1

        thread = threading.Thread(target=thunk)
        thread.start()
        thread.join()

        return output[0]
    return wrapper


class BinjaInterface(DecompilerInterface):
    def __init__(self, bv=None, **kwargs):
        self._bv: "binaryninja.BinaryView" = bv
        self._data_monitor = None
        super(BinjaInterface, self).__init__(name="binja", artifact_lifter=BinjaArtifactLifter(self), **kwargs)

    @property
    def bv(self):
        if self._bv is None:
            l.warning("The BinaryView is not initialized. You may need to pass 'bv=' to the constructor call or discover call.")

        return self._bv

    @bv.setter
    def bv(self, bv: "binaryninja.BinaryView"):
        if not isinstance(bv, binaryninja.BinaryView):
            raise TypeError("The bv must be a BinaryView instance.")

        self._bv = bv

    def _init_headless_components(self, *args, **kwargs):
        super()._init_headless_components(*args, **kwargs)
        if not BN_AVAILABLE:
            raise ImportError("Unable to import binaryninja module. Are you sure you have it installed with an enterprise license?")

        self.bv = binaryninja.load(str(self._binary_path))

    def _init_gui_components(self, *args, **kwargs):
        if binaryninja.core_ui_enabled():
            super()._init_gui_components(*args, **kwargs)
            return True
        else:
            return False

    def _init_gui_plugin(self, *args, **kwargs):
        return self

    def __del__(self):
        if self.headless and BN_AVAILABLE:
            self.bv.file.close()

    #
    # GUI
    #

    def gui_active_context(self) -> Optional[Context]:
        all_contexts = UIContext.allContexts()
        if not all_contexts:
            return None

        ctx = all_contexts[0]
        handler = ctx.contentActionHandler()
        if handler is None:
            return None

        actionContext = handler.actionContext()
        if actionContext is None:
            return None

        func_addr = actionContext.function.start if actionContext.function is not None else None
        addr = actionContext.address if actionContext.address is not None else None
        # TODO: support screen_name
        context = Context(addr=addr, func_addr=func_addr)
        return self.art_lifter.lift(context)

    def gui_goto(self, func_addr) -> None:
        func_addr = self.art_lifter.lower_addr(func_addr)
        self.bv.offset = func_addr

    def gui_register_ctx_menu(self, name, action_string, callback_func, category=None, shortcut=None) -> bool:
        # TODO: this needs to have a wrapper function that passes the bv to the current deci
        # correct name, category, and action_string for Binja
        action_string = action_string.replace("/", "\\")
        category = category.replace("/", "\\") if category else ""

        PluginCommand.register_for_address(
            f"{category}\\{action_string}",
            action_string,
            callback_func,
            is_valid=self.is_bn_func
        )

        if shortcut and BN_UI_AVAILABLE:
            try:
                from binaryninjaui import UIAction, UIActionHandler
                action_name = f"{category}\\{action_string}" if category else action_string
                UIAction.registerAction(action_name, shortcut)
                # UIAction expects a callable taking a UIActionContext
                UIActionHandler.globalActions().bindAction(
                    action_name, UIAction(lambda ctx: callback_func(None))
                )
            except Exception as e:
                l.warning(f"Failed to register Binja shortcut {shortcut!r} for {name}: {e}")

        return True

    def gui_ask_for_string(self, question, title="Plugin Question", default="") -> str:
        resp = binaryninja.get_text_line_input(question, title)
        return resp.decode() if resp else ""

    def gui_ask_for_choice(self, question: str, choices: list, title="Plugin Question") -> str:
        choice_idx = binaryninja.get_choice_input(question, title, choices)
        return choices[choice_idx] if choice_idx is not None else ""

    #
    # Public API
    #

    @property
    def binary_base_addr(self) -> int:
        return self._get_first_segment_base()

    @property
    def binary_hash(self) -> str:
        hash_ = ""
        try:
            hash_ = hashlib.md5(self.bv.file.raw[:]).hexdigest()
        except Exception:
            pass

        return hash_

    @property
    def binary_path(self) -> Optional[str]:
        try:
            return self.bv.file.original_filename
        except Exception:
            return None

    def fast_get_function(self, func_addr) -> Optional[Function]:
        func_addr = self.art_lifter.lower_addr(func_addr)
        func = self.bv.get_function_at(func_addr)
        if not func:
            return None

        return self.art_lifter.lift(self.bn_func_to_bs(func))

    def get_func_size(self, func_addr) -> int:
        func_addr = self.art_lifter.lower_addr(func_addr)
        func = self.bv.get_function_at(func_addr)
        if not func:
            return 0

        return func.highest_address - func.start

    def xrefs_to(self, artifact: Artifact, decompile=False, only_code=False) -> List[Artifact]:
        if not isinstance(artifact, Function):
            l.warning("xrefs_to is only implemented for functions.")
            return []

        function: Function = self.art_lifter.lower(artifact)
        if not function:
            return []

        bn_xrefs = list(self.bv.get_code_refs(function.addr))
        if not only_code:
            bn_xrefs.extend(self.bv.get_data_refs(function.addr))

        xrefs = []
        for bn_xref in bn_xrefs:
            if bn_xref.function is None:
                continue

            xrefs.append(Function(bn_xref.function.start, 0))

        return xrefs

    def get_func_containing(self, addr: int) -> Optional[Function]:
        addr = self.art_lifter.lower_addr(addr)
        funcs = self.bv.get_functions_containing(addr)
        if not funcs:
            return None

        if len(funcs) > 1:
            l.warning("More than one function contains the the address %s", addr)

        bn_func = funcs[0]
        return self._get_function(bn_func.start)

    def _decompile(self, function: Function, map_lines=False, **kwargs) -> Optional[Decompilation]:
        bv = self.bv
        if bv is None:
            return

        bn_func = self.addr_to_bn_func(bv, function.addr)
        if bn_func is None:
            return None

        settings = DisassemblySettings()
        settings.set_option(DisassemblyOption.ShowVariableTypesWhenAssigned)
        settings.set_option(DisassemblyOption.GroupLinearDisassemblyFunctions)
        settings.set_option(DisassemblyOption.WaitForIL)

        decomp_text = ""
        obj = lineardisassembly.LinearViewObject.single_function_language_representation(bn_func, settings)
        cursor = obj.cursor
        line_map = defaultdict(set)
        while True:
            for ln, line in enumerate(cursor.lines):
                if line.type in [
                    LinearDisassemblyLineType.FunctionHeaderStartLineType,
                    LinearDisassemblyLineType.FunctionHeaderEndLineType,
                    LinearDisassemblyLineType.AnalysisWarningLineType,
                ]:
                    continue

                for i in line.contents.tokens:
                    if i.type == InstructionTextTokenType.TagToken:
                        continue

                    decomp_text += str(i)
                decomp_text += "\n"
                if line.contents and line.contents.address is not None:
                    line_map[ln].add(int(line.contents.address))

            if not cursor.next():
                break

        decompilation = Decompilation(
            addr=function.addr,
            text=decomp_text,
            decompiler=self.name
        )
        if map_lines:
            # TODO: make this more accurate!
            decompilation.line_map = dict(line_map)

        return decompilation

    def local_variable_names(self, func: Function) -> List[str]:
        bn_func = self.addr_to_bn_func(self.bv, self.art_lifter.lower_addr(func.addr))
        if bn_func is None:
            return []

        return [str(var.name) for var in bn_func.vars]

    @background_and_wait
    def rename_local_variables_by_names(self, func: Function, name_map: Dict[str, str], **kwargs) -> bool:
        bn_func = self.addr_to_bn_func(self.bv, self.art_lifter.lower_addr(func.addr))
        if bn_func is None:
            return False

        lvars = {
            lvar.name: lvar for lvar in bn_func.vars if lvar.name
        }
        update = False
        for name, lvar in lvars.items():
            new_name = name_map.get(name, None)
            if new_name is None:
                continue

            lvar.name = new_name
            update |= True

        if update:
            bn_func.reanalyze()

        return update

    def get_decompilation_object(self, function: Function, **kwargs) -> Optional[object]:
        """
        Binary Ninja has no internal object that needs to be refreshed.
        """
        return None

    def read_memory(self, addr: int, size: int) -> Optional[bytes]:
        if size <= 0:
            return b""
        lowered = self.art_lifter.lower_addr(addr)
        try:
            data = self.bv.read(lowered, size)
        except Exception:
            return None
        if data is None:
            return None
        return bytes(data)

    def start_artifact_watchers(self):
        if not self.artifact_watchers_started:
            from .hooks import DataMonitor
            if self.bv is None:
                raise RuntimeError("Cannot start artifact watchers without a BinaryView.")

            self._data_monitor = DataMonitor(self.bv, self)
            self.bv.register_notification(self._data_monitor)
            super().start_artifact_watchers()

    def stop_artifact_watchers(self):
        if self.artifact_watchers_started:
            self.bv.unregister_notification(self._data_monitor)
            self._data_monitor = None
            super().stop_artifact_watchers()

    #
    # Artifact API
    #

    # functions
    def _set_function(self, func: Function, **kwargs) -> bool:
        bn_func = self.bv.get_function_at(func.addr)
        if bn_func is None:
            return False

        return super()._set_function(func, bn_func=bn_func, **kwargs)

    def _get_function(self, addr, **kwargs) -> Optional[Function]:
        bn_func = self.bv.get_function_at(addr)
        if bn_func is None:
            return None

        return self.bn_func_to_bs(bn_func)

    def _functions(self) -> Dict[int, Function]:
        funcs = {}
        for bn_func in self.bv.functions:
            if not bn_func.symbol.type in VALID_FUNC_SYM_TYPES:
                continue

            funcs[bn_func.start] = Function(bn_func.start, bn_func.total_bytes)
            funcs[bn_func.start].name = bn_func.name

        return funcs

    # function header
    def _set_function_header(self, fheader: FunctionHeader, bn_func=None, **kwargs) -> bool:
        updates = False
        if not fheader:
            return updates

        # func name
        if fheader.name and fheader.name != bn_func.name:
            bn_func.name = fheader.name
            updates |= True

        # ret type
        if fheader.type and \
                fheader.type != bn_func.return_type.get_string_before_name():

            try:
                new_type, _ = self.bv.parse_type_string(fheader.type)
            except Exception:
                new_type = None

            if new_type is not None:
                bn_func.return_type = new_type
                updates |= True

        # parameters
        if not fheader.args:
            return updates

        for i, bn_var in enumerate(bn_func.parameter_vars):
            bs_var = fheader.args.get(i, None)
            if bs_var is None:
                continue

            # type
            if bs_var.type and bs_var.type != self.art_lifter.lift_type(str(bn_var.type)):
                bn_var.type = bs_var.type
                updates |= True
                # refresh
                bn_var = bn_func.parameter_vars[i]

            # name
            if bs_var.name and bs_var.name != str(bn_var.name):
                bn_var.name = bs_var.name
                updates |= True

        return updates

    def _valid_var_for_bn_set(self, bs_var: StackVariable):
        # a stopgap for issue reported in:
        # https://github.com/binsync/declib/issues/128
        #
        # the real fix is likely on the binja side.
        return bs_var.offset is not None and bs_var.name is not None

    # stack vars
    def _set_stack_variable(self, svar: StackVariable, bn_func=None, **kwargs) -> bool:
        updates = False
        current_bn_vars: Dict[int, Any] = {
            v.storage: v for v in bn_func.stack_layout
            if v.source_type == VariableSourceType.StackVariableSourceType and v not in bn_func.parameter_vars
        }

        bn_offset = svar.offset
        if bn_offset in current_bn_vars:
            # name
            if svar.name and svar.name != str(current_bn_vars[bn_offset].name):
                current_bn_vars[bn_offset].name = svar.name
                updates |= True

            # type
            if svar.type:
                try:
                    bs_svar_type, _ = self.bv.parse_type_string(svar.type)
                except Exception:
                    bs_svar_type = None

                if bs_svar_type is not None:
                    if self.art_lifter.lift_type(str(current_bn_vars[bn_offset].type)) != bs_svar_type:
                        current_bn_vars[bn_offset].type = bs_svar_type

                    # this can cause a binja segfault, so we need to check if the var is valid before doing
                    # normal python try/except
                    if self._valid_var_for_bn_set(svar):
                        try:
                            bn_func.create_user_stack_var(bn_offset, bs_svar_type, svar.name)
                            bn_func.create_auto_stack_var(bn_offset, bs_svar_type, svar.name)
                        except Exception as e:
                            l.warning("BinSync could not sync stack variable at offset %s: %s", bn_offset, e)

                    updates |= True

        return updates

    # global variables
    def _set_global_variable(self, gvar: GlobalVariable, **kwargs) -> bool:
        bn_gvar = self.bv.get_data_var_at(gvar.addr)
        global_type = self.bv.parse_type_string(gvar.type)
        changed = False

        if bn_gvar is None:
            bn_gvar = self.bv.define_user_data_var(gvar.addr, global_type, gvar.name)
            changed = True

        if bn_gvar:
            self.bv.define_user_data_var(gvar.addr, global_type, gvar.name)
            changed = True

        return changed

    def _get_global_var(self, addr) -> Optional[GlobalVariable]:
        bn_gvar = self.bv.get_data_var_at(addr)
        if bn_gvar is None:
            return None

        return GlobalVariable(
            addr,
            self.bv.get_symbol_at(addr) or f"data_{addr:x}",
            type_=str(bn_gvar.type) if bn_gvar.type is not None else None,
            size=bn_gvar.type.width
        )

    def _global_vars(self, **kwargs) -> Dict[int, GlobalVariable]:
        return {
            addr: GlobalVariable(addr, var.name or f"data_{addr:x}")
            for addr, var in self.bv.data_vars.items()
        }

    # structs
    def _set_struct(self, struct: Struct, header=True, members=True, **kwargs) -> bool:
        if header:
            self.bv.define_user_type(struct.name, binaryninja.Type.structure(packed=True))

        if members:
            # this scope assumes that the type is now defined... if it's not we will error
            with binaryninja.Type.builder(self.bv, struct.name) as s:
                s.width = struct.size
                members = list()
                for offset in sorted(struct.members.keys()):
                    bs_memb = struct.members[offset]
                    try:
                        bn_type = self.bv.parse_type_string(bs_memb.type)[0] if bs_memb.type else None
                    except Exception:
                        bn_type = None
                    finally:
                        if bn_type is None:
                            bn_type = binaryninja.Type.int(bs_memb.size)

                    members.append((bn_type, bs_memb.name))
                s.members = members

        return True

    def _get_struct(self, name) -> Optional[Struct]:
        bn_struct = self.bv.types.get(name, None)
        if bn_struct is None or not isinstance(bn_struct, StructureType):
            return None

        return self.bn_struct_to_bs(name, bn_struct)

    def _del_struct(self, name) -> bool:
        return self.bv.undefine_user_type(name)

    def _structs(self) -> Dict[str, Struct]:
        return {
            name: Struct(''.join(name.name), t.width, {}) for name, t in self.bv.types.items()
            if isinstance(t, StructureType)
        }

    # enums
    def _set_enum(self, enum: Enum, **kwargs) -> bool:
        bn_members = list(enum.members.items())
        new_type = binaryninja.TypeBuilder.enumeration(self.bv.arch, bn_members)
        self.bv.define_user_type(enum.name, new_type)
        return True

    def _get_enum(self, name) -> Optional[Enum]:
        bn_enum = self.bv.types.get(name, None)
        if bn_enum is None:
            return None

        if isinstance(bn_enum, EnumerationType):
            return self.bn_enum_to_bs(name, bn_enum)

        return None

    def _enums(self) -> Dict[str, Enum]:
        return {
            name: self.bn_enum_to_bs(''.join(name.name), t) for name, t in self.bv.types.items()
            if isinstance(t, EnumerationType)
        }

    # typedef
    def _set_typedef(self, typedef: Typedef, **kwargs) -> bool:
        base_type = self.bv.parse_type_string(typedef.type)[0]
        if base_type is None:
            raise ValueError(f"Could not parse the type {typedef.type}")

        # handle primitive types
        try:
            base_type_name = str(base_type.name)
        except NotImplementedError:
            base_type_name = str(base_type)

        base_type_ref = binaryninja.TypeBuilder.named_type_reference(
            binaryninja.NamedTypeReferenceClass.TypedefNamedTypeClass, base_type_name, base_type_name,
            0, base_type.width
        )
        self.bv.define_user_type(typedef.name, base_type_ref)
        return True

    def _get_typedef(self, name) -> Optional[Typedef]:
        bn_typedef = self.bv.types.get(name, None)
        if bn_typedef is None:
            return None

        if isinstance(bn_typedef, binaryninja.NamedTypeReferenceType):
            return self.bn_typedef_to_bs(name, bn_typedef)

        return None

    def _typedefs(self) -> Dict[str, Typedef]:
        return {
            name: self.bn_typedef_to_bs(''.join(name.name), t) for name, t in self.bv.types.items()
            if isinstance(t, binaryninja.NamedTypeReferenceType)
        }

    # patches
    def _set_patch(self, patch: Patch, **kwargs) -> bool:
        l.warning("Patch setting is unimplemented in Binja")
        return False

    def _get_patch(self, addr) -> Optional[Patch]:
        l.warning("Patch getting is unimplemented in Binja")
        return None

    def _patches(self) -> Dict[int, Patch]:
        l.warning("Patch listing is unimplemented in Binja")
        return {}

    # comments
    def _set_comment(self, comment: Comment, **kwargs) -> bool:
        # search for the right function
        declib_func = self.get_func_containing(comment.addr)
        if declib_func is None:
            # in the case of the function not existing, just comment in addr space
            self.bv.set_comment_at(comment.addr, comment.comment)
            return True

        # func exists for commenting
        bn_func = self.addr_to_bn_func(self.bv, comment.addr)
        bn_func.set_comment_at(comment.addr, comment.comment)

    def _get_comment(self, addr) -> Optional[Comment]:
        non_func_cmt = self.bv.get_comment_at(addr)
        if non_func_cmt:
            return Comment(addr, non_func_cmt)

        # search for the right function
        funcs = self.bv.get_functions_containing(addr)
        if not funcs:
            return None

        bn_func = funcs[0]

        for _addr, cmt in bn_func.comments.items():
            if addr == _addr:
                return Comment(
                    addr,
                    cmt,
                    func_addr=bn_func.start,
                    decompiled=True
                )

        return None

    def _comments(self) -> Dict[int, Comment]:
        # search every single function for comments
        comments = {}
        for bn_func in self.bv.functions:
            if not bn_func.symbol.type in VALID_FUNC_SYM_TYPES:
                continue

            comments.update(bn_func.comments)

        # TODO: show non-function based comments
        return comments

    #
    # Helper converter functions
    #

    @staticmethod
    def bn_struct_to_bs(name, bn_struct):
        members = {
            member.offset: StructMember(str(member.name), member.offset, str(member.type), member.type.width)
            for member in bn_struct.members if member.offset is not None
        }

        return Struct(
            str(name),
            bn_struct.width if bn_struct.width is not None else 0,
            members
        )

    @staticmethod
    def bn_func_to_bs(bn_func):
        #
        # header: name, ret type, args
        #

        args = {
            i: FunctionArgument(i, parameter.name, parameter.type.get_string_before_name(), parameter.type.width)
            for i, parameter in enumerate(bn_func.parameter_vars)
        }
        # XXX: this a hack to fix the void (*arg) issue
        for i, arg in args.items():
            # notice the missing end parenthesis
            if arg.type.endswith("(*"):
                arg.type = arg.type.replace("(*", "*")

        sync_header = FunctionHeader(
            bn_func.name,
            bn_func.start,
            type_=bn_func.return_type.get_string_before_name(),
            args=args
        )

        #
        # stack vars
        #

        binja_stack_vars = {
            v.storage: v for v in bn_func.stack_layout
            if v.source_type == VariableSourceType.StackVariableSourceType and v not in bn_func.parameter_vars
        }
        sorted_stack = sorted(bn_func.stack_layout, key=lambda x: x.storage)
        var_sizes = {}

        for off, var in binja_stack_vars.items():
            i = sorted_stack.index(var)
            if i + 1 >= len(sorted_stack):
                var_sizes[var] = 0
            else:
                var_sizes[var] = var.storage - sorted_stack[i].storage

        bs_stack_vars = {
            off: declib.artifacts.StackVariable(
                off,
                var.name,
                var.type.get_string_before_name(),
                var_sizes[var],
                bn_func.start
            )
            for off, var in binja_stack_vars.items()
        }

        try:
            size = bn_func.highest_address - bn_func.start
        except Exception as e:
            size = 0
            l.critical(f"Failed to grab the size of function because {e}. It's possible the function "
                       f"is not yet known to Binary Ninja.")

        return Function(bn_func.start, size, header=sync_header, stack_vars=bs_stack_vars)

    @staticmethod
    def bn_enum_to_bs(name: str, bn_enum: "binaryninja.EnumerationType"):
        members = {}

        for enum_member in bn_enum.members:
            if isinstance(enum_member, binaryninja.EnumerationMember) and isinstance(enum_member.value, int):
                members[enum_member.name] = enum_member.value

        return Enum(name, members)

    @staticmethod
    def bn_typedef_to_bs(name: str, bn_typedef: "binaryninja.NamedTypeReferenceType"):
        return Typedef(name, str(bn_typedef.name))

    @staticmethod
    def addr_to_bn_func(bv, address):
        funcs = bv.get_functions_containing(address)
        try:
            func = funcs[0]
        except IndexError:
            return None

        return func

    def is_bn_func(self, bv, address):
        # HACK: update the BV whenever this is used in a context menu
        self.bv = bv
        func = self.addr_to_bn_func(bv, address)
        return func is not None

    def _get_first_segment_base(self) -> int:
        """
        Get the virtual address of the first segment.
        """
        if self.bv is None:
            return None
        
        # First, try to find a code/executable segment
        for segment in self.bv.segments:
            return segment.start
        
        # Fallback to bv.start if no segments found
        return self.bv.start
