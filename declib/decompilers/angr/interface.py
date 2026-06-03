import logging
import os
import re
from collections import defaultdict
from functools import lru_cache
from typing import Optional, Dict, List, Tuple
from pathlib import Path

import angr
from angr.analyses.decompiler.structured_codegen import DummyStructuredCodeGenerator

from declib.api.decompiler_interface import (
    DecompilerInterface,
)
from declib.artifacts import (
    Function, FunctionHeader, Comment, StackVariable, FunctionArgument, Artifact, Decompilation, Context,
    Struct, StructMember
)
from .artifact_lifter import AngrArtifactLifter

l = logging.getLogger(__name__)

try:
    from angrmanagement.ui.views import CodeView
except ImportError:
    l.debug("angr-management module not found... likely running headless.")

logging.getLogger("angr").setLevel(logging.ERROR)
logging.getLogger("cle").setLevel(logging.ERROR)


class AngrInterface(DecompilerInterface):
    """
    The class used for all pushing/pulling and merging based actions with BinSync artifacts.
    This class is responsible for handling callbacks that are done by changes from the local user
    and responsible for running a thread to get new changes from other users.
    """

    def __init__(self, workspace=None, **kwargs):
        self.workspace = workspace
        self.main_instance = workspace.main_instance if workspace else self
        self._ctx_menu_items = []
        self._am_logger = None
        self._cfg = None
        self._binary_arch = None
        super().__init__(name="angr", artifact_lifter=AngrArtifactLifter(self), **kwargs)

    def _init_headless_components(self, *args, **kwargs):
        super()._init_headless_components(*args, **kwargs)
        self.project = angr.Project(str(self._binary_path), auto_load_libs=False)
        # cross_references=True populates kb.xrefs so xrefs_to_addr (e.g.
        # "who references this string constant?") works.
        self._cfg = self.project.analyses.CFG(
            show_progressbar=False, normalize=True, data_references=True, cross_references=True,
        )
        self.project.analyses.CompleteCallingConventions(cfg=self._cfg, recover_variables=True, analyze_callsites=True)

    def _init_gui_components(self, *args, **kwargs):
        super()._init_gui_components(*args, **kwargs)
        if self.workspace is None:
            raise ValueError("The workspace provided is None, which will result in a broken BinSync.")

        self._am_logger = logging.getLogger(f"angrmanagement.{self._plugin_name or 'generic_plugin'}")
        self._am_logger.setLevel(logging.INFO)

    #
    # Decompiler API
    #

    @property
    def binary_base_addr(self) -> int:
        for seg in self.main_instance.project.loader.main_object.segments:
            return seg.min_addr

        # fallback
        return self.main_instance.project.loader.main_object.mapped_base

    @property
    def binary_hash(self) -> str:
        return self.main_instance.project.loader.main_object.md5.hex()

    @property
    def binary_path(self) -> Optional[str]:
        try:
            return self.main_instance.project.loader.main_object.binary
        # pylint: disable=broad-except
        except Exception:
            return None

    def fast_get_function(self, func_addr) -> Optional[Function]:
        lowered_addr = self.art_lifter.lower_addr(func_addr)
        try:
            _func = self.main_instance.project.kb.functions[lowered_addr]
        except KeyError:
            #self.warning(f"Function at {hex(func_addr)} not found.")
            return None

        func = Function(addr=_func.addr, size=_func.size, name=_func.name)
        if not _func or not _func.prototype:
            type_ = None
        else:
            type_ = _func.prototype.returnty.c_repr() if _func.prototype.returnty else None
        func.header.type = type_
        return self.art_lifter.lift(func)

    def get_func_size(self, func_addr) -> int:
        func_addr = self.art_lifter.lower_addr(func_addr)
        try:
            func = self.main_instance.project.kb.functions[func_addr]
            return func.size
        except KeyError:
            return 0

    def xrefs_to(self, artifact: Artifact, decompile=False, only_code=False) -> List[Artifact]:
        if not isinstance(artifact, Function):
            l.warning("xrefs_to is only implemented for functions.")
            return []
        if only_code:
            l.warning("only_code is not supported in angr.")

        function: Function = self.art_lifter.lower(artifact)
        program_cfg = self.main_instance.project.kb.cfgs.get_most_accurate()
        if program_cfg is None:
            return []

        func_node = program_cfg.get_any_node(function.addr)
        if func_node is None:
            return []

        xrefs = []
        seen_callers = set()
        for node in program_cfg.graph.predecessors(func_node):
            func_addr = node.function_address
            if func_addr is None or func_addr == function.addr:
                continue
            if func_addr in seen_callers:
                continue
            seen_callers.add(func_addr)
            xrefs.append(self.art_lifter.lift(Function(func_addr, 0)))

        return xrefs

    def xrefs_from(self, func_addr: int) -> List[Function]:
        """angr callees: use the kb.callgraph successor set.

        ``kb.callgraph`` is a NetworkX digraph populated during CFG analysis;
        its successors of a function address are the direct callees, which is
        what we want. Unlike ``Function.transition_graph``, these are
        deduplicated per target and come with kb function lookups.
        """
        lowered = self.art_lifter.lower_addr(func_addr)
        project = self.main_instance.project
        callgraph = getattr(project.kb, "callgraph", None)
        if callgraph is None or lowered not in callgraph:
            return []

        kb_functions = project.kb.functions
        callees: List[Function] = []
        seen = set()
        for succ_addr in callgraph.successors(lowered):
            if succ_addr in seen:
                continue
            seen.add(succ_addr)
            func_obj = kb_functions.get(succ_addr, None)
            name = getattr(func_obj, "name", None) if func_obj is not None else None
            header = FunctionHeader(name=name, addr=succ_addr) if name else None
            callees.append(self.art_lifter.lift(Function(succ_addr, 0, header=header)))
        return callees

    def xrefs_to_addr(self, addr: int, only_code: bool = False) -> List[Artifact]:
        """angr data-xref lookup: look up kb.xrefs references to ``addr``.

        Falls back to the default (empty) if the xref manager isn't populated.
        """
        lowered = self.art_lifter.lower_addr(addr)
        project = self.main_instance.project
        xref_manager = getattr(project.kb, "xrefs", None)
        if xref_manager is None:
            return []

        try:
            xref_set = xref_manager.get_xrefs_by_dst(lowered)
        except Exception:
            return []
        if not xref_set:
            return []

        program_cfg = project.kb.cfgs.get_most_accurate()
        if program_cfg is None:
            return []

        results: List[Artifact] = []
        seen = set()
        for xref in xref_set:
            node = program_cfg.get_any_node(xref.ins_addr, anyaddr=True)
            if node is None or node.function_address is None:
                continue
            func_addr = node.function_address
            if func_addr in seen:
                continue
            seen.add(func_addr)
            name = None
            try:
                name = project.kb.functions[func_addr].name
            except Exception:
                pass
            header = FunctionHeader(name=name, addr=func_addr) if name else None
            results.append(self.art_lifter.lift(Function(func_addr, 0, header=header)))
        return results

    def list_strings(self, filter: Optional[str] = None) -> List[Tuple[int, str]]:
        pattern = re.compile(filter) if filter else None
        try:
            cfg = self.main_instance.project.kb.cfgs.get_most_accurate()
        except Exception:
            cfg = None
        results: List[Tuple[int, str]] = []
        seen = set()
        if cfg is not None:
            for addr, mem_data in cfg.memory_data.items():
                if mem_data.sort != "string" or not mem_data.content:
                    continue
                try:
                    text = mem_data.content.decode("utf-8", errors="replace")
                except Exception:
                    continue
                lifted_addr = self.art_lifter.lift_addr(addr)
                if lifted_addr in seen:
                    continue
                seen.add(lifted_addr)
                if pattern is None or pattern.search(text):
                    results.append((lifted_addr, text))
        results.sort(key=lambda item: item[0])
        return results

    def read_memory(self, addr: int, size: int) -> Optional[bytes]:
        if size <= 0:
            return b""
        lowered = self.art_lifter.lower_addr(addr)
        loader_memory = self.main_instance.project.loader.memory
        try:
            data = loader_memory.load(lowered, size)
        except (KeyError, ValueError):
            # cle's Clemory raises when the address isn't backed by a segment.
            return None
        return bytes(data)

    def disassemble(self, addr: int, **kwargs) -> Optional[str]:
        lowered = self.art_lifter.lower_addr(addr)
        func = self.main_instance.project.kb.functions.get(lowered, None)
        if func is None:
            for _addr, _func in self.main_instance.project.kb.functions.items():
                if _addr <= lowered < (_addr + (_func.size or 0)):
                    func = _func
                    break
        if func is None:
            return None

        try:
            base_addr = self.binary_base_addr
        except Exception:
            base_addr = 0
        hex_re = re.compile(r"0x([0-9a-fA-F]+)")

        def _rewrite_operands(op_str: str) -> str:
            # Rewrite absolute addresses in operands to their lifted form so the
            # output is consistent across decompilers (e.g. ghidra lifts addresses).
            def _sub(match: "re.Match[str]") -> str:
                try:
                    raw = int(match.group(1), 16)
                except ValueError:
                    return match.group(0)
                if base_addr and raw >= base_addr:
                    return f"0x{raw - base_addr:x}"
                return match.group(0)

            return hex_re.sub(_sub, op_str)

        lines: List[str] = []
        try:
            blocks = sorted(func.blocks, key=lambda b: b.addr)
        except Exception:
            blocks = list(func.blocks)
        for block in blocks:
            try:
                for insn in block.capstone.insns:
                    lifted = self.art_lifter.lift_addr(insn.address)
                    op_str = _rewrite_operands(insn.op_str)
                    lines.append(f"0x{lifted:x}:\t{insn.mnemonic}\t{op_str}".rstrip())
            except Exception:
                continue
        return "\n".join(lines) if lines else None

    def _decompile(self, function: Function, map_lines=False, **kwargs) -> Optional[Decompilation]:
        if function.dec_obj is None:
            function.dec_obj = self.get_decompilation_object(function, do_lower=False)

        if function.dec_obj is None:
            return None

        codegen = function.dec_obj.codegen
        if codegen is None or not codegen.text:
            return None

        decompilation = Decompilation(addr=function.addr, text=codegen.text, decompiler=self.name)
        if map_lines:
            if self.headless:
                decompilation.line_map = self.line_map_from_decompilation(function.dec_obj)
            else:
                self.warning("Mapping lines is only supported in headless mode.")
                decompilation.line_map = {}

        return decompilation

    def get_decompilation_object(self, function: Function, do_lower=True, **kwargs) -> Optional[object]:
        func_addr = self.art_lifter.lower_addr(function.addr) if do_lower else function.addr
        func = self.main_instance.project.kb.functions.get(func_addr, None)
        if func is None:
            return None

        try:
            decomp = self.decompile_function(func)
        except Exception as e:
            l.warning("Failed to decompile %s because %s", func, e)
            decomp = None

        return decomp

    def local_variable_names(self, func: Function) -> List[str]:
        codegen = self.decompile_function(
            self.main_instance.project.kb.functions[self.art_lifter.lower_addr(func.addr)]
        ).codegen
        if not codegen or not codegen.cfunc or not codegen.cfunc.variable_manager:
            return []

        return [v.name for v in codegen.cfunc.variable_manager._unified_variables]

    def rename_local_variables_by_names(self, func: Function, name_map: Dict[str, str],  **kwargs) -> bool:
        codegen = self.decompile_function(
            self.main_instance.project.kb.functions[self.art_lifter.lower_addr(func.addr)]
        ).codegen
        if not codegen or not codegen.cfunc or not codegen.cfunc.variable_manager:
            return False

        changed = False
        for v in codegen.cfunc.variable_manager._unified_variables:
            if v.name in name_map and v.name != name_map[v.name]:
                v.name = name_map[v.name]
                changed = True

        if not self.headless:
            self.refresh_decompilation(func.addr)
        return changed

    @property
    def binary_arch(self) -> str | None:
        if self._binary_arch is None:
            if self.main_instance.project.arch:
                self._binary_arch = self.main_instance.project.arch.name

        return self._binary_arch


    #
    # GUI API
    #

    def _init_gui_plugin(self, *args, **kwargs):
        from .compat import GenericDLAngrManagementPlugin
        self.gui_plugin = GenericDLAngrManagementPlugin(self.workspace, interface=self)
        self.workspace.plugins.register_active_plugin(self._plugin_name, self.gui_plugin)
        return self.gui_plugin

    def gui_goto(self, func_addr):
        self.workspace.jump_to(self.art_lifter.lower_addr(func_addr))

    def gui_register_ctx_menu(self, name, action_string, callback_func, category=None, shortcut=None) -> bool:
        if self.gui_plugin is None:
            l.critical("Cannot register context menu item without a GUI plugin.")
            return False

        self._ctx_menu_items.append((name, action_string, callback_func, category))
        self.gui_plugin.context_menu_items = self._ctx_menu_items

        if shortcut:
            try:
                self.gui_plugin.register_shortcut(name, shortcut, callback_func, deci=self)
            except Exception as e:
                l.warning("Failed to register angr shortcut %r for %s: %s", shortcut, name, e)
        return True

    def gui_active_context(self) -> Optional[Context]:
        curr_view = self.workspace.view_manager.current_tab
        # current view is non-existent or does not support a "function" view type of context
        if not curr_view or not hasattr(curr_view, "function"):
            return None

        try:
            func = curr_view.function
        except NotImplementedError:
            return None

        # TODO: support addr and screen_name for Context
        if func is None or func.am_obj is None:
            return None

        context = Context(addr=None, func_addr=func.addr)
        return self.art_lifter.lift(context)

    def gui_attach_qt_window(self, qt_window: type["QWidgt"], title: str, target_window=None, position=None, *args, **kwargs) -> bool:
        from .compat import attach_qt_widget
        if self.workspace is None:
            l.warning("Cannot attach a Qt window without a workspace.")
            return False

        return attach_qt_widget(self.workspace, qt_window, title, *args, **kwargs)


    #
    # Artifact API
    #

    def _set_function(self, func: Function, **kwargs) -> bool:
        angr_func = self.main_instance.project.kb.functions[func.addr]

        # re-decompile a function if needed
        decompilation = self.decompile_function(angr_func).codegen
        changes = super()._set_function(func, decompilation=decompilation, **kwargs)
        if not self.headless and changes:
            # Use "retype_variable" event to trigger proper UI refresh including type reflow
            self.refresh_decompilation(func.addr, event="retype_variable")

        return changes

    def _get_function(self, addr, **kwargs) -> Optional[Function]:
        try:
            _func = self.main_instance.project.kb.functions[addr]
        except KeyError:
            return None

        func = Function(_func.addr, _func.size)
        if not _func or not _func.prototype:
            type_ = None
        else:
            type_ = _func.prototype.returnty.c_repr() if _func.prototype.returnty else None
        func.header = FunctionHeader(
            _func.name, _func.addr, type_=type_
        )

        try:
            decompilation = self.decompile_function(_func).codegen
        except Exception as e:
            l.warning("Failed to decompile function %s: %s", hex(_func.addr), e)
            decompilation = None

        if not decompilation:
            return func

        func.header.args = self.func_args_as_declib_args(decompilation)
        # overwrite type again since it can change with decompilation
        functy = decompilation.cfunc.functy if decompilation.cfunc else None
        if functy and functy.returnty:
            func.header.type = decompilation.cfunc.functy.returnty.c_repr()

        stack_vars = {
            angr_sv.offset: StackVariable(
                angr_sv.offset, angr_sv.name, self.stack_var_type_str(decompilation, angr_sv), angr_sv.size, func.addr
            )
            for angr_sv in self.stack_vars_in_dec(decompilation)
        }
        func.stack_vars = stack_vars

        return func

    def _functions(self) -> Dict[int, Function]:
        funcs = {}
        for addr, func in self.main_instance.project.kb.functions.items():
            funcs[addr] = Function(addr, func.size)

            # syscalls and simprocedures are not real funcs to sync
            if func.is_syscall or func.is_simprocedure or not func.name:
                continue

            funcs[addr].name = func.name

        return funcs

    def _set_function_header(self, fheader: FunctionHeader, decompilation=None, **kwargs) -> bool:
        angr_func = self.main_instance.project.kb.functions[fheader.addr]
        changes = False
        if not fheader:
            return changes

        if fheader.name and fheader.name != angr_func.name:
            angr_func.name = fheader.name
            decompilation.cfunc.name = fheader.name
            decompilation.cfunc.demangled_name = fheader.name
            changes = True

        if fheader.args:
            for i, arg in fheader.args.items():
                if not arg:
                    continue

                if i >= len(decompilation.cfunc.arg_list):
                    break

                dec_arg = decompilation.cfunc.arg_list[i].variable
                # TODO: set the types of the args
                if arg.name and arg.name != dec_arg.name:
                    dec_arg.name = arg.name
                    changes = True

        return changes

    def _set_stack_variable(self, svar: StackVariable, decompilation=None, **kwargs) -> bool:
        changed = False
        if not svar or not decompilation:
            return changed

        dec_svar = AngrInterface.find_stack_var_in_codegen(decompilation, svar.offset)
        if not dec_svar:
            return changed

        # Set the name if provided and different
        if svar.name and svar.name != dec_svar.name:
            dec_svar.name = svar.name
            dec_svar.renamed = True
            changed = True

        # Set the type if provided
        if svar.type:
            try:
                from angr.sim_type import parse_type
                types_store = self.main_instance.project.kb.types
                arch = self.main_instance.project.arch

                # Parse the type string into a SimType
                sim_type = parse_type(svar.type, predefined_types=types_store, arch=arch)
                sim_type = sim_type.with_arch(arch)

                # Get the variable manager and set the type
                variable_kb = decompilation._variable_kb if hasattr(decompilation, '_variable_kb') else self.main_instance.project.kb
                variable_manager = variable_kb.variables[svar.addr]
                variable_manager.set_variable_type(dec_svar, sim_type, all_unified=True, mark_manual=True)
                changed = True
            except Exception as e:
                l.warning(f"Failed to set stack variable type for {svar.name}: {e}")

        return changed

    def _set_comment(self, comment: Comment, decompilation=None, **kwargs) -> bool:
        changed = False
        if not comment or not comment.comment:
            return changed

        if comment.decompiled and comment.addr != comment.func_addr:
            try:
                pos = decompilation.map_addr_to_pos.get_nearest_pos(comment.addr)
                corrected_addr = decompilation.map_pos_to_addr.get_node(pos).tags['ins_addr']
            # pylint: disable=broad-except
            except Exception:
                return changed

            dec_cmt = decompilation.stmt_comments.get(corrected_addr, None)
            if dec_cmt != comment.comment:
                decompilation.stmt_comments[corrected_addr] = comment.comment
                changed |= True
        else:
            kb_cmt = self.main_instance.project.kb.comments.get(comment.addr, None)
            if kb_cmt != comment.comment:
                self.main_instance.project.kb.comments[comment.addr] = comment.comment
                changed |= True

        func_addr = comment.func_addr or self.get_closest_function(comment.addr)
        return changed & self.refresh_decompilation(func_addr)

    # structs
    def _structs(self) -> Dict[str, Struct]:
        """
        Returns a dict of declib.Struct that contain the name and size of each struct in the decompiler.
        """
        from angr.sim_type import SimStruct, TypeRef
        structs = {}
        types_store = self.main_instance.project.kb.types

        for type_ref in types_store.iter_own():
            if not isinstance(type_ref, TypeRef):
                continue
            sim_type = type_ref.type
            if isinstance(sim_type, SimStruct):
                structs[type_ref.name] = Struct(type_ref.name, sim_type.size // 8 if sim_type.size else 0, {})

        return structs

    def _get_struct(self, name) -> Optional[Struct]:
        """
        Get a struct by name from the TypesStore.
        """
        from angr.sim_type import SimStruct, TypeRef
        types_store = self.main_instance.project.kb.types

        try:
            type_ref = types_store[name]
        except KeyError:
            return None

        if not isinstance(type_ref, TypeRef):
            return None

        sim_struct = type_ref.type
        if not isinstance(sim_struct, SimStruct):
            return None

        return self._angr_struct_to_declib(name, sim_struct)

    def _set_struct(self, struct: Struct, header=True, members=True, **kwargs) -> bool:
        """
        Create or update a struct in the TypesStore.
        """
        from angr.sim_type import SimStruct, TypeRef, parse_type
        from collections import OrderedDict

        types_store = self.main_instance.project.kb.types
        arch = self.main_instance.project.arch

        # Build the fields OrderedDict from DecLib struct members
        fields = OrderedDict()
        if members and struct.members:
            sorted_members = sorted(struct.members.items(), key=lambda x: x[0])
            for offset, member in sorted_members:
                # Parse the member type string into a SimType
                try:
                    sim_type = parse_type(member.type, predefined_types=types_store, arch=arch)
                except Exception:
                    # Fallback to a simple int type with the right size if parsing fails
                    from angr.sim_type import SimTypeInt
                    sim_type = SimTypeInt(signed=False).with_arch(arch)

                fields[member.name] = sim_type.with_arch(arch)

        # Create the SimStruct
        sim_struct = SimStruct(fields, name=struct.name, pack=True)
        sim_struct = sim_struct.with_arch(arch)

        # Wrap it in a TypeRef and store it
        type_ref = TypeRef(struct.name, sim_struct)
        types_store[struct.name] = type_ref

        return True

    def _del_struct(self, name) -> bool:
        """
        Delete a struct from the TypesStore.
        """
        types_store = self.main_instance.project.kb.types

        if name in types_store.data:
            del types_store.data[name]
            return True

        return False

    @staticmethod
    def _angr_struct_to_declib(name: str, sim_struct: "angr.sim_type.SimStruct") -> Struct:
        """
        Convert an angr SimStruct to a DecLib Struct.
        """
        members = {}
        if sim_struct._arch is not None:
            offsets = sim_struct.offsets
            for field_name, sim_type in sim_struct.fields.items():
                offset = offsets.get(field_name, 0)
                type_str = sim_type.c_repr() if sim_type else None
                size = sim_type.size // 8 if sim_type and sim_type.size else 0
                members[offset] = StructMember(field_name, offset, type_str, size)

        size = sim_struct.size // 8 if sim_struct.size else 0
        return Struct(name, size, members)

    #
    #   Utils
    #

    def info(self, msg: str, **kwargs):
        if self._am_logger is not None:
            self._am_logger.info(msg)

    def debug(self, msg: str, **kwargs):
        if self._am_logger is not None:
            self._am_logger.debug(msg)

    def warning(self, msg: str, **kwargs):
        if self._am_logger is not None:
            self._am_logger.warning(msg)

    def error(self, msg: str, **kwargs):
        if self._am_logger is not None:
            self._am_logger.error(msg)

    def print(self, msg: str, **kwargs):
        if self.headless:
            print(msg)
        else:
            self.info(msg)

    #
    # angr-management specific helpers
    #

    # TODO: add LRU back one day
    #@lru_cache(maxsize=1024)
    def addr_starts_instruction(self, addr) -> bool:
        """
        Returns True when the provided address maps to a valid instruction address in the binary and that address
        is at the start of the instruction (not in the middle). Useful for checking if an instruction is
        incorrectly computed due to ARM THUMB.
        """
        cfg = self.main_instance.project.kb.cfgs.get_most_accurate()
        if cfg is None:
            l.warning("Unable load CFG from angr. Other operations may be wrong.")
            return False

        node = cfg.get_any_node(addr, anyaddr=True)
        if node is None:
            return False

        return addr in node.instruction_addrs

    def refresh_decompilation(self, func_addr, event=None):
        if self.headless:
            return False

        self.workspace.jump_to(func_addr)
        view = self.workspace._get_or_create_view("pseudocode", CodeView)
        if event:
            view.codegen.am_event(event=event)
        else:
            view.codegen.am_event()
        view.focus()
        return True

    def _headless_decompile(self, func):
        if not func.normalized:
            func.normalize()

        return self.main_instance.project.analyses.Decompiler(func, cfg=self._cfg, flavor='pseudocode', preset="full")

    def _angr_management_decompile(self, func):
        # recover direct pseudocode
        self.main_instance.project.analyses.Decompiler(func, flavor='pseudocode')

        # attempt to get source code if its available
        source_root = None
        if self.main_instance.original_binary_path:
            source_root = os.path.dirname(self.main_instance.original_binary_path)
        self.main_instance.project.analyses.ImportSourceCode(func, flavor='source', source_root=source_root)

    def decompile_function(self, func, refresh_gui=False):
        # check for known decompilation
        available = self.main_instance.project.kb.decompilations.available_flavors(func.addr)
        should_decompile = False
        if self.headless or 'pseudocode' not in available:
            should_decompile = True
        else:
            cached = self.main_instance.project.kb.decompilations[(func.addr, 'pseudocode')]
            if isinstance(cached, DummyStructuredCodeGenerator):
                should_decompile = True

        decomp = None
        if should_decompile:
            if not self.headless:
                self._angr_management_decompile(func)
            else:
                decomp = self._headless_decompile(func)

        # grab newly cached pseudocode
        if not self.headless:
            decomp = self.main_instance.project.kb.decompilations[(func.addr, 'pseudocode')]

        # refresh the UI after decompiling
        if refresh_gui and not self.headless:
            self.workspace.reload()

            # re-decompile current view to cause a refresh
            current_tab = self.workspace.view_manager.current_tab
            if isinstance(current_tab, CodeView) and current_tab.function == func:
                self.workspace.decompile_current_function()

        return decomp

    @staticmethod
    def find_stack_var_in_codegen(decompilation, stack_offset: int) -> Optional[angr.sim_variable.SimStackVariable]:
        for var in decompilation.cfunc.variable_manager._unified_variables:
            if hasattr(var, "offset") and var.offset == stack_offset:
                return var

        return None

    @staticmethod
    def stack_var_type_str(decompilation, stack_var: angr.sim_variable.SimStackVariable):
        try:
            var_type = decompilation.cfunc.variable_manager.get_variable_type(stack_var)
        # pylint: disable=broad-except
        except Exception:
            return None

        return var_type.c_repr() if var_type is not None else None

    @staticmethod
    def stack_vars_in_dec(decompilation):
        for var in decompilation.cfunc.variable_manager._unified_variables:
            if hasattr(var, "offset"):
                yield var

    @staticmethod
    def func_args_as_declib_args(decompilation) -> Dict[int, FunctionArgument]:
        args = {}
        if not decompilation.cfunc.arg_list:
            return args
        
        for idx, arg in enumerate(decompilation.cfunc.arg_list):
            type_ = arg.variable_type.c_repr() if arg.variable_type is not None else None
            args[idx] = FunctionArgument(
                idx, arg.variable.name, type_, arg.variable.size
            )

        return args

    @staticmethod
    def func_insn_addrs(func: angr.knowledge_plugins.Function):
        insn_addrs = set()
        for block in func.blocks:
            insn_addrs.update(block.instruction_addrs)

        return insn_addrs

    def get_closest_function(self, addr):
        try:
            func_addr = self.workspace.main_instance.project.kb.cfgs.get_most_accurate()\
                .get_any_node(addr, anyaddr=True)\
                .function_address
        except AttributeError:
            func_addr = None

        return func_addr

    @staticmethod
    def line_map_from_decompilation(dec):
        import ailment
        from angr.analyses.decompiler.structured_codegen.c import CStructuredCodeWalker, CFunctionCall, CIfElse, CIfBreak

        if dec is None or dec.codegen is None:
            return None

        codegen = dec.codegen
        base_addr = dec.project.loader.main_object.image_base_delta
        if hasattr(dec, "unoptimized_ail_graph"):
            nodes = dec.unoptimized_ail_graph.nodes
        else:
            l.critical(f"You are likely using an older version of angr that has no unoptimized_ail_graph."
                       f" Using clinic_graph instead, results will be less accurate...")
            nodes = dec.clinic.cc_graph.nodes

        # get the mapping of the original AIL graph
        mapping = defaultdict(set)
        ail_node_addr_map = {
            node.addr: node for node in nodes
        }
        for addr, ail_block in ail_node_addr_map.items():
            # get instructions of this block
            try:
                vex_block = dec.project.factory.block(addr)
            except Exception:
                continue

            ail_block_stmts = [stmt for stmt in ail_block.statements if not isinstance(stmt, ailment.statement.Label)]
            if not ail_block_stmts:
                continue

            next_ail_stmt_idx = 0
            for ins_addr in vex_block.instruction_addrs:
                next_ail_stmt_addr = ail_block_stmts[next_ail_stmt_idx].ins_addr
                mapping[next_ail_stmt_addr].add(ins_addr)
                if ins_addr == next_ail_stmt_addr:
                    next_ail_stmt_idx += 1
                if next_ail_stmt_idx >= len(ail_block_stmts):
                    break

        # node to addr map
        ailaddr_to_addr = defaultdict(set)
        for k, v in mapping.items():
            for v_ in v:
                ailaddr_to_addr[k - base_addr].add(v_ - base_addr)

        codegen.show_externs = False
        codegen.regenerate_text()

        decompilation = codegen.text
        if not decompilation:
            return

        try:
            first_code_pos = codegen.map_pos_to_addr.items()[0][0]
        except Exception:
            return

        # map the position start to an address
        pos_addr_map = defaultdict(set)
        for start, pos_map in codegen.map_pos_to_addr.items():
            obj = pos_map.obj
            if not hasattr(obj, "tags"):
                continue

            # leads to mapping at the beginning of loops, so skip.
            # see kill.o binary for send_signals
            if isinstance(obj, CIfElse):
                continue

            ins_addr = obj.tags.get("ins_addr", None)
            if ins_addr:
                pos_addr_map[start].add(ins_addr - base_addr)

        # find every line
        line_end_pos = [i for i, x in enumerate(decompilation) if x == "\n"]
        line_to_addr = defaultdict(set)
        last_pos = len(decompilation) - 1
        line_to_addr[1].add(codegen.cfunc.addr - base_addr)
        for i, pos in enumerate(line_end_pos[:-1]):
            if pos == last_pos:
                break

            curr_end = line_end_pos[i+1] - 1
            # check if this is the variable decs and header
            if curr_end < first_code_pos:
                line_to_addr[i+2].add(codegen.cfunc.addr - base_addr)
                continue

            # not header, real code
            for p_idx in range(pos+1, curr_end+1):
                if p_idx in pos_addr_map:
                    # line_to_addr[str(i+1)].update(pos_addr_map[p_idx])
                    for ail_ins_addr in pos_addr_map[p_idx]:
                        if ail_ins_addr in ailaddr_to_addr:
                            line_to_addr[i+2].update(ailaddr_to_addr[ail_ins_addr])
                        else:
                            line_to_addr[i+2].add(ail_ins_addr)

        return line_to_addr
