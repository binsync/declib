import logging
from typing import Dict, Optional, List
from collections import OrderedDict, defaultdict
from packaging.version import Version
import declib
from declib.api.decompiler_interface import DecompilerInterface
from declib.artifacts import (
    StackVariable, Function, FunctionHeader, Struct, Comment, GlobalVariable, Enum, Patch, Artifact, Decompilation,
    Context, Typedef, Segment
)
from declib.api.decompiler_interface import requires_decompilation
from . import compat
from .artifact_lifter import IDAArtifactLifter
from .compat import get_ida_gui_version
from .hooks import ContextMenuHooks, ScreenHook, IDBHooks, IDPHooks, HexraysHooks

if compat.IDA_IS_INTERACTIVE:
    from . import ida_ui
else:
    try:
        # IDA 9+
        import idapro
    except ImportError:
        # IDA 9 Beta
        import ida as idapro

import idc
import idaapi
import ida_hexrays
import ida_auto


_l = logging.getLogger(name=__name__)


def _qt_shortcut_to_ida(shortcut: str) -> str:
    """Convert a Qt-style shortcut like "Ctrl+Shift+D" to IDA's "Ctrl-Shift-D"."""
    if not shortcut:
        return ""
    return shortcut.replace("+", "-")


#
#   Controller
#

class IDAInterface(DecompilerInterface):
    # idalib (IDA's headless mode) enforces main-thread-only API access and
    # raises ``RuntimeError: Function can be called from the main thread only``
    # when called from a worker thread. The DecompilerServer checks this flag
    # and routes backend calls through its main-thread dispatcher.
    requires_main_thread_dispatch = True

    def __init__(self, project_dir=None, **kwargs):
        self._ctx_menu_names = []
        self._ui_hooks = []
        self._artifact_watcher_hooks = []
        self._gui_active_context = None
        self._deleted_artifacts = defaultdict(set)
        self.cached_ord_to_type_names = {}
        # Optional cache directory where the .id* database files should live.
        self._project_dir = project_dir

        super().__init__(
            name="ida", qt_version=get_ida_gui_version(), artifact_lifter=IDAArtifactLifter(self),
            decompiler_available=compat.initialize_decompiler(), **kwargs
        )

        self._max_patch_size = 0xff
        self._decompiler_available = None
        self._dec_version = None
        self._ida_analysis_finished = False

        # GUI properties
        self._updated_ctx = None

    def _init_headless_components(self, *args, **kwargs):
        """
        This function initializes the headless functionality of IDA through idalib.
        This also means that this feature is only supported in IDA versions >= 9.0
        """
        super()._init_headless_components(*args, **kwargs)
        binary_path = str(self.binary_path)

        # If a saved database already exists (from a prior `save`), reopen it
        # directly. Passing the original binary + `-o<existing.i64>` makes
        # idalib prompt to overwrite, which hangs headless — and re-analyzing
        # would clobber the user's persisted renames/types/comments. Reopening
        # the .i64 with auto-analysis off is both fast and lossless.
        existing_db = self._existing_database_path()
        if existing_db is not None:
            _l.info("Reopening existing IDA database %s", existing_db)
            if idapro.open_database(existing_db, False):
                raise RuntimeError(f"Failed to reopen database {existing_db}")
            return

        extra_args = self._ida_open_args()
        # IDA <= 9.1 only accepts (path, run_auto_analysis); the extra_args
        # parameter was added in 9.2.
        if compat.get_ida_version() <= 910:
            if extra_args:
                _l.warning(
                    "project_dir/extra open args are only supported on IDA >= 9.2; ignoring %r.",
                    extra_args,
                )
            failure = idapro.open_database(binary_path, True)
        else:
            failure = idapro.open_database(binary_path, True, extra_args)
        if failure:
            raise RuntimeError(f"Failed to open database {binary_path}")

    def _ida_db_base(self):
        """Return the database base path (no extension) IDA writes to.

        With ``project_dir`` set the database lives at
        ``<project_dir>/ida/<binary>``; otherwise IDA drops it beside the
        binary. IDA appends ``.i64``/``.idb`` itself.
        """
        from pathlib import Path as _Path

        if not self._project_dir:
            return _Path(str(self.binary_path))
        project_dir = _Path(self._project_dir).expanduser().resolve()
        return project_dir / "ida" / _Path(str(self.binary_path)).name

    def _existing_database_path(self) -> Optional[str]:
        """Path to a previously-saved IDA database for this binary, or None."""
        base = self._ida_db_base()
        for ext in (".i64", ".idb"):
            candidate = base.parent / (base.name + ext)
            if candidate.exists():
                return str(candidate)
        return None

    def _ida_open_args(self) -> Optional[str]:
        """Build the extra args string passed to ``idapro.open_database``.

        When ``project_dir`` is configured we redirect IDA's database sidecar
        files (``.id0/.id1/.id2/.nam/.til``) into that directory using IDA's
        own ``-o<name>`` command-line flag. The sidecars go into a nested
        ``ida/`` subdirectory so they don't collide with anything else the
        user / other backends leave in the top-level project_dir (Ghidra's
        ``<binary>_ghidra/`` project, stale symlinks, etc.).
        """
        if not self._project_dir:
            return None

        db_base = self._ida_db_base()
        db_base.parent.mkdir(parents=True, exist_ok=True)
        # IDA's -o takes the database base path (no extension); it picks
        # .idb / .i64 / .id* itself.
        return f"-o{db_base}"

    def _deinit_headless_components(self):
        """
        This function deinitializes the headless functionality of IDA through idalib.
        This also means that this feature is only supported in IDA versions >= 9.0

        ``persist_on_close`` (default False) decides whether the IDB is written
        out on the way down. ``decompiler stop --save`` sets it (or calls
        ``save()`` explicitly) so the database survives; the default discards
        the in-memory database, matching legacy behavior.
        """
        idapro.close_database(bool(self.persist_on_close))

    def save(self, path=None) -> bool:
        """Write the current IDB to disk (durable rename/type/comment artifacts)."""
        return compat.save_database(path)

    def set_function_signature(self, func_addr, prototype: str) -> bool:
        """Apply a full prototype via IDA's SetType (atomic, avoids clobbering)."""
        lowered = self.art_lifter.lower_addr(func_addr)
        return compat.set_function_prototype(lowered, prototype)

    def _init_gui_hooks(self):
        """
        This function can only be called from inside the compat.GenericIDAPlugin and is meant for IDA code which
        should be run as a plugin.
        """
        self._ui_hooks = [
            ScreenHook(self),
            ContextMenuHooks(self, menu_strs=self._ctx_menu_names),
            IDPHooks(self),
        ]
        for hook in self._ui_hooks:
            hook.hook()

    def _term_gui_hooks(self):
        """
        Symmetric teardown for _init_gui_hooks. Must run before IDAPython tears
        down — otherwise a still-registered hook can fire during shutdown
        events (e.g. term_database) and try to re-enter a finalized Python.
        """
        for hook in self._ui_hooks:
            try:
                hook.unhook()
            except Exception:
                _l.exception("Failed to unhook %r", hook)
        self._ui_hooks = []

    def _init_gui_plugin(self, *args, **kwargs):
        self.decompiler_opened_event()
        plugin_cls_name = self._plugin_name + "_cls"
        IDAPluginCls = compat.generate_generic_ida_plugic_cls(cls_name=plugin_cls_name)
        return IDAPluginCls(*args, name=self._plugin_name, interface=self, **kwargs)

    @property
    def dec_version(self):
        if self._dec_version is None:
            self._dec_version = compat.get_decompiler_version()

        return self._dec_version

    #
    # GUI
    #

    def gui_ask_for_string(self, question, title="Plugin Question", default="") -> str:
        resp = idaapi.ask_str(default, 0, question)
        return resp if resp else ""

    def gui_ask_for_choice(self, question: str, choices: list, title="Plugin Question") -> str:
        return ida_ui.ask_choice(question, choices, title=title)

    def gui_register_ctx_menu(self, name, action_string, callback_func, category=None, shortcut=None) -> bool:
        ida_shortcut = _qt_shortcut_to_ida(shortcut) if shortcut else ""
        action = idaapi.action_desc_t(
            name,
            action_string,
            compat.GenericAction(name, callback_func, deci=self),
            ida_shortcut,
            action_string,
            199
        )
        idaapi.register_action(action)
        idaapi.attach_action_to_menu(
            f"Edit/{category}/{name}" if category else f"Edit/{name}",
            name,
            idaapi.SETMENU_APP
        )
        self._ctx_menu_names.append((name, category or ""))
        return True

    def gui_attach_qt_window(self, qt_window: type["QWidgt"], title: str, target_window=None, position=None, *args, **kwargs) -> bool:
        return ida_ui.attach_qt_widget(qt_window, title, target_window=None, position=None, *args, **kwargs)

    #
    # Mandatory API
    #

    @property
    def binary_base_addr(self) -> int:
        return compat.get_first_segment_base()

    @property
    def binary_hash(self) -> str:
        return idc.retrieve_input_file_md5().hex()

    @property
    def binary_path(self) -> Optional[str]:
        return self._binary_path or compat.get_binary_path()

    def get_func_size(self, func_addr) -> int:
        func_addr = self.art_lifter.lower_addr(func_addr)
        return compat.get_func_size(func_addr)

    @property
    def decompiler_available(self) -> bool:
        if self._decompiler_available is None:
            self._decompiler_available = ida_hexrays.init_hexrays_plugin()

        return self._decompiler_available

    def xrefs_to(self, artifact: Artifact, decompile=False, only_code=False) -> List[Artifact]:
        if not isinstance(artifact, Function):
            _l.warning("xrefs_to is only implemented for functions.")
            return []

        function: Function = self.art_lifter.lower(artifact)
        return self._collect_xrefs_to(function.addr, only_code=only_code)

    def xrefs_to_addr(self, addr: int, only_code: bool = False) -> List[Artifact]:
        lowered = self.art_lifter.lower_addr(addr)
        return self._collect_xrefs_to(lowered, only_code=only_code)

    def xrefs_from(self, func_addr: int) -> List[Function]:
        """Direct callees of ``func_addr`` — just the call targets, no data."""
        lowered = self.art_lifter.lower_addr(func_addr)
        func = compat.fast_get_function(lowered, get_rtype=False)
        if func is None:
            return []
        callees: List[Function] = []
        seen = set()
        # Walk every instruction in the function body; cheap because fauxware-
        # sized binaries are typical, and this is the same approach the
        # ``idautils.CodeRefsFrom`` helpers use under the hood.
        import ida_funcs as _ida_funcs  # local to keep interface.py clean
        ida_func = _ida_funcs.get_func(lowered)
        if ida_func is None:
            return []
        ea = ida_func.start_ea
        while ea < ida_func.end_ea and ea != idaapi.BADADDR:
            for callee_ea in compat.xrefs_from(ea):
                callee_func_addr = compat.ida_func_addr(callee_ea) or callee_ea
                if callee_func_addr in seen:
                    continue
                seen.add(callee_func_addr)
                lifted = self.art_lifter.lift_addr(callee_func_addr)
                fast_func = self.fast_get_function(lifted) or Function(lifted, 0)
                callees.append(fast_func)
            ea = idc.next_head(ea, ida_func.end_ea)
        return callees

    def list_strings(self, filter: Optional[str] = None) -> List[tuple]:
        import re as _re
        pattern = _re.compile(filter) if filter else None
        out = []
        for ea, text in compat.list_strings():
            if pattern is not None and not pattern.search(text):
                continue
            out.append((self.art_lifter.lift_addr(ea), text))
        out.sort(key=lambda item: item[0])
        return out

    def disassemble(self, addr: int, **kwargs) -> Optional[str]:
        lowered = self.art_lifter.lower_addr(addr)
        return compat.disassemble_function(lowered)

    def read_memory(self, addr: int, size: int) -> Optional[bytes]:
        if size <= 0:
            return b""
        lowered = self.art_lifter.lower_addr(addr)
        return compat.read_memory(lowered, size)

    def search_bytes(self, pattern: bytes, max_results: int = 100) -> List[int]:
        return [self.art_lifter.lift_addr(ea) for ea in compat.search_bytes(pattern, max_results)]

    def list_imports(self) -> List[tuple]:
        out = []
        for ea, name, lib in compat.list_imports():
            out.append((self.art_lifter.lift_addr(ea), name, lib))
        return out

    def define_function(self, addr) -> bool:
        return compat.define_function(self.art_lifter.lower_addr(addr))

    def define_code(self, addr) -> bool:
        return compat.define_code(self.art_lifter.lower_addr(addr))

    def define_data(self, addr, type_str=None, size=None) -> bool:
        return compat.define_data(self.art_lifter.lower_addr(addr), type_str, size)

    def undefine(self, addr, size=1) -> bool:
        return compat.undefine(self.art_lifter.lower_addr(addr), size)

    def _collect_xrefs_to(self, lowered_addr: int, only_code: bool,
                          _max_chase: int = 2) -> List[Artifact]:
        """Collect function-level xrefs to ``lowered_addr``.

        PIE binaries route string / global references through indirection
        tables (GOT / _RDATA pointer arrays), so a direct
        ``idautils.XrefsTo(str_addr)`` only lands on the pointer — not on
        the code that dereferences it. We BFS up to ``_max_chase`` levels
        of data indirection so ``xrefs_to SOSNEAKY`` can still name the
        caller.
        """
        visited_targets: set = set()
        seen_funcs: set = set()
        xrefs: List[Artifact] = []

        frontier = [(lowered_addr, 0)]
        while frontier:
            target, depth = frontier.pop(0)
            if target in visited_targets:
                continue
            visited_targets.add(target)

            for ida_xref in compat.xrefs_to(target):
                if only_code and not ida_xref.iscode:
                    continue
                from_ea = int(ida_xref.frm)
                from_func_addr = compat.ida_func_addr(from_ea)
                if from_func_addr is not None:
                    if from_func_addr in seen_funcs:
                        continue
                    seen_funcs.add(from_func_addr)
                    lifted = self.art_lifter.lift_addr(from_func_addr)
                    fast_func = self.fast_get_function(lifted) or Function(lifted, 0)
                    xrefs.append(fast_func)
                elif depth < _max_chase and not only_code:
                    # data-to-data indirection: chase one hop further.
                    frontier.append((from_ea, depth + 1))
        return xrefs

    def get_decompilation_object(self, function: Function, do_lower=True, **kwargs) -> Optional[object]:
        function = self.art_lifter.lower(function) if do_lower else function
        dec = ida_hexrays.decompile(function.addr)
        if dec is None:
            return None

        return dec

    def _decompile(self, function: Function, map_lines=False, **kwargs) -> Optional[Decompilation]:
        try:
            cfunc = ida_hexrays.decompile(function.addr)
            if cfunc is None:
                return None
        except Exception:
            return None

        decompilation = Decompilation(addr=function.addr, text=str(cfunc), decompiler=self.name)
        if map_lines:
            linenum_to_addr = defaultdict(set)
            # always add the start as line 1
            linenum_to_addr[1].add(cfunc.entry_ea)

            # find all lines 2 - N
            for addr, lines in cfunc.get_eamap().items():
                for line in lines:
                    y_holder = idaapi.int_pointer()
                    if not cfunc.find_item_coords(line, None, y_holder):
                        continue

                    linenum = y_holder.value()
                    linenum_to_addr[linenum].add(addr)

            decompilation.line_map = {k: v for k, v in linenum_to_addr.items()}

        return decompilation

    def fast_get_function(self, func_addr) -> Optional[Function]:
        lowered_addr = self.art_lifter.lower_addr(func_addr)
        lowered_func = compat.fast_get_function(lowered_addr, get_rtype=False)
        if lowered_func is None:
            #_l.error(f"Function does not exist at {lowered_addr}")
            return None

        return self.art_lifter.lift(lowered_func)

    #
    # GUI API
    #

    def start_artifact_watchers(self):
        super().start_artifact_watchers()
        # TODO: this is a hack for backwards compatibility and should be removed in IDA 9
        idb_hook = IDBHooks(self)
        if self.decompiler_available and self.dec_version < Version("8.4"):
            idb_hook.local_types_changed = lambda: 0
        else:
            # this code in this block must exist in 9.0, so don't delete it!
            self.cached_ord_to_type_names = compat.get_ord_to_type_names()

        self._artifact_watcher_hooks = [
            idb_hook,
            # this hook is special because it relies on the decompiler being present, which can only be checked
            # after the plugin loading phase. this means the user will need to manually init this hook in the UI
            # either through scripting or a UI.
            HexraysHooks(self),
        ]
        for hook in self._artifact_watcher_hooks:
            hook.hook()

    def stop_artifact_watchers(self):
        super().stop_artifact_watchers()
        for hook in self._artifact_watcher_hooks:
            hook.unhook()

    def gui_active_context(self) -> Context:
        if self._gui_active_context is None:
            # in cases that we end up here, we are likely in UI mode, without artifact watchers started,
            # so we should not cache this result (as it will be stale)
            low_addr, low_func_addr = compat.get_function_cursor_at()
            return self.art_lifter.lift(Context(addr=low_addr, func_addr=low_func_addr))

        return self._gui_active_context

    def gui_goto(self, func_addr) -> None:
        func_addr = self.art_lifter.lower_addr(func_addr)
        compat.jumpto(func_addr)

    def gui_show_type(self, type_name: str) -> None:
        compat.jumpto_type(type_name)

    def should_watch_artifacts(self) -> bool:
        # never do hooks while IDA is in initial startup phase
        if not self._ida_analysis_finished:
            self._ida_analysis_finished = ida_auto.auto_is_ok()

        return self._ida_analysis_finished and self.artifact_watchers_started

    #
    # Optional API
    #

    @requires_decompilation
    def local_variable_names(self, func: Function) -> List[str]:
        dec = func.dec_obj
        if dec is None:
            return []

        return [lvar.name for lvar in dec.get_lvars() if lvar.name]

    @requires_decompilation
    def rename_local_variables_by_names(self, func: Function, name_map: Dict[str, str], **kwargs) -> bool:
        func = self.art_lifter.lower(func)
        return compat.rename_local_variables_by_names(func, name_map)

    #
    # Artifact API
    #

    # functions
    def _set_function(self, func: Function, **kwargs) -> bool:
        """
        Overrides the normal _set_function for speed optimizations
        """
        return compat.set_function(func, headless=self.headless, decompiler_available=self.decompiler_available, **kwargs)

    def _get_function(self, addr, **kwargs) -> Optional[Function]:
        return compat.function(addr, headless=self.headless, decompiler_available=self.decompiler_available, **kwargs)

    def _functions(self) -> Dict[int, Function]:
        return compat.functions()

    # stack vars
    def _set_stack_variable(self, svar: StackVariable, **kwargs) -> bool:
        _l.warning("Setting stack vars using this API is deprecared. Use _set_function instead.")
        return False

    # global variables
    def _set_global_variable(self, gvar: GlobalVariable, **kwargs) -> bool:
        modified = False
        if gvar.name:
            modified |= compat.set_global_var_name(gvar.addr, gvar.name)
        if gvar.type:
            modified |= compat.set_global_var_type(gvar.addr, gvar.type)

        return modified

    def _get_global_var(self, addr) -> Optional[GlobalVariable]:
        return compat.global_var(addr)

    def _global_vars(self, **kwargs) -> Dict[int, GlobalVariable]:
        """
        Returns a dict of declib.GlobalVariable that contain the addr and size of each global var.
        Note: this does not contain the live artifacts of the Artifact, only the minimum knowledge to that the Artifact
        exists. To get live artifacts, use the singleton function of the same name.

        @return:
        """
        return compat.global_vars()

    # structs
    def _set_struct(self, struct: Struct, header=True, members=True, **kwargs) -> bool:
        data_changed = False
        if self.decompiler_available and self.dec_version < Version("8.3") and "gcc_va_list" in struct.name:
            _l.critical("Syncing the struct %s in IDA Pro 8.2 <= will cause a crash. Skipping...", struct.name)
            return False

        if header:
            data_changed |= compat.set_ida_struct(struct)

        if members:
            data_changed |= compat.set_ida_struct_member_types(struct)

        return data_changed

    def _get_struct(self, name) -> Optional[Struct]:
        return compat.struct(name)

    def _del_struct(self, name) -> bool:
        return compat.del_ida_struct(name)

    def _structs(self) -> Dict[str, Struct]:
        """
        Returns a dict of declib.Structs that contain the name and size of each struct in the decompiler.
        Note: this does not contain the live artifacts of the Artifact, only the minimum knowledge to that the Artifact
        exists. To get live artifacts, use the singleton function of the same name.

        @return:
        """
        return compat.structs()

    # enums
    def _set_enum(self, enum: Enum, **kwargs) -> bool:
        return compat.set_enum(enum)

    def _get_enum(self, name) -> Optional[Enum]:
        return compat.enum(name)

    def _enums(self) -> Dict[str, Enum]:
        """
        Returns a dict of declib.Enum that contain the name of the enums in the decompiler.
        Note: this does not contain the live artifacts of the Artifact, only the minimum knowledge to that the Artifact
        exists. To get live artifacts, use the singleton function of the same name.

        @return:
        """
        return compat.enums()

    # typedefs
    def _set_typedef(self, typedef: Typedef, **kwargs) -> bool:
        return compat.set_typedef(typedef)

    def _get_typedef(self, name) -> Optional[Typedef]:
        return compat.typedef(name)

    def _typedefs(self) -> Dict[str, Typedef]:
        return compat.typedefs()

    # patches
    def _set_patch(self, patch: Patch, **kwargs) -> bool:
        idaapi.patch_bytes(patch.addr, patch.bytes)
        return True

    def _get_patch(self, addr) -> Optional[Patch]:
        patches = self._collect_continuous_patches(min_addr=addr-1, max_addr=addr+self._max_patch_size, stop_after_first=True)
        return patches.get(addr, None)

    def _patches(self) -> Dict[int, Patch]:
        """
        Returns a dict of declib.Patch that contain the addr of each Patch and the bytes.
        Note: this does not contain the live artifacts of the Artifact, only the minimum knowledge to that the Artifact
        exists. To get live artifacts, use the singleton function of the same name.

        @return:
        """
        return self._collect_continuous_patches()

    # comments
    def _set_comment(self, comment: Comment, **kwargs) -> bool:
        return compat.set_ida_comment(comment.addr, comment.comment, decompiled=comment.decompiled)

    def _get_comment(self, addr) -> Optional[Comment]:
        ida_cmt = compat.get_ida_comment(addr)
        if ida_cmt is None:
            return None

        return Comment(addr=addr, comment=str(ida_cmt), decompiled=True)

    def _del_comment(self, addr) -> bool:
        return compat.del_ida_comment(addr)

    def _comments(self) -> Dict[int, Comment]:
        return compat.comments()

    # segments
    def _set_segment(self, segment: Segment, **kwargs) -> bool:
        return compat.set_segment(segment)

    def _get_segment(self, name) -> Optional[Segment]:
        return compat.segment(name)

    def _del_segment(self, name) -> bool:
        return compat.del_segment(name)

    def _segments(self) -> Dict[str, Segment]:
        return compat.segments()

    # others...
    def _set_function_header(self, fheader: FunctionHeader, **kwargs) -> bool:
        return compat.set_function_header(fheader)

    #
    # utils
    #

    @staticmethod
    def _ea_to_func(addr):
        if not addr or addr == idaapi.BADADDR:
            return None

        func_addr = compat.ida_func_addr(addr)
        if func_addr is None:
            return None

        func = declib.artifacts.Function(
            func_addr, 0, header=FunctionHeader(compat.get_func_name(func_addr), func_addr)
        )
        return func

    @staticmethod
    def _collect_continuous_patches(min_addr=None, max_addr=None, stop_after_first=False) -> Dict[int, Patch]:
        patches = {}

        def _patch_collector(ea, fpos, org_val, patch_val):
            patches[ea] = bytes([patch_val])

        if min_addr is None:
            min_addr = idaapi.inf_get_min_ea()
        if max_addr is None:
            max_addr = idaapi.inf_get_max_ea()

        if min_addr is None or max_addr is None:
            return patches

        idaapi.visit_patched_bytes(min_addr, max_addr, _patch_collector)

        # now convert into continuous patches
        continuous_patches = defaultdict(bytes)
        patch_start = None
        last_pos = None
        for pos, patch in patches.items():
            should_break = False
            if last_pos is None or pos != last_pos + 1:
                patch_start = pos

                if last_pos is not None and stop_after_first:
                    should_break = True

            continuous_patches[patch_start] += patch
            if should_break:
                break

            last_pos = pos

        # convert the patches
        continuous_patches = dict(continuous_patches)
        normalized_patches = {
            offset: Patch(offset, _bytes)
            for offset, _bytes in continuous_patches.items()
        }

        return normalized_patches

