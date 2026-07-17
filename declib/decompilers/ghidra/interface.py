import os
import re
import sys
import time
import typing
from collections import defaultdict
from pathlib import Path
from typing import Optional, Dict, List, Tuple, Union
import logging
import queue
import threading

from declib.api import DecompilerInterface, CType
from declib.api.decompiler_interface import requires_decompilation
from declib.artifacts import (
    Function, FunctionHeader, StackVariable, Comment, FunctionArgument, GlobalVariable, Struct, StructMember, Enum,
    Decompilation, Context, Artifact, Typedef
)

from .artifact_lifter import GhidraArtifactLifter
from .compat.transaction import ghidra_transaction
from .compat.headless import close_program, open_program, save_program
from .compat.state import get_current_address

if typing.TYPE_CHECKING:
    from ghidra.program.model.listing import Function as GhidraFunction, Program
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.pcode import HighSymbol



_l = logging.getLogger(__name__)


class GhidraDecompilerInterface(DecompilerInterface):
    CACHE_TIMEOUT = 5
    # GUI-backed Ghidra program APIs are not safe to enter concurrently from
    # arbitrary socket worker threads. DecompilerServer routes calls through
    # its main-thread dispatcher when this is enabled.
    requires_main_thread_dispatch = True
    _program: Optional["Program"]
    flat_api: "FlatProgramAPI"

    def __init__(
        self,
        flat_api=None,
        loop_on_plugin=True,
        start_headless_watchers=False,
        analyze=True,
        project_location: Optional[Union[str, Path]] = None,
        project_name: Optional[str] = None,
        program_name: Optional[str] = None,
        program_obj: Optional["Program"] = None,
        language: Optional[str] = None,
        **kwargs
    ):
        self.loop_on_plugin = loop_on_plugin
        self.flat_api = flat_api

        # headless-only attributes
        self._start_headless_watchers = start_headless_watchers
        self._headless_analyze = analyze
        self._headless_project_location = project_location
        self._headless_project_name = project_name
        self._program_name = program_name
        self._project = None
        self._program = program_obj
        self._language = language

        # ui-only attributes
        self._data_monitor = None

        # cachable attributes
        self._active_ctx = None
        self._binary_base_addr = None
        self._default_pointer_size = None
        self._gsym_size = None
        self._max_gsym_size = 50_000

        # main thread queue
        self._main_thread_queue = queue.Queue()
        self._results_queue = queue.Queue()
        self.requires_main_thread_dispatch = not kwargs.get("headless", False)

        # Ghidra flushes the ProgramDB into the project on teardown by default,
        # so a reload already sees prior work. `decompiler stop --discard` flips
        # this off to drop unsaved edits.
        self.persist_on_close = True

        super().__init__(
            name="ghidra",
            artifact_lifter=GhidraArtifactLifter(self),
            supports_undo=True,
            supports_type_scopes=True,
            default_func_prefix="FUN_",
            **kwargs
        )

    def _init_gui_components(self, *args, **kwargs):
        # XXX: yeah, this is bad naming!
        if self._start_headless_watchers:
            self.start_artifact_watchers()

        super()._init_gui_components(*args, **kwargs)

    def _deinit_headless_components(self):
        if self._program is not None and self._project is not None:
            close_program(self._program, self._project, save=bool(self.persist_on_close))
            self._project = None
            self._program = None

    def save(self, path=None) -> bool:
        """Persist the Ghidra program into its project on disk.

        ``path`` is ignored: Ghidra saves back into the project the binary was
        imported into (set via ``--project-dir``). Returns False when running
        against a caller-provided program with no owned project.
        """
        if self._program is None or self._project is None:
            _l.warning("No owned Ghidra project to save (program provided externally).")
            return False
        return save_program(self._program, self._project)

    def _init_headless_components(self, *args, **kwargs):
        if self._program is not None:
            # We were already provided a program object as part of the instantiation, so just use it
            from ghidra.program.flatapi import FlatProgramAPI
            self.flat_api = FlatProgramAPI(self._program)
            return

        else:
            # This interface was not explicitly initialized as part of a GhidraScript, do the setup on our own
            if os.getenv("GHIDRA_INSTALL_DIR", None) is None:
                raise RuntimeError("GHIDRA_INSTALL_DIR must be set in the environment to use Ghidra headless.")

            flat_api, project, program = open_program(
                binary_path=self._binary_path,
                analyze=self._headless_analyze,
                project_location=self._headless_project_location,
                project_name=self._headless_project_name,
                program_name=self._program_name,
                language=self._language,
            )
            self._program = program
            self._project = project
            self.flat_api = flat_api
        if flat_api is None:
            raise RuntimeError("Failed to open program with Pyhidra")

    #
    # GUI
    #

    def start_artifact_watchers(self):
        if self.headless:
            _l.warning("Artifact watching is not supported in headless mode.")
            return

        from .hooks import create_data_monitor
        if not self.artifact_watchers_started:
            if self.flat_api is None:
                raise RuntimeError("Cannot start artifact watchers without FlatProgramAPI.")

            self._data_monitor = create_data_monitor(self)
            self.currentProgram.addListener(self._data_monitor)
            super().start_artifact_watchers()

    def stop_artifact_watchers(self):
        if self.artifact_watchers_started:
            self._data_monitor = None
            # TODO: generalize superclass method?
            super().stop_artifact_watchers()

    def gui_run_on_main_thread(self, func, *args, **kwargs):
        self._main_thread_queue.put((func, args, kwargs))
        return self._results_queue.get()

    def gui_register_ctx_menu(self, name, action_string, callback_func, category=None, shortcut=None) -> bool:
        from .hooks import create_context_action

        def callback_func_wrap(*args, **kwargs):
            try:
                callback_func(*args, **kwargs)
            except Exception as e:
                self.warning(f"Exception in ctx menu callback {name}: {e}")
                raise
        create_context_action(
            name, action_string, callback_func_wrap, category=(category or "DecLib"),
            tool=self.flat_api.getState().getTool(), shortcut=shortcut,
        )
        return True

    def gui_ask_for_string(self, question, title="Plugin Question", default="") -> str:
        answer = self.flat_api.askString(title, question, default)
        return answer if answer else ""

    def gui_ask_for_choice(self, question: str, choices: list, title="Plugin Question") -> str:
        answer = self.flat_api.askChoice(title, question, choices, choices[0])
        return answer if answer else ""

    def gui_active_context(self) -> Optional[Context]:
        active_addr = get_current_address(flat_api=self.flat_api)
        if (self._active_ctx is None) or (active_addr is not None and self._active_ctx.addr != active_addr):
            gfuncs = self.__fast_function(active_addr)
            gfunc = gfuncs[0] if gfuncs else None
            # TODO: support scree_name
            context = Context(addr=active_addr)
            if gfunc is not None:
                context.func_addr = int(gfunc.getEntryPoint().getOffset())

            self._active_ctx = self.art_lifter.lift(context)

        return self._active_ctx

    def gui_goto(self, func_addr) -> None:
        func_addr = self.art_lifter.lower_addr(func_addr)
        self.flat_api.goTo(self._to_gaddr(func_addr))

    #
    # Mandatory API
    #

    def fast_get_function(self, func_addr) -> Optional[Function]:
        lowered_addr = self.art_lifter.lower_addr(func_addr)
        gfuncs = self.__fast_function(lowered_addr)
        gfunc = gfuncs[0] if gfuncs else None
        if gfunc is None:
            _l.error("Func does not exist at %s", lowered_addr)

        bs_func = self._gfunc_to_bsfunc(gfunc)
        lifted_func = self.art_lifter.lift(bs_func)
        return lifted_func

    @property
    def binary_base_addr(self) -> int:
        if self._binary_base_addr is None:
            self._binary_base_addr = self._get_first_segment_base()

        return self._binary_base_addr

    @property
    def binary_hash(self) -> str:
        return self.currentProgram.executableMD5

    @property
    def binary_path(self) -> Optional[str]:
        return self.currentProgram.executablePath

    def get_func_size(self, func_addr) -> int:
        func_addr = self.art_lifter.lower_addr(func_addr)
        gfunc = self._get_nearest_function(func_addr)
        if gfunc is None:
            _l.critical("Failed to get function size for %s, likely a lifting error, report!", func_addr)
            return -1

        return int(gfunc.getBody().getNumAddresses())

    def _decompile(self, function: Function, map_lines=False, **kwargs) -> Optional[Decompilation]:
        dec_obj = self.get_decompilation_object(function, do_lower=False)
        if dec_obj is None:
            return None

        dec_results = dec_obj
        dec_func = dec_results.getDecompiledFunction()
        if dec_func is None:
            return None

        decompilation = Decompilation(addr=function.addr, text=str(dec_func.getC()), decompiler=self.name)
        if map_lines:
            from .compat.imports import PrettyPrinter

            g_func = dec_results.function
            linenum_to_addr = defaultdict(set)
            linenum_to_addr[1].add(function.addr)
            pp = PrettyPrinter(g_func, dec_results.getCCodeMarkup(), None)
            for line in pp.getLines():
                ln = line.getLineNumber()
                for i in range(line.getNumTokens()):
                    min_addr = line.getToken(i).getMinAddress()
                    if min_addr is None:
                        continue

                    linenum_to_addr[ln].add(min_addr.offset)
                    max_addr = line.getToken(i).getMaxAddress()
                    if max_addr is not None:
                        linenum_to_addr[ln].add(max_addr.offset)

            decompilation.line_map = {
                k: list(v) for k, v in dict(linenum_to_addr).items()
            }

        return decompilation

    def get_decompilation_object(self, function: Function, do_lower=True) -> Optional[object]:
        lowered_addr = self.art_lifter.lower_addr(function.addr) if do_lower else function.addr
        return self._ghidra_decompile(self._get_nearest_function(lowered_addr))

    def xrefs_from(self, func_addr: int) -> List[Function]:
        """Ghidra callees: use Function.getCalledFunctions for an O(1) hit per caller."""
        from .compat.imports import ConsoleTaskMonitor

        lowered = self.art_lifter.lower_addr(func_addr)
        gfunc = self._get_nearest_function(lowered)
        if gfunc is None:
            return []
        callees: List[Function] = []
        seen = set()
        try:
            for called_gfunc in gfunc.getCalledFunctions(ConsoleTaskMonitor()):
                entry_addr = int(called_gfunc.getEntryPoint().getOffset())
                if entry_addr in seen:
                    continue
                seen.add(entry_addr)
                func = Function(
                    addr=entry_addr,
                    size=int(called_gfunc.getBody().getNumAddresses()),
                    header=FunctionHeader(name=str(called_gfunc.getName()), addr=entry_addr),
                )
                callees.append(self.art_lifter.lift(func))
        except Exception as exc:
            _l.warning("Ghidra xrefs_from(0x%x) failed: %s", func_addr, exc)
        return callees

    def xrefs_to_addr(self, addr: int, only_code: bool = False) -> List[Artifact]:
        """Ghidra data-xref lookup: walk ReferenceManager refs to ``addr``.

        Backends' stock ``xrefs_to(Function)`` only fires on function entry
        points, so it misses data refs to string constants, globals, etc.
        This uses Ghidra's ReferenceManager directly and resolves each
        referencing instruction back to its containing function.
        """
        lowered = self.art_lifter.lower_addr(addr)
        return self._ghidra_refs_to_address(lowered, only_code=only_code)

    def _ghidra_refs_to_address(self, lowered_addr: int, only_code: bool = False) -> List[Artifact]:
        refs: List[Artifact] = []
        seen_funcs = set()
        try:
            gaddr = self._to_gaddr(lowered_addr)
            reference_manager = self.currentProgram.getReferenceManager()
            function_manager = self.currentProgram.getFunctionManager()
            ref_iter = reference_manager.getReferencesTo(gaddr)
            while ref_iter.hasNext():
                ref = ref_iter.next()
                from_addr_g = ref.getFromAddress()
                if only_code:
                    ref_type = ref.getReferenceType()
                    try:
                        is_data = ref_type.isData()
                    except Exception:
                        is_data = False
                    if is_data:
                        continue
                gfunc = function_manager.getFunctionContaining(from_addr_g)
                if gfunc is None:
                    continue
                entry_addr = int(gfunc.getEntryPoint().getOffset())
                if entry_addr in seen_funcs:
                    continue
                seen_funcs.add(entry_addr)
                func = Function(
                    addr=entry_addr,
                    size=int(gfunc.getBody().getNumAddresses()),
                    header=FunctionHeader(name=str(gfunc.getName()), addr=entry_addr),
                )
                refs.append(self.art_lifter.lift(func))
        except Exception as exc:
            _l.warning("Ghidra reference lookup at 0x%x failed: %s", lowered_addr, exc)
        return refs

    def xrefs_to(self, artifact: Artifact, decompile=False, only_code=False) -> List[Artifact]:
        if not isinstance(artifact, Function):
            raise ValueError("Only functions are supported for xrefs_to")

        # Base function-level xref: who references the entry point.
        # Without this, get_callgraph() + xref_from are empty on Ghidra
        # because the base class returns `[]`.
        lowered = self.art_lifter.lower(artifact)
        xrefs = self._ghidra_refs_to_address(lowered.addr, only_code=only_code)
        if not decompile:
            return xrefs

        artifact: Function
        if artifact.dec_obj is None:
            artifact = self.functions[artifact.addr]
        decompilation_results = self.get_decompilation_object(artifact, do_lower=True)

        high_function = decompilation_results.getHighFunction()
        if high_function is None:
            return xrefs

        new_xrefs = []
        for global_sym in high_function.getGlobalSymbolMap().getSymbols():
            sym_storage = global_sym.getStorage()
            if not sym_storage.isMemoryStorage():
                continue

            gvar = GlobalVariable(
                addr=int(sym_storage.getMinAddress().getOffset()),
                name=str(global_sym.getName()),
                type_=str(global_sym.getDataType().getPathName()) if global_sym.getDataType() else None,
                size=int(global_sym.getSize()),
            )
            new_xrefs.append(self.art_lifter.lift(gvar))

        # xrefs are already lifted by _ghidra_refs_to_address; only new_xrefs need lifting.
        return xrefs + new_xrefs

    def list_strings(self, filter: Optional[str] = None) -> List[Tuple[int, str]]:
        pattern = re.compile(filter) if filter else None
        found: Dict[int, str] = {}
        try:
            program = self.currentProgram
            listing = program.getListing()
            memory = program.getMemory()
            base_addr = self.binary_base_addr

            def _record(gaddr, text: str) -> None:
                if not text:
                    return
                block = memory.getBlock(gaddr) if memory is not None else None
                if block is None:
                    return
                try:
                    if not block.isLoaded():
                        return
                except Exception:
                    pass
                if gaddr.isNonLoadedMemoryAddress():
                    return
                addr = int(gaddr.getOffset())
                # Java signed longs can surface negative values for synthetic
                # addresses (ELF section name tables, overlays, etc.).
                if addr < base_addr:
                    return
                if pattern is not None and not pattern.search(text):
                    return
                # First writer wins — defined-data results carry the
                # decompiler's own typing / encoding, so we prefer them
                # over raw StringSearcher hits at the same address.
                found.setdefault(addr, text)

            # Pass 1: strings the decompiler has already committed to a
            # defined data type (char[], TerminatedCString, unicode).
            data_iter = listing.getDefinedData(True)
            while data_iter.hasNext():
                data = data_iter.next()
                if not data.hasStringValue():
                    continue
                try:
                    raw = data.getValue()
                    text = str(raw) if raw is not None else ""
                except Exception:
                    continue
                _record(data.getAddress(), text)

            # Pass 2: ask Ghidra's own StringSearcher to scan initialized
            # memory for ASCII runs. Ghidra's auto-analyzer misses sequences
            # that it instead typed as `byte[N]` (e.g. a base64 alphabet
            # stored as `uchar[64]`). This uses Ghidra's native detector —
            # no parallel byte scanning.
            self._scan_strings_via_searcher(program, memory, _record)
        except Exception as exc:
            _l.warning("Ghidra list_strings failed: %s", exc)

        results: List[Tuple[int, str]] = [
            (self.art_lifter.lift_addr(addr), text)
            for addr, text in found.items()
        ]
        results.sort(key=lambda item: item[0])
        return results

    def _scan_strings_via_searcher(self, program, memory, record) -> None:
        """Run Ghidra's StringSearcher over loaded memory.

        The searcher is the same component Ghidra's "Search > For Strings"
        command uses. This catches ASCII runs that Ghidra auto-typed as
        ``byte[N]`` / ``uchar[N]`` instead of promoting to a string (e.g. a
        base64 alphabet stored as ``uchar[64]``).
        """
        try:
            from ghidra.program.util.string import StringSearcher, FoundStringCallback
            from ghidra.util.task import TaskMonitor
            from jpype import JImplements, JOverride
        except Exception as exc:
            _l.warning("StringSearcher unavailable, skipping supplemental scan: %s", exc)
            return

        @JImplements(FoundStringCallback)
        class _Collector:
            def __init__(self, mem, on_string):
                self._mem = mem
                self._on_string = on_string

            @JOverride
            def stringFound(self, found_string):
                try:
                    text = found_string.getString(self._mem)
                except Exception:
                    return
                if text is None:
                    return
                self._on_string(found_string.getAddress(), str(text))

        try:
            # ctor args: program, minStringSize, alignment, allCharSizes,
            # requireNullTermination. allCharSizes=False keeps us on ASCII;
            # the UTF variants would otherwise inflate results with noise.
            searcher = StringSearcher(program, 4, 1, False, False)
            scan_set = memory.getLoadedAndInitializedAddressSet()
            # TaskMonitor.DUMMY is non-null but does nothing — passing None
            # here crashes with NullPointerException inside AbstractStringSearcher.
            searcher.search(scan_set, _Collector(memory, record), True, TaskMonitor.DUMMY)
        except Exception as exc:
            _l.warning("StringSearcher pass failed: %s", exc)

    def disassemble(self, addr: int, **kwargs) -> Optional[str]:
        lowered = self.art_lifter.lower_addr(addr)
        func = self._get_nearest_function(lowered)
        if func is None:
            return None

        lines: List[str] = []
        try:
            listing = self.currentProgram.getListing()
            body = func.getBody()
            insn_iter = listing.getInstructions(body, True)
            while insn_iter.hasNext():
                insn = insn_iter.next()
                try:
                    insn_addr = int(insn.getAddress().getOffset())
                    lifted = self.art_lifter.lift_addr(insn_addr)
                    lines.append(f"0x{lifted:x}:\t{str(insn)}")
                except Exception:
                    continue
        except Exception as exc:
            _l.warning("Ghidra disassemble failed: %s", exc)
            return None
        return "\n".join(lines) if lines else None

    def read_memory(self, addr: int, size: int) -> Optional[bytes]:
        if size <= 0:
            return b""
        lowered = self.art_lifter.lower_addr(addr)
        try:
            import jpype
            memory = self.currentProgram.getMemory()
            gaddr = self._to_gaddr(lowered)
            byte_array = jpype.JArray(jpype.JByte)(size)
            # Memory.getBytes returns the count of bytes copied; on partial
            # reads it raises MemoryAccessException, which we treat as the
            # caller asked for memory we can't reach.
            try:
                read = int(memory.getBytes(gaddr, byte_array))
            except Exception as exc:
                _l.debug("Ghidra read_memory at 0x%x size=%d failed: %s", lowered, size, exc)
                return None
            if read <= 0:
                return b""
            # JByte values arrive as signed Python ints; mask back to unsigned
            # so the resulting bytes match what the binary stores on disk.
            return bytes(int(b) & 0xFF for b in byte_array[:read])
        except Exception as exc:
            _l.warning("Ghidra read_memory failed: %s", exc)
            return None

    #
    # Extra API
    #

    @property
    def default_pointer_size(self) -> int:
        if self._default_pointer_size is None:
            self._default_pointer_size = int(self.currentProgram.getDefaultPointerSize())

        return self._default_pointer_size

    def undo(self):
        self.currentProgram.undo()

    @requires_decompilation
    def local_variable_names(self, func: Function) -> List[str]:
        symbols_by_name = self._get_local_variable_symbols(func)
        return list(name for name, _ in symbols_by_name)

    @requires_decompilation
    def rename_local_variables_by_names(self, func: Function, name_map: Dict[str, str], **kwargs) -> bool:
        symbols_by_name = {name: sym for name, sym in self._get_local_variable_symbols(func)}
        symbols_to_update = {}
        for name, new_name in name_map.items():
            if name not in symbols_by_name or symbols_by_name[name].name == new_name or new_name in symbols_by_name:
                continue

            sym: "HighSymbol" = symbols_by_name[name]
            symbols_to_update[sym] = (new_name, None)

        return self._update_local_variable_symbols(symbols_to_update) if symbols_to_update else False

    #
    # Private Artifact API
    #

    def _set_function(self, func: Function, **kwargs) -> bool:
        decompilation = self._ghidra_decompile(self._get_nearest_function(func.addr))
        changes = super()._set_function(func, decompilation=decompilation, **kwargs)
        return changes

    def _get_function(self, addr, **kwargs) -> Optional[Function]:
        func = self._get_nearest_function(addr)
        if func is None:
            return None

        dec = self._ghidra_decompile(func)
        stack_variables = self._stack_variables(addr, decompilation=dec)
        args = self._function_args(addr, decompilation=dec)
        type_ = self._function_type(addr, decompilation=dec)
        func_addr = int(func.getEntryPoint().getOffset())
        return Function(
            addr=func_addr,
            size=int(func.getBody().getNumAddresses()),
            header=FunctionHeader(name=func.getName(), addr=func_addr, args=args, type_=type_),
            stack_vars=stack_variables, dec_obj=dec
        )

    def _functions(self) -> Dict[int, Function]:
        funcs = {}
        func_info = self.__functions()
        for addr, name, size in func_info:
            funcs[addr] = Function(
                addr=addr, size=size, header=FunctionHeader(name=name, addr=addr)
            )

        if not funcs:
            _l.warning("Failed to get any functions from Ghidra. Did something break?")

        return funcs

    def _function_args(self, func_addr: int, decompilation=None) -> Dict[int, FunctionArgument]:
        decompilation = decompilation or self._ghidra_decompile(self._get_nearest_function(func_addr))
        args = {}
        for param_idx in range(decompilation.getHighFunction().getLocalSymbolMap().getNumParams()):
            sym = decompilation.getHighFunction().getLocalSymbolMap().getParamSymbol(param_idx)
            if not sym.isParameter():
                continue

            args[param_idx] = FunctionArgument(
                offset=param_idx, name=str(sym.getName()), type_=str(sym.getDataType().getPathName()), size=int(sym.getSize())
            )

        return args

    def _function_type(self, addr: int, decompilation=None) -> Optional[str]:
        decompilation = decompilation or self._ghidra_decompile(self._get_nearest_function(addr))
        type_pathname = decompilation.getHighFunction().getFunctionPrototype().getReturnType().getPathName()
        return type_pathname if type_pathname else None

    @ghidra_transaction
    def _set_stack_variables(self, svars: List[StackVariable], **kwargs) -> bool:
        from .compat.imports import SourceType
        changes = False
        if not svars:
            return changes

        first_svar = svars[0]
        func_addr = first_svar.addr
        decompilation = kwargs.get('decompilation', None) or self._ghidra_decompile(self._get_function(func_addr))
        ghidra_func = decompilation.getFunction() if decompilation else self._get_nearest_function(func_addr)
        gstack_vars = self.__get_decless_gstack_vars(ghidra_func)  # this works because the func was already decompiled
        #gstack_vars = self.__get_gstack_vars(decompilation.getHighFunction())
        if not gstack_vars:
            return changes

        var_pairs = []
        for svar in svars:
            for gstack_var in gstack_vars:
                #if svar.offset == gstack_var.storage.stackOffset:
                if svar.offset == gstack_var.getStackOffset():
                    var_pairs.append((svar, gstack_var))
                    break

        rename_pairs = []
        retype_pairs = []
        changes = False
        #updates = {}
        for svar, gstack_var in var_pairs:
            #update_data = [gstack_var.name, None]
            if svar.name and svar.name != gstack_var.name:
                changes |= True
                rename_pairs.append((gstack_var, svar.name))
                #update_data[0] = svar.name

            if svar.type:
                parsed_type = self.typestr_to_gtype(svar.type)
                if parsed_type is not None and parsed_type != str(gstack_var.getDataType().getPathName()):
                    changes |= True
                    retype_pairs.append((gstack_var, parsed_type))
                    #update_data[1] = parsed_type

            #updates[gstack_var] = update_data

        self.__set_sym_names(rename_pairs, SourceType.USER_DEFINED)
        self.__set_sym_types(retype_pairs, SourceType.USER_DEFINED)
        #changes = self._update_local_variable_symbols(updates)
        return changes

    def _get_stack_variable(self, addr: int, offset: int, **kwargs) -> Optional[StackVariable]:
        gstack_var = self._get_gstack_var(addr, offset)
        if gstack_var is None:
            return None

        return self._gstack_var_to_bsvar(gstack_var)

    def _stack_variables(self, func_addr: int, decompilation=None) -> Dict[int, StackVariable]:
        decompilation = decompilation or self._ghidra_decompile(self._get_nearest_function(func_addr))
        sv_info = self.__stack_variables(decompilation)
        stack_variables = {}
        for offset, name, type_, size in sv_info:
            stack_variables[offset] = StackVariable(
                stack_offset=offset, name=name, type_=type_, size=size, addr=func_addr
            )

        return stack_variables

    def _set_function_header(self, fheader: FunctionHeader, decompilation=None, **kwargs) -> bool:
        from .compat.transaction import Transaction
        from .compat.imports import SourceType, HighFunctionDBUtil

        changes = False
        func_addr = fheader.addr
        ghidra_func = decompilation.getFunction() if decompilation else self._get_nearest_function(func_addr)

        # func name
        if fheader.name and fheader.name != ghidra_func.getName():
            with Transaction(self.flat_api, msg="BS::set_function_header::set_name"):
                ghidra_func.setName(fheader.name, SourceType.USER_DEFINED)
            changes = True

        # return type
        if fheader.type and decompilation is not None:
            parsed_type = self.typestr_to_gtype(fheader.type)
            if parsed_type is not None and \
                    parsed_type != str(decompilation.highFunction.getFunctionPrototype().getReturnType()):
                with Transaction(self.flat_api, msg="BS::set_function_header::set_rettype"):
                    ghidra_func.setReturnType(parsed_type, SourceType.USER_DEFINED)
                changes = True

        # args
        # TODO: Only works for function arguments passed by register
        if fheader.args and decompilation is not None:
            params = ghidra_func.getParameters()
            if len(params) == 0:
                with Transaction(self.flat_api, msg="BS::set_function_header::update_params"):
                    HighFunctionDBUtil.commitParamsToDatabase(
                        decompilation.highFunction,
                        True,
                        HighFunctionDBUtil.ReturnCommitOption.COMMIT_NO_VOID,
                        SourceType.USER_DEFINED
                    )

            with Transaction(self.flat_api, msg="BS::set_function_header::set_arguments"):
                for offset, param in zip(fheader.args, params):
                    arg = fheader.args[offset]
                    gtype = self.typestr_to_gtype(arg.type)
                    param.setName(arg.name, SourceType.USER_DEFINED)
                    param.setDataType(gtype, SourceType.USER_DEFINED)
            changes = True

        return changes

    @ghidra_transaction
    def _set_struct(self, struct: Struct, header=True, members=True, **kwargs) -> bool:
        from .compat.imports import DataTypeConflictHandler, StructureDataType, ByteDataType, CategoryPath

        data_manager = self.currentProgram.getDataTypeManager()
        scope = struct.scope or ""
        ghidra_struct = StructureDataType(CategoryPath("/" + scope), struct.name, 0)
        for offset in struct.members:
            member = struct.members[offset]
            ghidra_struct.add(ByteDataType.dataType, 1, member.name, "")
            ghidra_struct.growStructure(member.size - 1)
            for dtc in ghidra_struct.getComponents():
                if dtc.getFieldName() == member.name:
                    gtype = self.typestr_to_gtype(member.type if member.type else 'undefined' + str(member.size))
                    for i in range(offset, offset + member.size):
                        ghidra_struct.clearAtOffset(i)
                    ghidra_struct.replaceAtOffset(offset, gtype, member.size, member.name, "")
                    break

        # TODO: normalize the size of the struct if it did not grow enough
        old_ghidra_struct = self._get_gtype_by_bs_name(struct.scoped_name, Struct)
        try:
            if old_ghidra_struct is not None:
                data_manager.replaceDataType(old_ghidra_struct, ghidra_struct, True)
            else:
                data_manager.addDataType(ghidra_struct, DataTypeConflictHandler.DEFAULT_HANDLER)
            return True
        except Exception as ex:
            print(f'Error filling struct {struct.name}: {ex}')
            return False

    def _get_struct(self, name) -> Optional[Struct]:
        ghidra_struct = self._get_gtype_by_bs_name(name, Struct)
        if ghidra_struct is None:
            return None

        full_struct_name = ghidra_struct.getPathName()
        name, scope = self._gscoped_type_to_bs(full_struct_name)
        size = 0 if ghidra_struct.isZeroLength() else ghidra_struct.getLength()

        return Struct(
            name=name, size=size, members=self._struct_members_from_gstruct(ghidra_struct), scope=scope
        )

    @ghidra_transaction
    def _del_struct(self, name) -> bool:
        from .compat.imports import ConsoleTaskMonitor
        data_manager = self.currentProgram.getDataTypeManager()
        gstruct = self._get_gtype_by_bs_name(name, Struct)
        try:
            success = data_manager.remove(gstruct, ConsoleTaskMonitor())
            if success:
                return True
            else:
                raise Exception('DataManager failed to remove struct')
        except Exception as ex:
            self.error(f"Failed to remove struct {name}: {ex}")


    def _structs(self) -> Dict[str, Struct]:
        structs = {}
        gstructs = self.__gstructs()
        for g_scoped_name, gstruct in gstructs:
            name, scope = self._gscoped_type_to_bs(g_scoped_name)
            size = 0 if gstruct.isZeroLength() else gstruct.getLength()
            struct = Struct(
                name=name, size=size, members=self._struct_members_from_gstruct(gstruct), scope=scope
            )
            structs[struct.scoped_name] = struct

        return structs

    @ghidra_transaction
    def _set_comment(self, comment: Comment, **kwargs) -> bool:
        from .compat.imports import CodeUnit, SetCommentCmd

        cmt_type = CodeUnit.PRE_COMMENT if comment.decompiled else CodeUnit.EOL_COMMENT
        if comment.addr == comment.func_addr:
            cmt_type = CodeUnit.PLATE_COMMENT

        if comment.comment:
            # TODO: check if comment already exists, and append?
            return SetCommentCmd(
                self._to_gaddr(comment.addr), cmt_type, comment.comment
            ).applyTo(self.currentProgram)
        return True

    def _get_comment(self, addr) -> Optional[Comment]:
        # TODO: speedup needed here, see global vars for example
        comments = self._comments()
        return comments.get(addr, None)

    def _comments(self) -> Dict[int, Comment]:
        from .compat.imports import CodeUnit

        # Ghidra stores multiple comment slots per code unit, while declib has one
        # portable Comment per address. Preserve all populated text and label the
        # slots when more than one has to collapse into the same Comment.
        ordered_types = (
            (CodeUnit.PLATE_COMMENT, "PLATE", False),
            (CodeUnit.PRE_COMMENT, "PRE", True),
            (CodeUnit.EOL_COMMENT, "EOL", False),
            (CodeUnit.POST_COMMENT, "POST", False),
            (CodeUnit.REPEATABLE_COMMENT, "REPEATABLE", False),
        )

        comments = {}
        listing = self.currentProgram.getListing()
        for func in self.currentProgram.getFunctionManager().getFunctions(True):
            for code_unit in listing.getCodeUnits(func.getBody(), True):
                comment_entries = []
                for cmt_type, label, is_decompiled_type in ordered_types:
                    text = code_unit.getComment(cmt_type)
                    if not text:
                        continue
                    comment_entries.append((label, str(text), is_decompiled_type))

                if not comment_entries:
                    continue

                should_prefix = len(comment_entries) > 1
                parts = [
                    f"[{label}] {text}" if should_prefix else text
                    for label, text, _ in comment_entries
                ]
                has_decompiled = any(is_decompiled for _, _, is_decompiled in comment_entries)
                has_disassembly = any(not is_decompiled for _, _, is_decompiled in comment_entries)
                addr = int(code_unit.getAddress().getOffset())
                comments[addr] = Comment(
                    addr=addr,
                    comment="\n".join(parts),
                    decompiled=has_decompiled and not has_disassembly,
                )

        return comments

    @ghidra_transaction
    def _set_enum(self, enum: Enum, **kwargs) -> bool:
        from .compat.imports import EnumDataType, CategoryPath, DataTypeConflictHandler

        data_manager = self.currentProgram.getDataTypeManager()
        scope = enum.scope or ""
        ghidra_enum = EnumDataType(CategoryPath("/" + scope), enum.name, 4)
        for m_name, m_val in enum.members.items():
            ghidra_enum.add(m_name, m_val)

        old_ghidra_enum = self.currentProgram.getDataTypeManager().getDataType(ghidra_enum.getPathName())
        try:
            if old_ghidra_enum:
                data_manager.replaceDataType(old_ghidra_enum, ghidra_enum, True)
            else:
                data_manager.addDataType(ghidra_enum, DataTypeConflictHandler.DEFAULT_HANDLER)
            return True
        except Exception as ex:
            self.error(f'Error adding enum {enum.name}: {ex}')
            return False

    def _get_enum(self, name) -> Optional[Enum]:
        g_enum = self._get_gtype_by_bs_name(name, Enum)
        if g_enum is None:
            return None

        name, scope = self._gscoped_type_to_bs(g_enum.getPathName())
        members = {_name: val for _name, val in self.__get_enum_members(g_enum)}
        return Enum(name=name, members=members, scope=scope)

    def _enums(self) -> Dict[str, Enum]:
        enums = {}
        enums_by_name = self.__enum_names()
        for g_enum_name, g_enum in enums_by_name:
            name, scope = self._gscoped_type_to_bs(g_enum_name)
            members = {_name: val for _name, val in self.__get_enum_members(g_enum)}
            enum = Enum(name=name, members=members, scope=scope)
            enums[enum.scoped_name] = enum

        return enums

    @ghidra_transaction
    def _set_typedef(self, typedef: Typedef, **kwargs) -> bool:
        from .compat.imports import TypedefDataType, CategoryPath, DataTypeConflictHandler

        # validate the typedef basetype
        base_g_type = self.typestr_to_gtype(typedef.type)
        if base_g_type is None:
            raise ValueError(f"Invalid base type for typedef {typedef.name}: {typedef.type}")

        # parse out the correct name
        scope = typedef.scope
        if not scope:
            scope = ""

        # do a full parse of the typedef
        ghidra_typedef = TypedefDataType(CategoryPath("/"+scope), typedef.name, base_g_type)
        if ghidra_typedef is None:
            raise ValueError(f"Failed to create TypedefDataType for {typedef}")

        # get the old typedef if it exists, and override it
        g_typename = ghidra_typedef.getPathName()
        old_g_typedef = self.currentProgram.getDataTypeManager().getDataType(g_typename)
        data_manager = self.currentProgram.getDataTypeManager()

        try:
            if old_g_typedef:
                data_manager.replaceDataType(old_g_typedef, ghidra_typedef, True)
            else:
                data_manager.addDataType(ghidra_typedef, DataTypeConflictHandler.DEFAULT_HANDLER)
            return True
        except Exception as ex:
            self.error(f'Error adding typedef {typedef.name}: {ex}')
            return False

    def _get_typedef(self, name) -> Optional[Typedef]:
        g_typedef = self._get_gtype_by_bs_name(name, Typedef)
        if g_typedef is None:
            return None

        base_type = g_typedef.getDataType()
        if base_type is None:
            return None

        norm_name, scope = self._gscoped_type_to_bs(g_typedef.getPathName())
        return Typedef(name=norm_name, type_=str(base_type.getPathName()), scope=scope)

    def _typedefs(self) -> Dict[str, Typedef]:
        typedefs = {}
        typedefs_by_name = self.__gtypedefs()
        for gtype_name, gtypedef in typedefs_by_name:
            type_ = gtypedef.getDataType()
            if type_ is None:
                continue

            type_name = str(type_.getPathName())
            if not type_name or type_name == gtype_name:
                continue

            name, scope = self._gscoped_type_to_bs(gtypedef.getPathName())
            bs_typedef = Typedef(name=name, type_=type_name, scope=scope)
            # TODO: this could probably go wrong if typedef name and type are of different scopes
            typedefs[bs_typedef.scoped_name] = bs_typedef

        return typedefs

    def _gsyms_too_large(self):
        if self._gsym_size is None:
            self._gsym_size = self.currentProgram.getSymbolTable().getNumSymbols()

        return self._gsym_size > self._max_gsym_size

    @ghidra_transaction
    def _set_global_variable(self, gvar: GlobalVariable, **kwargs):
        from .compat.imports import RenameLabelCmd, SourceType

        changes = False
        if self._gsyms_too_large():
            self.warning("There are too many global symbols in your binary to accurately set. Skipping!")

        g_gvars_info = self.__g_global_variables()

        for addr, name, sym_data, sym in g_gvars_info:
            if addr != gvar.addr:
                continue

            # we've found the global variable
            if gvar.name and gvar.name != name:
                cmd = RenameLabelCmd(sym, gvar.name, SourceType.USER_DEFINED)
                cmd.applyTo(self.currentProgram)
                changes = True

            type_str = str(sym_data.getDataType().getPathName()) if sym_data is not None else None
            if gvar.type and gvar.type != type_str:
                # TODO: set type
                pass

        return changes

    def _get_global_var(self, addr) -> Optional[GlobalVariable]:
        gvars = self._global_vars(match_single_offset=addr)
        return gvars.get(addr, None)

    def _global_vars(self, match_single_offset=None, **kwargs) -> Dict[int, GlobalVariable]:
        if self._gsyms_too_large():
            self.warning("There are too many global symbols in your binary to get all global symbols!")
            return {}

        g_gvars_info = self.__g_global_variables()
        gvars = {}
        for addr, name, sym_data, sym in g_gvars_info:
            # speed optimization for single offset lookups
            if match_single_offset is not None and match_single_offset != addr:
                continue

            type_str = str(sym_data.getDataType().getPathName())
            size = int(self.currentProgram.getListing().getDataAt(sym.getAddress()).getLength()) \
                if type_str != "undefined" else self.default_pointer_size

            gvars[addr] = GlobalVariable(addr=addr, name=name, type_=type_str, size=size)

        return gvars

    #
    # Specialized print handlers
    # TODO: refactor the below for the new ghidra changes
    #

    def print(self, msg, print_local=True, **kwargs):
        print(msg)

    def info(self, msg: str, **kwargs):
        _l.info(msg)
        self.print(self._fmt_log_msg(msg, "INFO"), print_local=False)

    def debug(self, msg: str, **kwargs):
        _l.debug(msg)
        if _l.level >= logging.DEBUG:
            self.print(self._fmt_log_msg(msg, "DEBUG"), print_local=False)

    def warning(self, msg: str, **kwargs):
        _l.warning(msg)
        self.print(self._fmt_log_msg(msg, "WARNING"), print_local=False)

    def error(self, msg: str, **kwargs):
        _l.error(msg)
        self.print(self._fmt_log_msg(msg, "ERROR"), print_local=False)

    @staticmethod
    def _fmt_log_msg(msg: str, level: str):
        full_filepath = Path(__file__)
        log_path = str(full_filepath.with_suffix("").name)
        for part in full_filepath.parts[:-1][::-1]:
            log_path = f"{part}." + log_path
            if part == "ghidra":
                break

        return f"[{level}] | {log_path} | {msg}"

    #
    # Ghidra Specific API
    #

    def _gscoped_type_to_bs(self, gscoped_type: str) -> tuple[str, str | None]:
        scope = None
        if "/" in gscoped_type:
            scope_parts = gscoped_type.split("/")
            name = scope_parts.pop(-1)
            scope = "/".join(scope_parts)
            # remove the first slash
            if scope.startswith("/"):
                scope = scope[1:]
        else:
            name = gscoped_type

        return name, scope

    def _bs_scoped_type_to_g(self, bs_scoped_type: str) -> str:
        name, scope = self.art_lifter.parse_scoped_type(bs_scoped_type)
        if scope is None:
            return "/" + name

        return f"/{scope}/{name}"

    def _to_gaddr(self, addr: int):
        return self.flat_api.toAddr(hex(addr))

    @property
    def currentProgram(self):
        from .compat.state import get_current_program
        return get_current_program(self.flat_api)

    @ghidra_transaction
    def _update_local_variable_symbols(self, symbols: Dict["HighSymbol", Tuple[str, Optional["DataType"]]]) -> bool:
        return any([
            r is not None for r in self.__update_local_variable_symbols(symbols)
        ])

    def _get_struct_by_name(self, name: str) -> Optional["StructureDB"]:
        """
        Returns None if the struct does not exist or is not a struct.
        """
        from .compat.imports import StructureDB

        struct = self.currentProgram.getDataTypeManager().getDataType("/" + name)
        return struct if isinstance(struct, StructureDB) else None

    def _struct_members_from_gstruct(self, gstruct: "StructDB") -> Dict[int, StructMember]:
        gmemb_info = self.__gstruct_members(gstruct)
        members = {}
        for offset, field_name, type_, size in gmemb_info:
            name = field_name if field_name else f'field_{hex(offset)[2:]}'
            members[offset] = StructMember(name=name, offset=offset, type_=type_, size=size)

        return members

    def _get_nearest_function(self, addr: int) -> "GhidraFunction":
        func_manager = self.currentProgram.getFunctionManager()
        return func_manager.getFunctionContaining(self._to_gaddr(addr))

    def _get_first_segment_base(self) -> int:
        """
        Get the virtual address of the first segment.
        """
        memory = self.currentProgram.getMemory()

        # First, try to find an executable segment (typically the code segment)
        for block in memory.getBlocks():
            return int(block.getStart().getOffset())

        # Fallback to image base if no memory blocks found
        return int(self.currentProgram.getImageBase().getOffset())

    def _gstack_var_to_bsvar(self, gstack_var: "LocalVariableDB"):
        if gstack_var is None:
            return None

        bs_stack_var = StackVariable(
            gstack_var.getStackOffset(),
            gstack_var.getName(),
            str(gstack_var.getDataType().getPathName()),
            gstack_var.getLength(),
            gstack_var.getFunction().getEntryPoint().getOffset()  # Unsure if this is what is wanted here
        )
        return bs_stack_var

    def _gfunc_to_bsfunc(self, gfunc: "GhidraFunction"):
        if gfunc is None:
            return None

        bs_func = Function(
            addr=gfunc.getEntryPoint().getOffset(), size=gfunc.getBody().getNumAddresses(),
            header=FunctionHeader(name=gfunc.getName(), addr=gfunc.getEntryPoint().getOffset()),
        )
        return bs_func

    def _ghidra_decompile_nearest(self, addr: int) -> Optional["DecompileResult"]:
        func = self._get_nearest_function(addr)
        if func is None:
            raise RuntimeError(f"Failed to get nearest function for decompilation at {hex(addr)}")

        dec = self._ghidra_decompile(func)
        if dec is None:
            raise RuntimeError(f"Failed to decompile function at {hex(addr)}")

        return dec

    def _ghidra_decompile(self, func: "GhidraFunction") -> "DecompileResult":
        """
        TODO: this needs to be cached!
        @param func:
        @return:
        """
        from .compat.imports import DecompInterface, ConsoleTaskMonitor

        dec_interface = DecompInterface()
        dec_interface.openProgram(self.currentProgram)
        dec_results = dec_interface.decompileFunction(func, 0, ConsoleTaskMonitor())
        return dec_results

    def _get_gstack_var(self, func: "GhidraFunction", offset: int) -> Optional["LocalVariableDB"]:
        """
        TODO: this needs to be updated that when its called we get decomilation, and pass it to
            __get_gstack_vars

        @param func:
        @param offset:
        @return:
        """
        gstack_vars = self.__get_decless_gstack_vars(func)
        for var in gstack_vars:
            if var.getStackOffset() == offset:
                return var

        return None

    def _headless_lookup_struct(self, typestr: str) -> Optional["DataType"]:
        """
        This function is mostly a hack because getDataTypeManagerService does not have up to date
        datatypes in headless mode, so any structs you create dont get registerd
        """
        if not typestr:
            return None

        type_: CType = self.type_parser.parse_type(typestr)
        if not type_:
            # it was not parseable
            return None

        # type is known and parseable
        if not type_.is_unknown:
            return None

        base_type_str = type_.base_type.type
        return self.currentProgram.getDataTypeManager().getDataType("/" + base_type_str)

    def typestr_to_gtype(self, typestr: str) -> Optional["DataType"]:
        """
        typestr should look something like:
        `int` or if a struct `struct name`.

        @param typestr:
        @return:
        """
        from .compat.imports import DataTypeParser, AutoAnalysisManager

        if not typestr:
            return None

        aam = AutoAnalysisManager.getAnalysisManager(self.currentProgram)
        dt_service = aam.getDataTypeManagerService()
        dt_parser = DataTypeParser(dt_service, DataTypeParser.AllowedDataTypes.ALL)
        try:
            parsed_type = dt_parser.parse(typestr)
        except Exception as e:
            parsed_type = None

        dtm = self.currentProgram.getDataTypeManager()

        # attempt a lookup as a custom datatype by name (e.g. "Point")
        if parsed_type is None:
            lookup = typestr if typestr.startswith("/") else "/" + typestr
            parsed_type = dtm.getDataType(lookup)

        # attempt to resolve a pointer to a custom datatype (e.g. "Point *"):
        # DataTypeParser can't resolve user structs by bare name and the path
        # lookup above only matches non-pointer names, so build the pointer
        # explicitly from the resolved base type.
        if parsed_type is None and typestr.rstrip().endswith("*"):
            base_str = typestr.strip()
            ptr_levels = 0
            while base_str.endswith("*"):
                base_str = base_str[:-1].strip()
                ptr_levels += 1
            base_lookup = base_str if base_str.startswith("/") else "/" + base_str
            base_dt = dtm.getDataType(base_lookup)
            if base_dt is not None:
                from ghidra.program.model.data import PointerDataType
                parsed_type = base_dt
                for _ in range(ptr_levels):
                    parsed_type = PointerDataType(parsed_type)

        if parsed_type is None:
            _l.warning("Failed to parse type string: %s", typestr)

        return parsed_type

    def prototype_str_to_gtype(self, progotype_str: str) -> Optional["FunctionDefinitionDataType"]:
        """
        Strings must look like:
        'void functions1(int p1, int p2)'
        """
        from .compat.imports import CParserUtils

        if not progotype_str:
            return None

        program = self.currentProgram
        return CParserUtils.parseSignature(program, progotype_str)

    def _get_gtype_by_bs_name(self, name: str, bs_type: type[Artifact]) -> Optional["DataType"]:
        """
        Returns None if the type does not exist or is not a struct.
        """
        from .compat.imports import EnumDB, StructureDB, TypedefDB

        g_type = {
            Typedef: TypedefDB,
            Struct: StructureDB,
            Enum: EnumDB,
        }.get(bs_type, None)
        if g_type is None:
            raise ValueError(f"Invalid type for gtype lookup: {bs_type}")

        g_scoped_name = self._bs_scoped_type_to_g(name)
        gtype = self.currentProgram.getDataTypeManager().getDataType(g_scoped_name)
        if not gtype:
            # TODO: add recovery one day: if the scope is None we should still try to search
            #self.warning(f"Failed to get type by name: {g_scoped_name}")
            return None

        if not isinstance(gtype, g_type):
            #self.warning(f"Type {g_scoped_name} is not a {g_type.__name__}")
            return None

        return gtype

    #
    # Internal functions that are very dangerous
    #

    def __fast_function(self, lowered_addr: int) -> List["GhidraFunction"]:
        return [
            self.currentProgram.getFunctionManager().getFunctionContaining(self.flat_api.toAddr(hex(lowered_addr)))
        ]

    def __functions(self) -> List[Tuple[int, str, int]]:
        return [
            (int(func.getEntryPoint().getOffset()), str(func.getName()), int(func.getBody().getNumAddresses()))
            for func in self.currentProgram.getFunctionManager().getFunctions(True)
        ]

    def __update_local_variable_symbols(self, symbols: Dict["HighSymbol", Tuple[str, Optional["DataType"]]]) -> List:
        from .compat.imports import HighFunctionDBUtil, SourceType

        return [
            HighFunctionDBUtil.updateDBVariable(sym, updates[0], updates[1], SourceType.ANALYSIS)
            for sym, updates in symbols.items()
        ]

    def _get_local_variable_symbols(self, func: Function) -> List[Tuple[str, "HighSymbol"]]:
        return [
            (sym.name, sym)
            for sym in func.dec_obj.getHighFunction().getLocalSymbolMap().getSymbols() if sym.name
        ]


    def __get_decless_gstack_vars(self, func: "GhidraFunction") -> List["LocalVariableDB"]:
        return [var for var in func.getAllVariables() if var.isStackVariable()]


    def __get_gstack_vars(self, high_func: "HighFunction") -> List["LocalVariableDB"]:
        return [
            var for var in high_func.getLocalSymbolMap().getSymbols()
            if var.storage and var.storage.isStackStorage()
        ]


    def __enum_names(self) -> List[Tuple[str, "EnumDB"]]:
        from .compat.imports import EnumDB

        return [
            (dType.getPathName(), dType)
            for dType in self.currentProgram.getDataTypeManager().getAllDataTypes()
            if isinstance(dType, EnumDB)
        ]


    def __stack_variables(self, decompilation) -> List[Tuple[int, str, str, int]]:
        return [
            (int(sym.getStorage().getStackOffset()), str(sym.getName()), sym.getDataType().getPathName(), int(sym.getSize()))
            for sym in decompilation.getHighFunction().getLocalSymbolMap().getSymbols()
            if sym.getStorage().isStackStorage()
        ]


    def __set_sym_names(self, sym_pairs, source_type):
        return [
            sym.setName(new_name, source_type) for sym, new_name in sym_pairs
        ]


    def __set_sym_types(self, sym_pairs, source_type):
        return [
            sym.setDataType(new_type, False, True, source_type) for sym, new_type in sym_pairs
        ]


    def __gstruct_members(self, gstruct: "StructureDB") -> List[Tuple[int, str, str, int]]:
        return [
            (int(m.getOffset()), str(m.getFieldName()), str(m.getDataType().getPathName()), int(m.getLength()))
            for m in gstruct.getComponents()
        ]


    def __get_enum_members(self, g_enum: "EnumDB") -> List[Tuple[str, int]]:
        return [
            (name, g_enum.getValue(name)) for name in g_enum.getNames()
        ]


    def __g_global_variables(self):
        # TODO: this could be optimized more both in use and in implementation
        # TODO: this just does not work for bigger than 50k syms
        from .compat.imports import SymbolType

        return [
            (int(sym.getAddress().getOffset()), str(sym.getName()), self.currentProgram.getListing().getDataAt(sym.getAddress()), sym)
            for sym in self.currentProgram.getSymbolTable().getAllSymbols(True)
            if sym.getSymbolType() == SymbolType.LABEL and
            self.currentProgram.getListing().getDataAt(sym.getAddress()) and
            not self.currentProgram.getListing().getDataAt(sym.getAddress()).isStructure()
        ]


    def __gstructs(self):
        return [
            (struct.getPathName(), struct)
            for struct in self.currentProgram.getDataTypeManager().getAllStructures()
        ]


    def __gtypedefs(self):
        from .compat.imports import TypedefDB

        return [
            (typedef.getPathName(), typedef)
            for typedef in self.currentProgram.getDataTypeManager().getAllDataTypes()
            if isinstance(typedef, TypedefDB)
        ]
