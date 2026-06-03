import logging
import typing
from typing import Tuple, Optional
import threading

from ...artifacts import FunctionHeader, Function, FunctionArgument, StackVariable, GlobalVariable, Struct, Enum

if typing.TYPE_CHECKING:
    from declib.decompilers.ghidra.interface import GhidraDecompilerInterface

_l = logging.getLogger(__name__)
from .compat.imports import (
    DomainObjectListener, ChangeManager, ProgramChangeRecord, VariableDB, FunctionDB, CodeSymbol,
    FunctionSymbol, FunctionChangeRecord
)
from jpype import JImplements, JOverride


@JImplements(DomainObjectListener, deferred=False)
class DataMonitor:
    @JOverride
    def __init__(self, deci: "GhidraDecompilerInterface"):
        self._deci = deci
        # Init event lists
        self.funcEvents = {
            ChangeManager.DOCR_FUNCTION_CHANGED,
            ChangeManager.DOCR_FUNCTION_BODY_CHANGED,
            ChangeManager.DOCR_VARIABLE_REFERENCE_ADDED,
            ChangeManager.DOCR_VARIABLE_REFERENCE_REMOVED
        }

        self.symDelEvents = {
            ChangeManager.DOCR_SYMBOL_REMOVED
        }

        self.symChgEvents = {
            ChangeManager.DOCR_SYMBOL_ADDED,
            ChangeManager.DOCR_SYMBOL_RENAMED,
            ChangeManager.DOCR_SYMBOL_DATA_CHANGED
        }

        self.typeEvents = {
            ChangeManager.DOCR_SYMBOL_ADDRESS_CHANGED,
            ChangeManager.DOCR_DATA_TYPE_CHANGED,
            ChangeManager.DOCR_DATA_TYPE_REPLACED,
            ChangeManager.DOCR_DATA_TYPE_RENAMED,
            ChangeManager.DOCR_DATA_TYPE_SETTING_CHANGED,
            ChangeManager.DOCR_DATA_TYPE_MOVED,
            ChangeManager.DOCR_DATA_TYPE_ADDED
        }

        self.imageBaseEvents = {
            ChangeManager.DOCR_IMAGE_BASE_CHANGED
        }

        self.TrackedEvents = (
            self.funcEvents | self.symDelEvents | self.symChgEvents | self.typeEvents | self.imageBaseEvents
        )

    @JOverride
    def domainObjectChanged(self, ev):
        try:
            self.do_change_handler(ev)
        except Exception as e:
            excep_str = str(e).replace('\n', ' ')
            self._deci.error(f"Error in domainObjectChanged: {excep_str}")

    def do_change_handler(self, ev):
        for record in ev:
            if not isinstance(record, ProgramChangeRecord):
                continue

            changeType = record.getEventType()
            if changeType not in self.TrackedEvents:
                # bail out early if we don't care about this event
                continue

            new_value = record.getNewValue()
            obj = record.getObject()
            if changeType in self.funcEvents:
                func_change_type = record.getSpecificChangeType()
                if func_change_type == FunctionChangeRecord.FunctionChangeType.RETURN_TYPE_CHANGED:
                    # Function return type changed
                    header = FunctionHeader(
                        name=None, addr=obj.getEntryPoint().getOffset(), type_=str(obj.getReturnType())
                    )
                    self._deci.function_header_changed(header)

            elif changeType in self.typeEvents:
                if changeType == ChangeManager.DOCR_SYMBOL_ADDRESS_CHANGED:
                    # stack variables change address when retyped!
                    if isinstance(obj, VariableDB):
                        parent_namespace = obj.getParentNamespace()
                        storage = obj.getVariableStorage()
                        if (
                                (new_value is not None) and (storage is not None) and bool(storage.isStackStorage())
                                and (parent_namespace is not None)
                        ):
                            sv = StackVariable(
                                int(storage.stackOffset),
                                None,
                                str(obj.getDataType()),
                                int(storage.size),
                                int(obj.parentNamespace.entryPoint.offset)
                            )
                            self._deci.stack_variable_changed(
                                sv
                            )

                else:
                    try:
                        struct = self._deci.structs[new_value.name]
                        # TODO: access old name indicate deletion
                        # self._deci.struct_changed(Struct(None, None, None), deleted=True)
                        self._deci.struct_changed(struct)
                    except KeyError:
                        pass
                if changeType == ChangeManager.DOCR_SYMBOL_ADDRESS_CHANGED:
                    # stack variables change address when retyped!
                    if isinstance(obj, VariableDB):
                        parent_namespace = obj.getParentNamespace()
                        storage = obj.getVariableStorage()
                        if (
                                (new_value is not None) and (storage is not None) and bool(storage.isStackStorage())
                                and (parent_namespace is not None)
                        ):
                            self._deci.stack_variable_changed(
                                StackVariable(
                                    int(storage.stackOffset),
                                    None,
                                    str(obj.getDataType()),
                                    int(storage.size),
                                    int(obj.parentNamespace.entryPoint.offset)
                                )
                            )

                else:
                    try:
                        struct = self._deci.structs[new_value.name]
                        # TODO: access old name indicate deletion
                        # self._deci.struct_changed(Struct(None, None, None), deleted=True)
                        self._deci.struct_changed(struct)
                    except KeyError:
                        pass

                    try:
                        enum = self._deci.enums[new_value.name]
                        # self._deci.enum_changed(Enum(None, None), deleted=True)
                        self._deci.enum_changed(enum)
                    except KeyError:
                        pass

            elif changeType in self.symDelEvents:
                # Globals are deleted first then recreated
                if isinstance(obj, CodeSymbol):
                    removed = GlobalVariable(obj.getAddress().getOffset(), obj.getName())
                    # deleted kwarg not yet handled by global_variable_changed
                    self._deci.global_variable_changed(removed, deleted=True)
            elif changeType in self.symChgEvents:
                # For creation events, obj is stored in newValue
                if obj is None and new_value is not None:
                    obj = new_value

                if changeType == ChangeManager.DOCR_SYMBOL_ADDED:
                    if isinstance(obj, CodeSymbol):
                        gvar = GlobalVariable(obj.getAddress().getOffset(), obj.getName())
                        self._deci.global_variable_changed(gvar)
                elif changeType == ChangeManager.DOCR_SYMBOL_RENAMED:
                    if isinstance(obj, CodeSymbol):
                        gvar = GlobalVariable(obj.getAddress().getOffset(), new_value)
                        self._deci.global_variable_changed(gvar)
                    if isinstance(obj, FunctionSymbol):
                        header = FunctionHeader(name=new_value, addr=int(obj.getAddress().offset))
                        self._deci.function_header_changed(header)
                elif isinstance(obj, VariableDB):
                    parent_namespace = obj.getParentNamespace()
                    storage = obj.getVariableStorage()
                    if (
                            (new_value is not None) and (storage is not None) and bool(storage.isStackStorage())
                            and (parent_namespace is not None)
                    ):
                        self._deci.stack_variable_changed(
                            StackVariable(
                                int(obj.variableStorage.stackOffset),
                                new_value,
                                None,
                                None,
                                int(obj.parentNamespace.entryPoint.offset)
                            )
                        )
                elif isinstance(obj, FunctionDB):
                    # TODO: Fix argument name support
                    # changed_arg = FunctionArgument(None, newValue, None, None)
                    # header = FunctionHeader(None, None, args={None: changed_arg})
                    # self._deci.function_header_changed(header)
                    pass
                else:
                    continue
            elif changeType in self.imageBaseEvents:
                new_base_addr = int(new_value.getOffset()) if new_value is not None else None
                if new_base_addr is not None:
                    self._deci._binary_base_addr = new_base_addr


def create_data_monitor(deci: "GhidraDecompilerInterface"):
    data_monitor = DataMonitor(deci)
    return data_monitor


def _qt_shortcut_to_ghidra(shortcut: str) -> str:
    """Convert a Qt-style shortcut like "Ctrl+Shift+D" to Ghidra's "ctrl shift D"."""
    if not shortcut:
        return ""
    parts = shortcut.split("+")
    out = []
    for p in parts[:-1]:
        out.append(p.strip().lower())
    key = parts[-1].strip()
    out.append(key.upper() if len(key) == 1 else key)
    return " ".join(out)


def create_context_action(
    name, action_string, callback_func, category=None,
    plugin_name="declib_ghidra", tool=None, shortcut=None,
):
    from .compat.imports import ProgramLocationActionContext, ActionBuilder
    def _invoke(ctx: ProgramLocationActionContext):
        threading.Thread(target=callback_func, daemon=True).start()

    menu_path = []
    if category is not None and "/" in category:
        menu_path.extend(category.split("/"))
    menu_path.append(action_string)

    b = (ActionBuilder(name, plugin_name)
            .popupMenuPath(list(menu_path))
            .withContext(ProgramLocationActionContext)
            .validContextWhen(lambda ctx: ctx is not None and ctx.getAddress() is not None)
            .onAction(_invoke))

    return b.buildAndInstall(tool)
