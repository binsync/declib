import logging

_l = logging.getLogger(__name__)


def get_private_class(path: str):
    from java.lang import ClassLoader
    from jpype import JClass

    gcl = ClassLoader.getSystemClassLoader()
    return JClass(path, loader=gcl)

from ghidra.framework.model import DomainObjectListener
from ghidra.program.model.symbol import SourceType, SymbolType
from ghidra.program.model.pcode import HighFunctionDBUtil
from ghidra.program.model.data import (
    DataTypeConflictHandler, StructureDataType, ByteDataType, EnumDataType, CategoryPath, TypedefDataType
)
from ghidra.program.util import ChangeManager, ProgramChangeRecord, FunctionChangeRecord
from ghidra.program.database.function import VariableDB, FunctionDB
from ghidra.program.database.symbol import CodeSymbol, FunctionSymbol
from ghidra.program.model.listing import CodeUnit
from ghidra.app.cmd.comments import SetCommentCmd
from ghidra.app.cmd.label import RenameLabelCmd
from ghidra.app.context import ProgramLocationContextAction, ProgramLocationActionContext
from ghidra.app.decompiler import DecompInterface
from ghidra.app.plugin.core.analysis import AutoAnalysisManager
from ghidra.app.util.cparser.C import CParserUtils
from ghidra.app.decompiler import PrettyPrinter
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.util.data import DataTypeParser
from ghidra.util.exception import CancelledException
from docking.action import MenuData
from docking.action.builder import ActionBuilder

EnumDB = get_private_class("ghidra.program.database.data.EnumDB")
StructureDB = get_private_class("ghidra.program.database.data.StructureDB")
TypedefDB = get_private_class("ghidra.program.database.data.TypedefDB")

__all__ = [
    # forcefully imported objects
    "DomainObjectListener",
    "SourceType",
    "ChangeManager",
    "ProgramChangeRecord",
    "FunctionChangeRecord",
    "VariableDB",
    "FunctionDB",
    "CodeSymbol",
    "FunctionSymbol",
    "ProgramLocationContextAction",
    "ProgramLocationActionContext",
    "MenuData",
    "ActionBuilder",
    "HighFunctionDBUtil",
    "DataTypeConflictHandler",
    "StructureDataType",
    "ByteDataType",
    "CodeUnit",
    "SetCommentCmd",
    "EnumDataType",
    "CategoryPath",
    "TypedefDataType",
    "EnumDB",
    "RenameLabelCmd",
    "SymbolType",
    "StructureDB",
    "PrettyPrinter",
    "ConsoleTaskMonitor",
    "DecompInterface",
    "AutoAnalysisManager",
    "DataTypeParser",
    "CParserUtils",
    "CancelledException",
    "EnumDB",
    "StructureDB",
    "TypedefDB"
]
