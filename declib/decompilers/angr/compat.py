# pylint: disable=wrong-import-position,wrong-import-order
import logging
from collections import defaultdict
from typing import Optional

from angrmanagement.plugins import BasePlugin
from angrmanagement.ui.workspace import Workspace
from angrmanagement.ui.views.view import BaseView

from declib.artifacts import (
    StackVariable, FunctionHeader, Enum, Struct, GlobalVariable, Comment, FunctionArgument
)
from declib.decompilers.angr.interface import AngrInterface

l = logging.getLogger(__name__)


class GenericDLAngrManagementPlugin(BasePlugin):
    def __init__(self, workspace: Workspace, interface: Optional[AngrInterface] = None, context_menu_items=None):
        super().__init__(workspace)
        # (name, action_string, callback_func, category)
        self.context_menu_items = context_menu_items or []
        # Keep strong refs to QShortcut objects so Qt doesn't GC them
        self._qshortcuts: list = []
        if interface is None:
            from declib.decompilers.angr.interface import AngrInterface
            self.interface = AngrInterface(
                workspace,
                init_plugin=True,
            )
        else:
            self.interface = interface

    def teardown(self):
        pass

    def register_shortcut(self, name: str, shortcut: str, callback_func, deci=None) -> bool:
        """
        Register a keyboard shortcut bound to ``callback_func`` on the angr-management
        main window. The shortcut is an application-wide QShortcut so it fires from
        any focused widget.
        """
        from PySide6.QtGui import QShortcut, QKeySequence
        from PySide6.QtCore import Qt
        from PySide6.QtWidgets import QApplication

        parent = getattr(self.workspace, "main_window", None)
        if parent is None:
            app = QApplication.instance()
            if app is not None:
                for w in app.topLevelWidgets():
                    if w.isWindow():
                        parent = w
                        break
        if parent is None:
            l.warning("No Qt main window available; cannot bind shortcut %s", shortcut)
            return False

        qsc = QShortcut(QKeySequence(shortcut), parent)
        qsc.setContext(Qt.ApplicationShortcut)
        qsc.activated.connect(lambda: callback_func(None, deci=deci))
        self._qshortcuts.append(qsc)
        return True

    #
    # Context Menus
    #

    @staticmethod
    def build_nested_structure_from_ctx_items(context_items):
        def insert(categories, action, func, node):
            if categories:
                category = categories[0]
                next_node = None
                for child in node:
                    if child[0] == category:
                        next_node = child[1]
                        break
                if not next_node:
                    next_node = []
                    node.append((category, next_node))
                insert(categories[1:], action, func, next_node)
            else:
                node.append((action, func))

        root = []
        for path, action, func in context_items:
            categories = path.strip('/').split('/')
            insert(categories, action, func, root)

        return root[0]

    def build_context_menu_node(self, node):
        """
        The context menu triggered on right-click on a node in the decompilation view.
        If used agnostic to the node type, this will always be on the context menu
        """
        try:
            func_addr = node.codegen.cfunc.addr
        except AttributeError:
            func_addr = None

        # only add the context menu items if we are in a function
        if func_addr is not None:
            # collect all the context menu items into a single list
            ctx_items = [
                (category if category else "", action_string, callback_func)
                for name, action_string, callback_func, category in self.context_menu_items
            ]
            if ctx_items:
                nested_structure = GenericDLAngrManagementPlugin.build_nested_structure_from_ctx_items(ctx_items)
                if not nested_structure[0][0]:
                    root_items = nested_structure[0][1]
                    categorized_items = nested_structure[1]
                    for item in root_items:
                        yield item
                else:
                    categorized_items = nested_structure

                yield categorized_items

    #
    #  Decompiler Hooks
    #

    # pylint: disable=unused-argument
    def handle_stack_var_renamed(self, func, offset, old_name, new_name):
        if func is None:
            return False

        decompilation = self.interface.decompile_function(func).codegen
        stack_var = self.interface.find_stack_var_in_codegen(decompilation, offset)
        self.interface.stack_variable_changed(StackVariable(offset, new_name, None, stack_var.size, func.addr))
        return True

    # pylint: disable=unused-argument
    def handle_stack_var_retyped(self, func, offset, old_type, new_type):
        decompilation = self.interface.decompile_function(func).codegen
        stack_var = self.interface.find_stack_var_in_codegen(decompilation, offset)
        var_type = AngrInterface.stack_var_type_str(decompilation, stack_var)
        self.interface.stack_variable_changed(StackVariable(offset, stack_var.name, var_type, stack_var.size, func.addr))
        return True

    # pylint: disable=unused-argument
    def handle_func_arg_renamed(self, func, offset, old_name, new_name):
        decompilation = self.interface.decompile_function(func).codegen
        func_args = AngrInterface.func_args_as_declib_args(decompilation)
        self.interface.function_header_changed(
            FunctionHeader(
                name=None,
                addr=func.addr,
                type_=None,
                args={
                    offset: FunctionArgument(offset=offset, name=new_name, type_=None, size=func_args[offset].size)
                },
            )
        )

        return True

    # pylint: disable=unused-argument
    def handle_func_arg_retyped(self, func, offset, old_type, new_type):
        decompilation = self.interface.decompile_function(func).codegen
        func_args = AngrInterface.func_args_as_declib_args(decompilation)
        self.interface.function_header_changed(
            FunctionHeader(
                name=None,
                addr=func.addr,
                type_=None,
                args={
                    offset: FunctionArgument(offset=offset, name=None, type_=new_type, size=func_args[offset].size)
                },
            )
        )

        return True

    # pylint: disable=unused-argument,no-self-use
    def handle_global_var_renamed(self, address, old_name, new_name):
        self.interface.global_variable_changed(
            GlobalVariable(addr=address, name=new_name, type_=None)
        )
        return True

    # pylint: disable=unused-argument,no-self-use
    def handle_global_var_retyped(self, address, old_type, new_type):
        self.interface.global_variable_changed(
            GlobalVariable(addr=address, name=None, type_=new_type)
        )
        return True

    # pylint: disable=unused-argument
    def handle_function_renamed(self, func, old_name, new_name):
        if func is None:
            return False

        self.interface.function_header_changed(FunctionHeader(name=new_name, addr=func.addr))
        return True

    # pylint: disable=unused-argument,no-self-use
    def handle_function_retyped(self, func, old_type, new_type):
        if func is None:
            return False

        self.interface.function_header_changed(FunctionHeader(name=None, addr=func.addr, type_=new_type))
        return True

    # pylint: disable=unused-argument
    def handle_comment_changed(self, address, old_cmt, new_cmt, created: bool, decomp: bool):
        # comments are only possible in functions in AM
        func_addr = self.interface.get_closest_function(address)
        if func_addr is None:
            return False

        self.interface.comment_changed(
            Comment(addr=address, comment=new_cmt, func_addr=func_addr, decompiled=True), deleted=not new_cmt
        )
        return True

class AngrWidgetWrapper(BaseView):
    """
    The class for the window that shows changes/info to BinSync data. This includes things like
    changes to functions or structs.
    """

    def __init__(self, workspace, default_docking_position, qt_cls, window_name: str, *args, **kwargs):
        # hacky imports to avoid ui
        from declib.ui.version import set_ui_version
        set_ui_version("PySide6")
        from declib.ui.qt_objects import QVBoxLayout

        super().__init__(window_name.replace(" ", "_"), workspace, default_docking_position)
        self.base_caption = window_name
        self.widget = qt_cls(*args, **kwargs)

        main_layout = QVBoxLayout()
        main_layout.addWidget(self.widget)
        self.setLayout(main_layout)
        self.width_hint = 300

    def closeEvent(self, event):
        self.widget.close()


def attach_qt_widget(workspace: Workspace, qt_cls, window_name: str, default_docking_position=None, *args, **kwargs):
    from PySide6QtAds import SideBarRight, CDockWidget, CDockManager

    wrapper = AngrWidgetWrapper(workspace, default_docking_position, qt_cls, window_name, *args, **kwargs)
    if not wrapper.widget:
        l.error("Failed to create widget %s", window_name)
        return False

    workspace.add_view(wrapper)
    dock = workspace.view_manager.view_to_dock[wrapper]
    dock.setAutoHide(False, SideBarRight)
    dock.closed.disconnect()
    dock.setFeature(CDockWidget.DockWidgetDeleteOnClose, False)
    # grab the dock manager by climbing up parents, probably a better way to directly grab it
    dm = dock.parent().parent().parent()
    assert (isinstance(dm, CDockManager))
    dm.setAutoHideConfigFlags(CDockManager.AutoHideHasCloseButton, False)
    return True
