import logging

import idaapi

from .compat import get_ida_gui_version

from declib.ui.version import set_ui_version
set_ui_version(get_ida_gui_version())
from declib.ui.qt_objects import QWidget, QVBoxLayout, wrapInstance

_l = logging.getLogger(__name__)


def ask_choice(question, choices, title="Choose an option"):
    class MyForm(idaapi.Form):
        def __init__(self, options):
            self.dropdown = idaapi.Form.DropdownListControl(items=options)
            form_string = ("STARTITEM 0\n"
                           f"{title}\n"
                           f"{question}\n"
                           "<Options:{dropdown}>")
            idaapi.Form.__init__(self, form_string, {'dropdown': self.dropdown})

    # Instantiate and display the form
    form = MyForm(choices)
    form.Compile()
    ok = form.Execute()
    if ok == 1:
        selected_index = form.dropdown.value
        selected_item = choices[selected_index]
    else:
        selected_item = ""
    form.Free()
    return selected_item


class IDAWidgetWrapper(object):
    def __init__(self, qt_cls, window_name: str, *args, **kwargs):
        self.twidget = idaapi.create_empty_widget(window_name)
        self.widget = wrapInstance(int(self.twidget), QWidget)
        self.name = window_name
        self.widget.name = window_name
        self.width_hint = 250

        self._widget = qt_cls(*args, **kwargs)
        layout = QVBoxLayout()
        layout.addWidget(self._widget)
        layout.setContentsMargins(2, 2, 2, 2)
        self.widget.setLayout(layout)


def attach_qt_widget(qt_cls, window_name: str, target_window=None, position=None, *args, **kwargs):
    wrapper = IDAWidgetWrapper(qt_cls, window_name, *args, **kwargs)
    if not wrapper.twidget:
        _l.error("Failed to create widget %s", window_name)
        return False

    flags = idaapi.PluginForm.WOPN_TAB | idaapi.PluginForm.WOPN_RESTORE | idaapi.PluginForm.WOPN_PERSIST
    idaapi.display_widget(wrapper.twidget, flags)
    wrapper.widget.visible = True

    if position is None:
        # make a new tab in the target window
        position = idaapi.DP_RIGHT

    if target_window == "Functions":
        dock_dst = "Functions"
        position = idaapi.DP_INSIDE
    else:
        # attempt to 'dock' the widget in a reasonable location
        for target in ["IDA View-A", "Pseudocode-A"]:
            dwidget = idaapi.find_widget(target)
            if dwidget:
                dock_dst = target
                break
        else:
            raise RuntimeError("Could not find a suitable dock position for the widget")

    idaapi.set_dock_pos(wrapper.name, dock_dst, position)
    return True
