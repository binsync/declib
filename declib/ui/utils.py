import sys

from .qt_objects import (
    QDialog, QVBoxLayout, QProgressBar, QLabel, QPushButton, Qt, QThread, QApplication, Signal, QLineEdit,
    QComboBox, QFontMetrics, QMessageBox
)


def gui_popup_text(text, title="Plugin Info") -> bool:
    message_box = QMessageBox()
    message_box.setIcon(QMessageBox.Information)
    message_box.setWindowTitle(title)
    message_box.setText(text)
    message_box.setStandardButtons(QMessageBox.Ok)

    if message_box.exec() == QMessageBox.Ok:
        return True
    else:
        return False


def gui_ask_for_string(question, title="Plugin Question", default="") -> str:
    dialog = QDialog()
    dialog.setWindowTitle(title)

    layout = QVBoxLayout(dialog)

    # Question label
    label = QLabel(question)
    layout.addWidget(label)

    # Text input field
    text_input = QLineEdit()
    if default:
        text_input.setText(default)
    layout.addWidget(text_input)

    # Submit button
    submit_button = QPushButton("Submit")
    layout.addWidget(submit_button)
    submit_button.clicked.connect(dialog.accept)

    dialog.setLayout(layout)

    # Show the dialog and wait for user to submit
    if dialog.exec():
        return text_input.text()
    else:
        return ""


def gui_ask_for_choice(question: str, choices: list, title="Plugin Question") -> str:
    dialog = QDialog()
    dialog.setWindowTitle(title)

    layout = QVBoxLayout()
    label = QLabel(question)
    layout.addWidget(label)

    combo_box = QComboBox()
    combo_box.addItems(choices)
    layout.addWidget(combo_box)

    button = QPushButton('Confirm')
    button.clicked.connect(dialog.accept)
    layout.addWidget(button)

    dialog.setLayout(layout)
    dialog.exec()

    return combo_box.currentText()


class QProgressBarDialog(QDialog):
    def __init__(self, label_text="Loading...", on_cancel_callback=None, parent=None):
        super().__init__(parent)
        self.on_cancel_callback = on_cancel_callback

        self.setWindowTitle("DecLib Loading...")
        self.setWindowModality(Qt.ApplicationModal)
        self.layout = QVBoxLayout()

        # Add the label
        self.layout.addWidget(QLabel(label_text))

        # Add the progress bar
        self.progressBar = QProgressBar(self)
        self.progressBar.setValue(0)
        self.layout.addWidget(self.progressBar)

        # Add cancel button on the bottom
        self.button = QPushButton("Cancel", self)
        self.button.clicked.connect(self.on_cancel_clicked)
        self.layout.addWidget(self.button)

        self.setLayout(self.layout)

        # Initialize progress value
        self.progress = 0

    def on_cancel_clicked(self):
        if self.on_cancel_callback is not None:
            self.on_cancel_callback()

        self.close()

    def on_finished(self):
        self.close()

    def update_progress(self, value):
        self.progress += value
        if self.progress >= 100:
            self.on_finished()

        self.progressBar.setValue(self.progress)
