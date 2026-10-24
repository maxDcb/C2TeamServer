from PyQt6.QtGui import QPalette
from PyQt6.QtWidgets import QApplication, QComboBox, QVBoxLayout, QWidget
from qt_material import apply_stylesheet

from C2Client.console_style import CONSOLE_COLORS
from C2Client.panel_style import apply_dark_panel_style, style_dark_combo_popup


def test_combo_popup_keeps_compact_dark_selection_with_material_theme():
    app = QApplication.instance() or QApplication([])
    original_stylesheet = app.styleSheet()
    original_palette = QPalette(app.palette())
    panel = None
    try:
        apply_stylesheet(app, theme="dark_teal.xml")
        panel = QWidget()
        apply_dark_panel_style(panel)
        layout = QVBoxLayout(panel)
        combo = QComboBox(panel)
        style_dark_combo_popup(combo)
        combo.addItems(["All", "module", "beacon", "screenshot"])
        layout.addWidget(combo)
        panel.show()
        combo.showPopup()
        view = combo.view()
        selected = combo.model().index(2, 0)
        view.setCurrentIndex(selected)
        app.processEvents()

        row = view.visualRect(selected)
        pixel = view.viewport().grab().toImage().pixelColor(
            view.viewport().width() - 12, row.center().y()
        )
        assert pixel.name() == CONSOLE_COLORS["selection"]
        assert row.height() <= 36
        assert view.window().width() >= 140
    finally:
        if panel is not None:
            panel.close()
        app.setStyleSheet(original_stylesheet)
        app.setPalette(original_palette)
