from __future__ import annotations

import platform

SYS = platform.system()
FONT_FAMILY_UI = "SF Pro Text" if SYS == "Darwin" else ("Segoe UI" if SYS == "Windows" else "DejaVu Sans")
FONT_FAMILY_MONO = "Menlo" if SYS == "Darwin" else ("Consolas" if SYS == "Windows" else "DejaVu Sans Mono")

FONT_TITLE = (FONT_FAMILY_UI, 15, "bold")
FONT_UI = (FONT_FAMILY_UI, 11)
FONT_UI_BOLD = (FONT_FAMILY_UI, 11, "bold")
FONT_MONO = (FONT_FAMILY_MONO, 12)
FONT_MONO_SMALL = (FONT_FAMILY_MONO, 10)
FONT_STATUS = (FONT_FAMILY_MONO, 11)

THEMES = {
    "Nord Frost (Dark)": {
        "bg_window": "#242933",
        "bg_card": "#2E3440",
        "bg_editor": "#1E222A",
        "bg_elevated": "#3B4252",
        "border": "#4C566A",
        "fg_main": "#ECEFF4",
        "fg_muted": "#9AA5B8",
        "text_dark": "#1E222A",
        "frost_cyan": "#88C0D0",
        "frost_blue": "#81A1C1",
        "aurora_green": "#A3BE8C",
        "aurora_yellow": "#EBCB8B",
        "aurora_red": "#BF616A",
        "select_bg": "#434C5E",
        "select_fg": "#ECEFF4",
    },
    "Nord Snow Storm (Light)": {
        "bg_window": "#D8DEE9",
        "bg_card": "#ECEFF4",
        "bg_editor": "#FFFFFF",
        "bg_elevated": "#E5E9F0",
        "border": "#B8C2D1",
        "fg_main": "#2E3440",
        "fg_muted": "#4C566A",
        "text_dark": "#FFFFFF",
        "frost_cyan": "#006B8F",
        "frost_blue": "#2B5B84",
        "aurora_green": "#236B36",
        "aurora_yellow": "#8A5300",
        "aurora_red": "#B02A37",
        "select_bg": "#C8D3E3",
        "select_fg": "#1E222A",
    },
}

NORD = THEMES["Nord Frost (Dark)"].copy()
