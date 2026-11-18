"""Host guidelines the panel's QML has to keep, checked in the source.

The shell can't be loaded here, so these read the plugin's own QML. Process
names, working directories, command lines, Docker's stderr and the filter
query all reach Text items, and a Text left at its default AutoText renders
markup-shaped input such as <img src="https://example.invalid/t"> as rich
text, which can load a resource. Omarchy's own components (PanelToolTip,
PanelHero, ConfirmDialog, PanelActionButton, the bar tooltip) already set
PlainText; only the plugin's own Text items are checked.
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCES = sorted([ROOT / "Panel.qml", *(ROOT / "lib").glob("*.qml")])


def blocks(source: str, type_name: str):
    """(line, body) of every `<type_name> {` object in a QML file, the body
    without nested objects, found by brace matching."""
    for match in re.finditer(rf"(?<![\w.]){type_name}\s*\{{", source):
        depth, start, own = 0, match.end() - 1, []
        for index in range(start, len(source)):
            char = source[index]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    break
            if depth == 1 and char not in "{}":
                own.append(char)
        yield source.count("\n", 0, match.start()) + 1, "".join(own)


class PlainTextTests(unittest.TestCase):
    def test_every_text_item_is_plain_text(self):
        found = 0
        for path in SOURCES:
            for line, body in blocks(path.read_text(), "Text"):
                found += 1
                self.assertRegex(body, r"\btextFormat:\s*Text\.PlainText\b",
                                 f"{path.name}:{line} Text without textFormat: Text.PlainText")
        self.assertGreaterEqual(found, 10, "the Text items were not found")

    def test_the_checker_catches_a_text_left_at_auto_text(self):
        source = "Item {\n  Text {\n    text: o.name\n    Behavior on x { NumberAnimation {} }\n  }\n}\n"
        [(line, body)] = blocks(source, "Text")
        self.assertEqual(line, 2)
        self.assertNotRegex(body, r"textFormat")


class MotionTests(unittest.TestCase):
    def test_durations_go_through_style_duration(self):
        # Style.duration() is 0 once animations are turned off.
        for path in SOURCES:
            for number, text in enumerate(path.read_text().splitlines(), 1):
                for value in re.findall(r"\bduration:\s*([^\s;}]+)", text):
                    self.assertTrue(value.startswith("Style.duration("),
                                    f"{path.name}:{number} bare duration {value}")


if __name__ == "__main__":
    unittest.main()
