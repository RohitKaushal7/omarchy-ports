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
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "bin"))

import ports  # noqa: E402
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


# Qt's editable text inputs. Every one follows the clipboard for as long as it
# exists, and on Wayland that means fetching every change any app makes.
EDITABLE = re.compile(r"(?<![\w.])(TextField|TextInput|TextEdit|TextArea)\s*\{")


def without_comments(source: str) -> str:
    """Line comments blanked to spaces, so offsets and braces line up."""
    return re.sub(r"(?m)(^|\s)//[^\n]*", lambda m: m[1] + " " * (len(m[0]) - len(m[1])), source)


def enclosing_objects(source: str, index: int):
    """(type name, offset of its "{") of every object around `index`,
    innermost first. Braces that do not open an object (handlers, functions,
    JS) are tracked with no name."""
    stack = []
    for match in re.finditer(r"[{}]", source[:index]):
        if match[0] == "{":
            name = re.search(r"([A-Za-z_][\w.]*)\s*$", source[:match.start()])
            stack.append((name[1] if name else None, match.start()))
        elif stack:
            stack.pop()
    return [entry for entry in reversed(stack) if entry[0]]


def own_body(source: str, brace: int) -> str:
    """An object's text from its "{", without its nested objects."""
    depth, own = 0, []
    for char in source[brace:]:
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                break
        if depth == 1 and char not in "{}":
            own.append(char)
    return "".join(own)


def editable_inputs_outside_an_open_loader(source: str):
    """Line numbers of editable text inputs not inside a Loader whose
    `active` depends on the panel being opened."""
    source = without_comments(source)
    for match in EDITABLE.finditer(source):
        loaders = [brace for name, brace in enclosing_objects(source, match.start()) if name == "Loader"]
        if not any(re.search(r"\bactive:[^\n]*\bopened\b", own_body(source, brace)) for brace in loaders):
            yield source.count("\n", 0, match.start()) + 1


class ClipboardTests(unittest.TestCase):
    """An editable input left in the lazy content would outlive the panel:
    the content stays built after the first open, and a clipboard transfer
    that never completes would then stall the shell with the panel closed."""

    def test_editable_inputs_exist_only_while_the_panel_is_open(self):
        found = 0
        for path in SOURCES:
            source = path.read_text()
            found += len(EDITABLE.findall(without_comments(source)))
            self.assertEqual(list(editable_inputs_outside_an_open_loader(source)), [], path.name)
        self.assertGreaterEqual(found, 1, "the filter field was not found")

    def test_the_checker_catches_an_input_that_outlives_the_panel(self):
        cases = {
            "Item {\n  Column {\n    TextField { text: q }\n  }\n}\n": [3],
            "Loader {\n  active: true\n  sourceComponent: Component { TextInput {} }\n}\n": [3],
            # A Loader further out, or `opened` in a nested object, is not enough.
            "Loader {\n  active: root.opened\n}\nTextEdit {}\n": [4],
            "Loader {\n  Item { visible: opened }\n  TextArea {}\n}\n": [3],
        }
        for source, lines in cases.items():
            self.assertEqual(list(editable_inputs_outside_an_open_loader(source)), lines, source)

    def test_the_checker_passes_an_input_built_per_open(self):
        source = ("Loader {\n  id: l\n  // active: true\n  active: root.opened\n"
                  "  function f(e) { if (e) { return } }\n"
                  "  sourceComponent: Component {\n    TextField { onTextChanged: { q = text } }\n  }\n}\n")
        self.assertEqual(list(editable_inputs_outside_an_open_loader(source)), [])


class DockerNoteTests(unittest.TestCase):
    def test_the_panel_and_the_helper_give_the_same_note(self):
        source = (ROOT / "lib" / "dockerHost.js").read_text()
        self.assertIn(f'var skippedNote = "{ports.REMOTE_DOCKER}"', source)


if __name__ == "__main__":
    unittest.main()
