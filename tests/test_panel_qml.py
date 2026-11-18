"""The panel's QML that runs without the shell, through Qt's own test runner."""

import os
import shutil
import subprocess
import unittest
from pathlib import Path

QML_TESTS = Path(__file__).resolve().parent / "qml"
# The Qt 6 runner. /usr/bin/qmltestrunner, where there is one, is Qt 5's.
RUNNER = next((path for path in ("/usr/lib/qt6/bin/qmltestrunner", shutil.which("qmltestrunner6"))
               if path and os.access(path, os.X_OK)), None)


@unittest.skipUnless(RUNNER, "Qt 6 qmltestrunner is not installed")
class QmlTests(unittest.TestCase):
    def test_qml(self):
        environment = {**os.environ, "QT_QPA_PLATFORM": "offscreen"}
        result = subprocess.run([RUNNER, "-input", str(QML_TESTS)], env=environment,
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("0 failed", result.stdout)
