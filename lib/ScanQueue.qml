// One scan at a time, and no request dropped.
//
// A refresh asked for while a scan is running -- a setting saved mid-scan,
// the settle after an action, a right-click on the icon -- is held, and run
// once that scan has exited, instead of waiting for the next tick of the
// refresh timer (up to two minutes away). Any number of requests made
// meanwhile fold into that one rerun, which reads the settings as they are
// when it starts.
//
// Plain QtQml, with no shell imports, so tests/qml can run it on its own.

import QtQml

QtObject {
  id: queue

  // Bind to the scanner's `running`.
  property bool busy: false
  readonly property bool pending: queue._pending
  property bool _pending: false

  // Start a scan now. Only ever emitted while not busy.
  signal start()

  function request() {
    if (queue.busy) {
      queue._pending = true
      return
    }
    queue._pending = false
    queue.start()
  }

  // Call from the scanner's onExited. Quickshell has already handed over
  // the scan's output by then, and `running` only turns false after the
  // exited signal, so the rerun waits for the event loop to come round.
  function finished() {
    if (queue._pending) Qt.callLater(queue.request)
  }
}
