import QtQuick
import QtTest
import "../../lib"

TestCase {
  id: test
  name: "ScanQueue"

  property int starts: 0
  property bool scanning: false

  ScanQueue {
    id: queue
    busy: test.scanning
    // Like Panel.qml: starting a scan makes the scanner busy.
    onStart: { test.starts++; test.scanning = true }
  }

  // The scanner exiting, in the order Quickshell reports it: exited first,
  // running false after.
  function exitScan() {
    queue.finished()
    test.scanning = false
  }

  function init() {
    test.starts = 0
    test.scanning = false
    queue._pending = false
  }

  function test_idle_request_starts_at_once() {
    queue.request()
    compare(test.starts, 1)
    verify(!queue.pending)
  }

  // The bug: a setting saved during a scan was dropped until the next tick.
  function test_request_during_a_scan_runs_when_it_exits() {
    queue.request()
    queue.request()
    compare(test.starts, 1)
    verify(queue.pending)
    exitScan()
    tryCompare(test, "starts", 2)
    verify(!queue.pending)
  }

  function test_requests_during_a_scan_fold_into_one_rerun() {
    queue.request()
    queue.request()
    queue.request()
    queue.request()
    exitScan()
    tryCompare(test, "starts", 2)
    exitScan()
    wait(50)
    compare(test.starts, 2)
  }

  function test_exit_with_nothing_pending_starts_nothing() {
    queue.request()
    exitScan()
    wait(50)
    compare(test.starts, 1)
  }

  // If something else starts a scan before the rerun comes round, the
  // request is still held for that scan's exit, not lost.
  function test_request_survives_another_scan_starting_first() {
    queue.request()
    queue.request()
    queue.finished()
    test.scanning = false
    test.scanning = true
    wait(50)
    compare(test.starts, 1)
    verify(queue.pending)
    exitScan()
    tryCompare(test, "starts", 2)
  }
}
