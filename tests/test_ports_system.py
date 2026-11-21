"""Ports collector against real processes, the real ss, and a stand-in docker."""

import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

BIN = Path(__file__).resolve().parent.parent / "bin"
sys.path.insert(0, str(BIN))

import ports  # noqa: E402

PORTS = str(BIN / "ports.py")
REDIS_ID = "496909168eb86ef27f24d6c813d55e02bf3b6c3dcc742a671fadf93452f8365b"

TCP_LISTENER = (
    "import socket, time\n"
    "s = socket.socket(); s.bind(('127.0.0.1', 0)); s.listen()\n"
    "print(s.getsockname()[1], flush=True)\n"
    "time.sleep(60)\n"
)

UDP_LISTENER = (
    "import socket, time\n"
    "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('127.0.0.1', 0))\n"
    "print(s.getsockname()[1], flush=True)\n"
    "time.sleep(60)\n"
)


def exited_within(child, seconds):
    try:
        child.wait(timeout=seconds)
        return True
    except subprocess.TimeoutExpired:
        return False


def exited_pid():
    child = subprocess.Popen(["true"])
    child.wait()
    return child.pid


class ChildProcessCase(unittest.TestCase):
    """Spawns processes this user owns and always reaps them."""

    def spawn(self, code="import time; time.sleep(60)", cwd=None):
        child = subprocess.Popen([sys.executable, "-c", code], cwd=cwd,
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        self.addCleanup(self.reap, child)
        return child

    @staticmethod
    def reap(child):
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)
        child.stdout.close()


class DescribeProcessTests(ChildProcessCase):
    def test_own_child_is_described(self):
        with tempfile.TemporaryDirectory() as workdir:
            # Popen returns while the kernel is still setting up the child's
            # new image, when its cmdline can read empty; wait until it runs.
            child = self.spawn("print('up', flush=True); import time; time.sleep(60)", cwd=workdir)
            child.stdout.readline()
            details = ports.describe_process(child.pid)
            self.assertIsNotNone(details)
            self.assertTrue(details["owned"])
            self.assertGreater(details["start"], 0)
            # Just started, so its wall-clock start is now, to within the
            # second boot_time and the tick rounding each lose.
            self.assertLessEqual(abs(details["startedAt"] - time.time()), 5)
            self.assertIn("time.sleep(60)", details["command"])
            self.assertEqual(details["cwd"], os.path.realpath(workdir))

    def test_process_of_another_user_is_not_owned(self):
        details = ports.describe_process(1)
        self.assertIsNotNone(details)
        self.assertFalse(details["owned"])

    def test_exited_process_is_not_described(self):
        self.assertIsNone(ports.describe_process(exited_pid()))

    def test_holder_of_a_real_socket_is_described_against_it(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            inode = os.fstat(listener.fileno()).st_ino
            comm = Path("/proc/self/comm").read_text().strip()
            details = ports.describe_holder(os.getpid(), comm, listener.fileno(), inode)
            self.assertIsNotNone(details)
            self.assertEqual(details["start"], ports.describe_process(os.getpid())["start"])
            self.assertIsNone(ports.describe_holder(os.getpid(), comm, listener.fileno(), inode + 1))
            self.assertIsNone(ports.describe_holder(os.getpid(), comm + "x", listener.fileno(), inode))


class SignalProcessTests(ChildProcessCase):
    def start_of(self, child):
        details = ports.describe_process(child.pid)
        self.assertIsNotNone(details, "child could not be described")
        return details["start"]

    def test_matching_identity_is_terminated(self):
        child = self.spawn()
        ports.signal_process(child.pid, self.start_of(child), "term")
        self.assertTrue(exited_within(child, 5))
        self.assertEqual(child.returncode, -signal.SIGTERM)

    def test_kill_sends_sigkill(self):
        child = self.spawn()
        ports.signal_process(child.pid, self.start_of(child), "kill")
        self.assertTrue(exited_within(child, 5))
        self.assertEqual(child.returncode, -signal.SIGKILL)

    def test_stale_start_time_is_refused_and_process_survives(self):
        child = self.spawn()
        with self.assertRaises(ports.ActionError):
            ports.signal_process(child.pid, self.start_of(child) + 1, "term")
        self.assertFalse(exited_within(child, 0.3))

    def test_unknown_signal_is_refused_and_process_survives(self):
        child = self.spawn()
        with self.assertRaises(ports.ActionError):
            ports.signal_process(child.pid, self.start_of(child), "hup")
        self.assertFalse(exited_within(child, 0.3))

    @unittest.skipIf(os.geteuid() == 0, "as root this would really signal init")
    def test_process_of_another_user_is_refused(self):
        with self.assertRaises(ports.ActionError):
            ports.signal_process(1, ports.describe_process(1)["start"], "term")

    def test_exited_process_is_refused(self):
        with self.assertRaises(ports.ActionError):
            ports.signal_process(exited_pid(), 1, "term")


class FakeDocker:
    """Stands in for subprocess.run: answers each docker subcommand from a
    script and records every argv it was handed."""

    def __init__(self, replies):
        self.replies = replies
        self.calls = []
        self.environments = []

    def __call__(self, argv, **kwargs):
        self.calls.append(list(argv))
        self.environments.append(kwargs.get("env"))
        code, out, err = self.replies.get(argv[1], (1, "", "unexpected docker call"))
        return subprocess.CompletedProcess(argv, code, out, err)


INSPECT_RUNNING = ["docker", "inspect", "--format", "{{.State.Running}}", REDIS_ID]
INSPECT_CONTEXT = ["docker", "context", "inspect", "--format", "{{.Name}} {{.Endpoints.docker.Host}}"]
LOCAL_CONTEXT = (0, "default unix:///var/run/docker.sock\n", "")


def stand_in(**replies):
    return FakeDocker({"context": LOCAL_CONTEXT, **replies})


class StopContainerTests(unittest.TestCase):
    def test_malformed_ids_never_reach_docker(self):
        for bad in ("", "abc", "postgres; rm -rf /", "g" * 64, REDIS_ID[:11]):
            docker = stand_in(inspect=(0, "true\n", ""), stop=(0, "", ""))
            with self.assertRaises(ports.ActionError, msg=bad):
                ports.stop_container(bad, run=docker, environ={})
            self.assertEqual(docker.calls, [], bad)

    def test_container_that_is_not_running_is_not_stopped(self):
        docker = stand_in(inspect=(0, "false\n", ""))
        with self.assertRaises(ports.ActionError):
            ports.stop_container(REDIS_ID, run=docker, environ={})
        self.assertEqual(docker.calls, [INSPECT_CONTEXT, INSPECT_RUNNING])

    def test_running_container_is_stopped(self):
        docker = stand_in(inspect=(0, "true\n", ""), stop=(0, REDIS_ID + "\n", ""))
        ports.stop_container(REDIS_ID, run=docker, environ={})
        self.assertEqual(docker.calls, [INSPECT_CONTEXT, INSPECT_RUNNING, ["docker", "stop", REDIS_ID]])

    def test_stop_goes_to_the_socket_the_current_context_names(self):
        # dockerd-rootless-setuptool.sh's context, chosen with `docker context use`.
        docker = stand_in(context=(0, "rootless unix:///run/user/1000/docker.sock\n", ""),
                          inspect=(0, "true\n", ""), stop=(0, "", ""))
        ports.stop_container(REDIS_ID, run=docker, environ={"DOCKER_CONTEXT": "rootless"})
        resolve, *calls = docker.environments
        self.assertEqual(resolve, {"DOCKER_CONTEXT": "rootless"})
        self.assertEqual(calls, [{"DOCKER_HOST": "unix:///run/user/1000/docker.sock",
                                  "DOCKER_CONTEXT": "default"}] * 2)

    def test_a_context_elsewhere_is_never_asked_to_stop(self):
        for answer in ("elsewhere tcp://10.0.0.5:2376\n", "box ssh://me@build-box\n", "default \n", ""):
            docker = stand_in(context=(0, answer, ""), inspect=(0, "true\n", ""), stop=(0, "", ""))
            with self.assertRaises(ports.RemoteDocker, msg=answer):
                ports.stop_container(REDIS_ID, run=docker, environ={})
            self.assertEqual(docker.calls, [INSPECT_CONTEXT], answer)

    def test_a_docker_host_elsewhere_is_never_asked_to_stop(self):
        for host in ("tcp://10.0.0.5:2376", "ssh://me@build-box", "tcp://127.0.0.1:2375", "unix://"):
            docker = stand_in(inspect=(0, "true\n", ""), stop=(0, "", ""))
            with self.assertRaises(ports.RemoteDocker, msg=host):
                ports.stop_container(REDIS_ID, run=docker, environ={"DOCKER_HOST": host})
            self.assertEqual(docker.calls, [], host)

    def test_a_local_docker_host_is_used_without_asking_the_context(self):
        docker = stand_in(inspect=(0, "true\n", ""), stop=(0, "", ""))
        ports.stop_container(REDIS_ID, run=docker, environ={"DOCKER_HOST": "unix:///run/user/1000/docker.sock"})
        self.assertEqual(docker.calls, [INSPECT_RUNNING, ["docker", "stop", REDIS_ID]])
        self.assertEqual({env["DOCKER_HOST"] for env in docker.environments}, {"unix:///run/user/1000/docker.sock"})

    def test_docker_refusing_to_stop_is_an_action_error(self):
        docker = FakeDocker({"inspect": (0, "true\n", ""),
                             "stop": (1, "", "Error response from daemon: permission denied")})
        with self.assertRaises(ports.ActionError):
            ports.stop_container(REDIS_ID, run=docker, environ={})


class CliTests(ChildProcessCase):
    def run_cli(self, *args, env=None):
        result = subprocess.run([sys.executable, PORTS, *map(str, args)],
                                capture_output=True, text=True, timeout=20, env=env)
        self.assertTrue(result.stdout.strip(), f"no JSON on stdout; stderr: {result.stderr!r}")
        return result.returncode, json.loads(result.stdout)

    def listening(self, code=TCP_LISTENER):
        child = self.spawn(code)
        return child, int(child.stdout.readline())

    def test_scan_reports_a_listening_child(self):
        child, port = self.listening()
        code, payload = self.run_cli("scan", "--no-docker")
        self.assertEqual(code, 0)
        matches = [l for l in payload["listeners"] if l["port"] == port]
        self.assertEqual(len(matches), 1, payload)
        listener = matches[0]
        self.assertEqual(listener["owner"]["kind"], "process")
        self.assertEqual(listener["owner"]["pid"], child.pid)
        self.assertTrue(listener["owner"]["owned"])
        self.assertTrue(listener["owner"]["verified"], "the scan should bind the pid to its socket")
        self.assertEqual(listener["scope"], "local")
        self.assertEqual(listener["url"], f"http://localhost:{port}")
        self.assertIn("terminate", listener["actions"])

    def test_a_process_named_like_ss_syntax_is_still_its_own(self):
        # ss prints names unescaped; this one ends in a backslash before the
        # closing quote and carries an inode-shaped word.
        child, port = self.listening("open('/proc/self/comm', 'w').write(' ino:5 \\\\')\n" + TCP_LISTENER)
        code, payload = self.run_cli("scan", "--no-docker")
        self.assertEqual(code, 0)
        [listener] = [l for l in payload["listeners"] if l["port"] == port]
        self.assertEqual(listener["owner"]["kind"], "process")
        self.assertEqual((listener["owner"]["pid"], listener["owner"]["name"]), (child.pid, " ino:5 \\"))
        self.assertTrue(listener["owner"]["verified"])
        self.assertIn("terminate", listener["actions"])

    def test_ignored_port_is_left_out(self):
        _, port = self.listening()
        _, payload = self.run_cli("scan", "--no-docker", "--ignore", f"1-2,{port}")
        self.assertNotIn(port, [l["port"] for l in payload["listeners"]])

    def test_udp_is_only_scanned_when_asked(self):
        _, port = self.listening(UDP_LISTENER)
        _, without = self.run_cli("scan", "--no-docker")
        _, with_udp = self.run_cli("scan", "--no-docker", "--udp")
        self.assertNotIn(port, [l["port"] for l in without["listeners"]])
        self.assertIn((port, "udp"), [(l["port"], l["proto"]) for l in with_udp["listeners"]])

    def test_signal_command_terminates_a_scanned_listener(self):
        child, port = self.listening()
        _, payload = self.run_cli("scan", "--no-docker")
        [listener] = [l for l in payload["listeners"] if l["port"] == port]
        code, result = self.run_cli("signal", "--pid", child.pid,
                                    "--start", listener["owner"]["start"], "--signal", "term")
        self.assertEqual((code, result), (0, {"ok": True}))
        self.assertTrue(exited_within(child, 5))

    def test_signal_command_reports_a_refusal_as_json(self):
        child, _ = self.listening()
        code, result = self.run_cli("signal", "--pid", child.pid, "--start", 1, "--signal", "term")
        self.assertEqual(code, 1)
        self.assertIsInstance(result.get("error"), str)
        self.assertTrue(result["error"])
        self.assertFalse(exited_within(child, 0.3))

    def fake_path(self, docker_script=None):
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory)
        os.symlink(shutil.which("ss"), os.path.join(directory, "ss"))
        if docker_script is not None:
            docker = Path(directory, "docker")
            docker.write_text(docker_script)
            docker.chmod(0o755)
        environment = {k: v for k, v in os.environ.items() if not k.startswith("DOCKER_")}
        return dict(environment, PATH=directory)

    # A stand-in docker that notes how it was run, one JSON line per call,
    # answers `context inspect` with FAKE_CONTEXT (the default context's
    # local socket unless set), and reports no containers.
    RECORDING_DOCKER = (
        "#!/usr/bin/python3\n"
        "import json, os, sys\n"
        "with open(os.path.join(os.path.dirname(sys.argv[0]), 'calls'), 'a') as log:\n"
        "    log.write(json.dumps({'argv': sys.argv[1:], 'context': os.environ.get('DOCKER_CONTEXT'),\n"
        "                          'host': os.environ.get('DOCKER_HOST')}) + '\\n')\n"
        "if sys.argv[1] == 'context':\n"
        "    print(os.environ.get('FAKE_CONTEXT', 'default unix:///var/run/docker.sock'))\n"
        "sys.exit(0)\n"
    )
    CONTEXT_ARGV = ["context", "inspect", "--format", "{{.Name}} {{.Endpoints.docker.Host}}"]

    def docker_calls(self, env):
        log = Path(env["PATH"], "calls")
        return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []

    def test_docker_host_elsewhere_is_not_scanned_and_says_so(self):
        _, port = self.listening()
        for host in ("tcp://10.0.0.5:2376", "ssh://me@build-box"):
            env = dict(self.fake_path(self.RECORDING_DOCKER), DOCKER_HOST=host)
            code, payload = self.run_cli("scan", env=env)
            self.assertEqual(code, 0)
            self.assertEqual(self.docker_calls(env), [], host)
            self.assertEqual(payload["warnings"], ["Docker skipped: DOCKER_HOST isn't a local socket"], host)
            self.assertIn(port, [l["port"] for l in payload["listeners"]])

    def test_rootless_docker_socket_is_scanned(self):
        env = dict(self.fake_path(self.RECORDING_DOCKER), DOCKER_HOST="unix:///run/user/1000/docker.sock")
        code, payload = self.run_cli("scan", env=env)
        self.assertEqual((code, payload["warnings"]), (0, []))
        self.assertEqual(self.docker_calls(env), [
            {"argv": ["ps", "--quiet", "--no-trunc"], "context": "default",
             "host": "unix:///run/user/1000/docker.sock"},
        ])

    def test_the_default_context_is_scanned_through_its_socket(self):
        env = self.fake_path(self.RECORDING_DOCKER)
        code, payload = self.run_cli("scan", env=env)
        self.assertEqual((code, payload["warnings"]), (0, []))
        self.assertEqual(self.docker_calls(env), [
            {"argv": self.CONTEXT_ARGV, "context": None, "host": None},
            {"argv": ["ps", "--quiet", "--no-trunc"], "context": "default", "host": "unix:///var/run/docker.sock"},
        ])

    def test_a_context_naming_a_local_socket_is_scanned(self):
        # Rootless Docker's `rootless` context, or Docker Desktop's
        # `desktop-linux`, picked by DOCKER_CONTEXT or `docker context use`.
        env = dict(self.fake_path(self.RECORDING_DOCKER), DOCKER_CONTEXT="rootless",
                   FAKE_CONTEXT="rootless unix:///run/user/1000/docker.sock")
        code, payload = self.run_cli("scan", env=env)
        self.assertEqual((code, payload["warnings"]), (0, []))
        self.assertEqual(self.docker_calls(env), [
            {"argv": self.CONTEXT_ARGV, "context": "rootless", "host": None},
            {"argv": ["ps", "--quiet", "--no-trunc"], "context": "default",
             "host": "unix:///run/user/1000/docker.sock"},
        ])

    def test_a_context_elsewhere_is_not_scanned_and_says_so(self):
        cases = {
            "elsewhere tcp://10.0.0.5:2376": 'Docker skipped: context "elsewhere" isn\'t a local socket',
            "box ssh://me@build-box": 'Docker skipped: context "box" isn\'t a local socket',
            "": "Docker skipped: the current Docker context isn't a local socket",
        }
        for answer, warning in cases.items():
            env = dict(self.fake_path(self.RECORDING_DOCKER), FAKE_CONTEXT=answer)
            code, payload = self.run_cli("scan", env=env)
            self.assertEqual((code, payload["warnings"]), (0, [warning]), answer)
            self.assertEqual([call["argv"] for call in self.docker_calls(env)], [self.CONTEXT_ARGV], answer)

    def test_unreachable_docker_is_a_warning_and_sockets_still_list(self):
        _, port = self.listening()
        env = self.fake_path("#!/bin/sh\necho 'Cannot connect to the Docker daemon' >&2\nexit 1\n")
        code, payload = self.run_cli("scan", env=env)
        self.assertEqual(code, 0)
        self.assertTrue(any("Cannot connect to the Docker daemon" in w for w in payload["warnings"]), payload)
        self.assertIn(port, [l["port"] for l in payload["listeners"]])

    def test_machine_without_docker_scans_quietly(self):
        _, port = self.listening()
        code, payload = self.run_cli("scan", env=self.fake_path())
        self.assertEqual(code, 0)
        self.assertEqual(payload["warnings"], [])
        self.assertIn(port, [l["port"] for l in payload["listeners"]])


    def test_runaway_docker_output_is_a_warning_and_sockets_still_list(self):
        _, port = self.listening()
        env = self.fake_path("#!/usr/bin/python3\nimport sys\nsys.stdout.write('x' * 6_000_000)\n")
        code, payload = self.run_cli("scan", env=env)
        self.assertEqual(code, 0)
        self.assertTrue(any("too much output" in w for w in payload["warnings"]), payload["warnings"])
        self.assertIn(port, [l["port"] for l in payload["listeners"]])


    def test_docker_ps_noise_never_reaches_inspect(self):
        _, port = self.listening()
        real_id = "c" * 64
        script = (
            "#!/usr/bin/python3\n"
            "import sys\n"
            "if sys.argv[1] == 'context':\n"
            "    print('default unix:///var/run/docker.sock')\n"
            "    sys.exit(0)\n"
            "if sys.argv[1] == 'ps':\n"
            "    print('WARNING: not a container id')\n"
            f"    print('{real_id}')\n"
            "    sys.exit(0)\n"
            "if sys.argv[1] == 'inspect':\n"
            "    if sys.argv[2:] != ['" + real_id + "']:\n"
            "        sys.stderr.write('inspect was handed ' + ' '.join(sys.argv[2:]) + '\\n')\n"
            "        sys.exit(1)\n"
            "    print('[]')\n"
            "    sys.exit(0)\n"
            "sys.exit(1)\n"
        )
        code, payload = self.run_cli("scan", env=self.fake_path(script))
        self.assertEqual(code, 0)
        self.assertEqual(payload["warnings"], [])
        self.assertIn(port, [l["port"] for l in payload["listeners"]])

class RunBoundedTests(unittest.TestCase):
    """ss and docker are read through run_bounded: a child that talks too much
    or runs too long is killed rather than buffered or waited on."""

    def test_small_output_comes_back_like_subprocess_run(self):
        result = ports.run_bounded(
            [sys.executable, "-c", "import sys; print('hi'); sys.stderr.write('err'); sys.exit(3)"],
            timeout=5, limit=1024)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (3, "hi\n", "err"))

    def test_output_over_the_limit_kills_the_child_early(self):
        started = time.monotonic()
        with self.assertRaises(ports.OutputTooLarge):
            ports.run_bounded(
                [sys.executable, "-c", "import sys, time; sys.stdout.write('x' * 1_000_000); sys.stdout.flush(); time.sleep(4)"],
                timeout=3, limit=100_000)
        self.assertLess(time.monotonic() - started, 2.5)

    def test_silent_child_past_its_deadline_is_killed(self):
        started = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):
            ports.run_bounded([sys.executable, "-c", "import time; time.sleep(4)"], timeout=0.5, limit=1024)
        self.assertLess(time.monotonic() - started, 2.5)

if __name__ == "__main__":
    unittest.main()
