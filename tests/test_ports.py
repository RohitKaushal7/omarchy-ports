"""Behaviour of the Ports collector: turning ss and docker output into listeners."""

import functools
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "bin"))

import ports  # noqa: E402


# Captured from `ss -H -ltnpe` as a normal user. Sockets owned by root or by
# another user carry no users:() field; the user's own sockets do. Process
# names can contain spaces, and a socket inherited by forked workers lists
# every process holding it, each on its own fd. A socket bound to one
# interface (tailscaled's, the DHCPv6 client's) carries a %iface after the
# address, outside the brackets of an IPv6 one. -e adds the owning uid (when
# it is not root), the socket's inode, and v6only on an IPv6 socket.
SS_TCP = """\
LISTEN 0      4096                       0.0.0.0:6379  0.0.0.0:* ino:25465 sk:1003 cgroup:/system.slice/docker.service <->
LISTEN 0      4096                 127.0.0.53%lo:53    0.0.0.0:* uid:974 ino:5520 sk:3 cgroup:/system.slice/systemd-resolved.service <->
LISTEN 0      4096   [fd7a:115c:a1e0::6c01:74c1]:65009    [::]:* ino:18034 sk:1005 cgroup:/system.slice/tailscaled.service v6only:1 <->
LISTEN 0      4096   [fd7a:115c:a1e0::6c01:74c1]%tailscale0:65010    [::]:* ino:18035 sk:1006 cgroup:/system.slice/tailscaled.service v6only:1 <->
LISTEN 0      4096                   100.90.0.14%tailscale0:57203 0.0.0.0:* ino:18031 sk:1002 cgroup:/system.slice/tailscaled.service <->
LISTEN 0      128                          [::1]:51725    [::]:* users:(("python3",pid=112443,fd=6)) uid:1000 ino:15437892 sk:40b9 cgroup:/user.slice/user-1000.slice v6only:1 <->
LISTEN 0      511                        0.0.0.0:8080  0.0.0.0:* users:(("nginx",pid=911,fd=6),("nginx",pid=907,fd=6)) uid:1000 ino:9709935 sk:50dc cgroup:/user.slice <->
LISTEN 0      128                      127.0.0.1:3000  0.0.0.0:* users:(("Web Content",pid=5150,fd=41)) uid:1000 ino:9714789 sk:612b cgroup:/user.slice <->

not a socket line
"""

SS_UDP = """\
UNCONN 0      0                             127.0.0.1:57983 0.0.0.0:* users:(("python3",pid=112443,fd=7)) uid:1000 ino:15392429 sk:20ed cgroup:/user.slice <->
UNCONN 0      0                                     *:5353        *:* uid:974 ino:5519 sk:12 cgroup:/system.slice/systemd-resolved.service v6only:0 <->
UNCONN 0      0      [fe80::57c3:2a98:8b6a:e7ed]%wlo1:546      [::]:*
"""

POSTGRES_ID = "cf700d1b5f1e09c6859c55e74ad917fccb629810d60b67264fae300bb22e4a5b"
REDIS_ID = "496909168eb86ef27f24d6c813d55e02bf3b6c3dcc742a671fadf93452f8365b"
WEB_ID = "7d3c9a" + "0" * 58

# The fields `docker inspect` returns that the collector reads, shaped as
# docker 29 prints them: bindings per "port/proto", null for exposed-only
# ports, an empty HostIp meaning every address.
DOCKER_INSPECT = [
    {
        "Id": POSTGRES_ID,
        "Name": "/postgres",
        "Config": {
            "Image": "postgres:18",
            "Labels": {
                "com.docker.compose.project": "shop",
                "com.docker.compose.service": "postgres",
                "com.docker.compose.project.working_dir": "/home/alice/src/shop",
            },
        },
        "State": {"Running": True, "Status": "running", "StartedAt": "2026-11-17T09:12:44.123456789Z"},
        "NetworkSettings": {
            "Ports": {
                "5432/tcp": [
                    {"HostIp": "0.0.0.0", "HostPort": "5432"},
                    {"HostIp": "::", "HostPort": "5432"},
                ]
            }
        },
    },
    {
        "Id": WEB_ID,
        "Name": "/scratch-web",
        "Config": {"Image": "nginx:alpine", "Labels": None},
        "State": {"Running": True, "Status": "running", "StartedAt": "2026-11-18T13:14:00+05:30"},
        "NetworkSettings": {
            "Ports": {
                "80/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8088"}],
                "443/tcp": None,
                "5353/udp": [{"HostIp": "", "HostPort": "5354"}],
            }
        },
    },
    {
        "Id": "0e" + "1" * 62,
        "Name": "/stopped",
        "Config": {"Image": "busybox", "Labels": {}},
        "State": {"Running": False, "Status": "exited"},
        "NetworkSettings": {"Ports": {"9000/tcp": [{"HostIp": "0.0.0.0", "HostPort": "9000"}]}},
    },
]


class IgnoredPortsTests(unittest.TestCase):
    def test_single_ports_and_ranges(self):
        self.assertEqual(ports.parse_ignored("53, 631, 8000-8002"), {53, 631, 8000, 8001, 8002})

    def test_reversed_range_is_read_low_to_high(self):
        self.assertEqual(ports.parse_ignored("9002-9000"), {9000, 9001, 9002})

    def test_ranges_are_clamped_to_real_ports(self):
        self.assertEqual(ports.parse_ignored("65534-70000"), {65534, 65535})
        self.assertEqual(ports.parse_ignored("0-2"), {1, 2})

    def test_junk_is_skipped(self):
        self.assertEqual(ports.parse_ignored("abc, 0, 70000, -5, 7-, ,"), set())
        self.assertEqual(ports.parse_ignored(""), set())


class ClassifyTests(unittest.TestCase):
    def test_loopback_is_local(self):
        for address in ("127.0.0.1", "127.0.0.53", "::1"):
            self.assertEqual(ports.classify(address), "local", address)

    def test_tailscale_and_netbird_ranges_are_overlay(self):
        for address in ("100.64.0.1", "100.90.0.14", "100.127.255.255", "fd7a:115c:a1e0::6c01:74c1"):
            self.assertEqual(ports.classify(address), "overlay", address)

    def test_v4_mapped_addresses_classify_as_their_v4(self):
        self.assertEqual(ports.classify("::ffff:127.0.0.1"), "local")
        self.assertEqual(ports.classify("::ffff:100.90.0.14"), "overlay")
        self.assertEqual(ports.listener_url("tcp", 80, ["::ffff:192.168.1.5"]), "http://192.168.1.5:80")

    def test_wildcards_and_everything_else_are_network(self):
        for address in ("0.0.0.0", "::", "*", "192.168.1.8", "172.17.0.1",
                        "100.63.255.255", "100.128.0.0", "fd00::1", "example.local"):
            self.assertEqual(ports.classify(address), "network", address)


class ParseSocketsTests(unittest.TestCase):
    def test_tcp_rows(self):
        self.assertEqual(ports.parse_sockets(SS_TCP, "tcp"), [
            {"proto": "tcp", "address": "0.0.0.0", "port": 6379, "interface": "", "inode": 25465, "processes": []},
            {"proto": "tcp", "address": "127.0.0.53", "port": 53, "interface": "lo", "inode": 5520, "processes": []},
            {"proto": "tcp", "address": "fd7a:115c:a1e0::6c01:74c1", "port": 65009, "interface": "", "inode": 18034,
             "processes": []},
            {"proto": "tcp", "address": "fd7a:115c:a1e0::6c01:74c1", "port": 65010, "interface": "tailscale0",
             "inode": 18035, "processes": []},
            {"proto": "tcp", "address": "100.90.0.14", "port": 57203, "interface": "tailscale0", "inode": 18031,
             "processes": []},
            {"proto": "tcp", "address": "::1", "port": 51725, "interface": "", "inode": 15437892,
             "processes": [{"name": "python3", "pid": 112443, "fd": 6}]},
            {"proto": "tcp", "address": "0.0.0.0", "port": 8080, "interface": "", "inode": 9709935,
             "processes": [{"name": "nginx", "pid": 911, "fd": 6}, {"name": "nginx", "pid": 907, "fd": 6}]},
            {"proto": "tcp", "address": "127.0.0.1", "port": 3000, "interface": "", "inode": 9714789,
             "processes": [{"name": "Web Content", "pid": 5150, "fd": 41}]},
        ])

    def test_udp_rows_including_star_address(self):
        self.assertEqual(ports.parse_sockets(SS_UDP, "udp"), [
            {"proto": "udp", "address": "127.0.0.1", "port": 57983, "interface": "", "inode": 15392429,
             "processes": [{"name": "python3", "pid": 112443, "fd": 7}]},
            {"proto": "udp", "address": "*", "port": 5353, "interface": "", "inode": 5519, "processes": []},
            # Without -e's fields the socket has no inode to check a holder against.
            {"proto": "udp", "address": "fe80::57c3:2a98:8b6a:e7ed", "port": 546, "interface": "wlo1", "inode": 0,
             "processes": []},
        ])

    def test_inode_is_read_from_outside_the_process_names(self):
        line = ('LISTEN 0 128 127.0.0.1:4000 0.0.0.0:* users:(("x ino:1 y",pid=42,fd=5)) '
                'uid:1000 ino:777 sk:9 cgroup:/user.slice <->\n')
        [sock] = ports.parse_sockets(line, "tcp")
        self.assertEqual(sock["inode"], 777)
        self.assertEqual(sock["processes"], [{"name": "x ino:1 y", "pid": 42, "fd": 5}])


class SplitEndpointTests(unittest.TestCase):
    def test_plain_addresses(self):
        self.assertEqual(ports.split_endpoint("0.0.0.0:22"), ("0.0.0.0", 22, ""))
        self.assertEqual(ports.split_endpoint("[::1]:631"), ("::1", 631, ""))
        self.assertEqual(ports.split_endpoint("*:5353"), ("*", 5353, ""))

    def test_interface_suffix_is_split_off(self):
        self.assertEqual(ports.split_endpoint("127.0.0.53%lo:53"), ("127.0.0.53", 53, "lo"))
        self.assertEqual(ports.split_endpoint("100.90.0.14%tailscale0:57203"),
                         ("100.90.0.14", 57203, "tailscale0"))

    def test_interface_suffix_after_ipv6_brackets_is_split_off_first(self):
        # ss puts the interface outside the brackets, so the brackets only
        # close the host once it is gone.
        self.assertEqual(ports.split_endpoint("[fe80::57c3:2a98:8b6a:e7ed]%wlo1:546"),
                         ("fe80::57c3:2a98:8b6a:e7ed", 546, "wlo1"))
        self.assertEqual(ports.split_endpoint("[fd7a:115c:a1e0::6c01:74c1]%tailscale0:65009"),
                         ("fd7a:115c:a1e0::6c01:74c1", 65009, "tailscale0"))

    def test_not_an_endpoint(self):
        for text in ("", "nonsense", "1.2.3.4:", "1.2.3.4:http"):
            self.assertIsNone(ports.split_endpoint(text), text)


class ContainerPortsTests(unittest.TestCase):
    def test_published_bindings_of_running_containers(self):
        postgres = {"id": POSTGRES_ID, "name": "postgres", "image": "postgres:18",
                    "project": "shop", "service": "postgres", "startedAt": 1794906764}
        web = {"id": WEB_ID, "name": "scratch-web", "image": "nginx:alpine",
               "project": "", "service": "", "startedAt": 1794987840}
        self.assertEqual(ports.container_ports(DOCKER_INSPECT), [
            {"proto": "tcp", "port": 5432, "address": "0.0.0.0", "containerPort": 5432, "container": postgres},
            {"proto": "tcp", "port": 5432, "address": "::", "containerPort": 5432, "container": postgres},
            {"proto": "tcp", "port": 8088, "address": "127.0.0.1", "containerPort": 80, "container": web},
            {"proto": "udp", "port": 5354, "address": "0.0.0.0", "containerPort": 5353, "container": web},
        ])


class StartTimeTests(unittest.TestCase):
    def test_docker_times_with_any_precision_and_zone(self):
        self.assertEqual(ports.docker_time("2026-11-17T09:12:44.123456789Z"), 1794906764)
        self.assertEqual(ports.docker_time("2026-11-17T09:12:44Z"), 1794906764)
        self.assertEqual(ports.docker_time("2026-11-18T13:14:00+05:30"), 1794987840)

    def test_unusable_docker_times_are_zero(self):
        for text in (None, "", "yesterday", "0001-01-01T00:00:00Z", "2026-13-45T99:00:00Z",
                     "2026-11-17T09:12:44.1Z; rm -rf /"):
            self.assertEqual(ports.docker_time(text), 0, text)

    def test_process_start_ticks_become_wall_clock_seconds(self):
        # Booted at 1_794_900_000, started 227_621 ticks (2276 s at 100 Hz) later.
        self.assertEqual(ports.started_at(227621, 1794900000, 100), 1794902276)

    def test_unknown_parts_give_no_wall_clock_time(self):
        self.assertEqual(ports.started_at(0, 1794900000, 100), 0)
        self.assertEqual(ports.started_at(227621, 0, 100), 0)
        self.assertEqual(ports.started_at(227621, 1794900000, 0), 0)

    def test_boot_time_is_read_from_proc_stat(self):
        with tempfile.TemporaryDirectory() as proc:
            Path(proc, "stat").write_text("cpu  1 2 3 4\nintr 5\nbtime 1794900000\nprocesses 99\n")
            self.assertEqual(ports.boot_time(proc), 1794900000)

    def test_unreadable_boot_time_is_zero(self):
        with tempfile.TemporaryDirectory() as proc:
            self.assertEqual(ports.boot_time(proc), 0)
            Path(proc, "stat").write_text("cpu  1 2 3 4\nbtime soon\n")
            ports.boot_time.cache_clear()
            self.assertEqual(ports.boot_time(proc), 0)


# ------------------------------------------------------------------ grouping

SELF = {"owned": True, "start": 227621, "startedAt": 1794902276, "command": "python3 -m http.server 42635", "cwd": "/home/alice/code/site"}
PROCESSES = {
    112443: SELF,
    4242: {"owned": False, "start": 900, "command": "/usr/bin/prometheus", "cwd": "/"},
    5150: {"owned": True, "start": 0, "command": "", "cwd": ""},
    907: {"owned": True, "start": 50, "command": "nginx: master process", "cwd": "/"},
    911: {"owned": True, "start": 51, "command": "nginx: worker process", "cwd": "/"},
    1200: {"owned": True, "start": 10, "command": "/usr/lib/systemd/systemd --user", "cwd": "/"},
    3300: {"owned": True, "start": 90, "command": "/usr/bin/devserver", "cwd": "/home/alice"},
}


def describe(pid, name=None, fd=None, inode=0):
    return PROCESSES.get(pid)


def sock(address, port, proto="tcp", *procs, interface="", inode=4321):
    return {"proto": proto, "address": address, "port": port, "interface": interface, "inode": inode,
            "processes": [{"name": name, "pid": pid, "fd": 3} for name, pid in procs]}


def published(address, port, *, name="redis", cid=REDIS_ID, image="redis:7", container_port=None,
              project="shop", service="redis", proto="tcp"):
    return {"proto": proto, "port": port, "address": address,
            "containerPort": port if container_port is None else container_port,
            "container": {"id": cid, "name": name, "image": image, "project": project, "service": service}}


def build(sockets, containers=(), ignored=frozenset()):
    return ports.build_listeners(list(sockets), list(containers), describe, set(ignored))


def without_key(listener):
    return {k: v for k, v in listener.items() if k != "key"}


class BuildListenersTests(unittest.TestCase):
    def test_dual_stack_sockets_of_one_process_become_one_listener(self):
        listeners = build([sock("0.0.0.0", 42635, "tcp", ("python3", 112443)),
                           sock("::", 42635, "tcp", ("python3", 112443))])
        self.assertEqual([without_key(l) for l in listeners], [{
            "proto": "tcp", "port": 42635, "addresses": ["0.0.0.0", "::"], "interfaces": [],
            "scope": "network", "url": "http://localhost:42635",
            "owner": {"kind": "process", "name": "python3", "pid": 112443, "verified": True, "owned": True,
                      "start": 227621, "startedAt": 1794902276, "command": "python3 -m http.server 42635",
                      "cwd": "/home/alice/code/site"},
            "actions": ["open", "copy", "terminate", "kill"],
        }])

    def test_different_processes_on_one_port_stay_separate(self):
        listeners = build([sock("127.0.0.1", 8000, "tcp", ("python3", 112443)),
                           sock("::1", 8000, "tcp", ("prometheus", 4242))])
        self.assertEqual(sorted(l["owner"]["pid"] for l in listeners), [4242, 112443])
        self.assertEqual(len({l["key"] for l in listeners}), 2)

    def test_socket_shared_by_forked_workers_belongs_to_lowest_pid(self):
        [listener] = build([sock("0.0.0.0", 8080, "tcp", ("nginx", 911), ("nginx", 907))])
        self.assertEqual(listener["owner"]["pid"], 907)
        self.assertEqual(listener["owner"]["command"], "nginx: master process")

    def test_socket_activation_belongs_to_the_service_not_the_manager(self):
        # systemd --user keeps the activated socket and has the lower pid.
        [listener] = build([sock("127.0.0.1", 9000, "tcp", ("systemd", 1200), ("devserver", 3300))])
        self.assertEqual(listener["owner"]["pid"], 3300)

    def test_a_socket_only_the_manager_holds_is_never_signalled(self):
        [listener] = build([sock("127.0.0.1", 9000, "tcp", ("systemd", 1200))])
        self.assertEqual(listener["owner"]["name"], "systemd")
        self.assertFalse(listener["owner"]["owned"], "the user manager must stay read-only")

    def test_published_container_claims_the_anonymous_host_sockets(self):
        listeners = build([sock("0.0.0.0", 6379), sock("::", 6379)],
                          [published("0.0.0.0", 6379), published("::", 6379)])
        self.assertEqual([without_key(l) for l in listeners], [{
            "proto": "tcp", "port": 6379, "addresses": ["0.0.0.0", "::"], "interfaces": [],
            "scope": "network", "url": "http://localhost:6379",
            "owner": {"kind": "container", "name": "redis", "id": REDIS_ID, "image": "redis:7",
                      "project": "shop", "service": "redis", "containerPort": 6379},
            "actions": ["open", "copy", "stop"],
        }])

    def test_container_without_a_visible_host_socket_is_still_listed(self):
        listeners = build([], [published("127.0.0.1", 8088, name="scratch-web", cid=WEB_ID,
                                         image="nginx:alpine", container_port=80,
                                         project="", service="")])
        self.assertEqual([without_key(l) for l in listeners], [{
            "proto": "tcp", "port": 8088, "addresses": ["127.0.0.1"], "interfaces": [],
            "scope": "local", "url": "http://localhost:8088",
            "owner": {"kind": "container", "name": "scratch-web", "id": WEB_ID, "image": "nginx:alpine",
                      "project": "", "service": "", "containerPort": 80},
            "actions": ["open", "copy", "stop"],
        }])

    def test_unknown_owner_on_a_well_known_port_gets_a_guess(self):
        [listener] = build([sock("0.0.0.0", 8096)])
        self.assertEqual(listener["owner"], {"kind": "unknown", "guess": "Jellyfin", "guessFrom": "port"})
        self.assertEqual(listener["actions"], ["open", "copy"])

    def test_hidden_sockets_on_popular_service_ports_get_guesses(self):
        # One from each kind of service the table covers: file sharing,
        # desktop, name resolution, queues, sync, search, media, VPN.
        cases = {
            445: "SMB",
            1716: "KDE Connect",
            2049: "NFS",
            3389: "RDP",
            5355: "LLMNR",
            5672: "RabbitMQ",
            8384: "Syncthing",
            9200: "Elasticsearch",
            32400: "Plex",
            51820: "WireGuard",
            57621: "Spotify Connect",
        }
        for port, guess in cases.items():
            [listener] = build([sock("0.0.0.0", port)])
            self.assertEqual(listener["owner"], {"kind": "unknown", "guess": guess, "guessFrom": "port"}, port)

    def test_unknown_owner_on_an_unlisted_port_has_no_guess(self):
        [listener] = build([sock("127.0.0.1", 39033)])
        self.assertEqual(listener["owner"], {"kind": "unknown", "guess": None, "guessFrom": None})
        self.assertEqual(listener["scope"], "local")

    def test_socket_bound_to_a_vpn_interface_is_guessed_from_it(self):
        cases = {
            "tailscale0": "Tailscale",
            "wt0": "NetBird",
            "ztc3qwerty": "ZeroTier",
            "wg0": "WireGuard",
            "wg-home": "WireGuard",
        }
        for interface, guess in cases.items():
            [listener] = build([sock("100.90.0.14", 57203, interface=interface)])
            self.assertEqual(listener["owner"], {"kind": "unknown", "guess": guess, "guessFrom": "interface"},
                             interface)
            self.assertEqual(listener["interfaces"], [interface])

    def test_tailscaled_random_port_sockets_are_guessed_as_tailscale(self):
        listeners = build(ports.parse_sockets(SS_TCP, "tcp"))
        by_port = {l["port"]: l for l in listeners}
        for port in (57203, 65010):
            self.assertEqual(by_port[port]["owner"]["guess"], "Tailscale", port)
            self.assertEqual(by_port[port]["scope"], "overlay", port)
        # Unscoped, the same address says nothing about who opened it.
        self.assertIsNone(by_port[65009]["owner"]["guess"])

    def test_vpn_interface_beats_the_port_guess(self):
        [listener] = build([sock("100.90.0.14", 8096, interface="tailscale0")])
        self.assertEqual(listener["owner"]["guess"], "Tailscale")

    def test_other_interfaces_leave_the_port_guess(self):
        [loopback] = build([sock("127.0.0.53", 53, interface="lo")])
        self.assertEqual(loopback["owner"], {"kind": "unknown", "guess": "DNS", "guessFrom": "port"})
        self.assertEqual(loopback["interfaces"], ["lo"])
        [dhcp] = build([sock("fe80::57c3:2a98:8b6a:e7ed", 546, "udp", interface="wlo1")])
        self.assertIsNone(dhcp["owner"]["guess"])

    def test_named_process_on_a_vpn_interface_keeps_its_name(self):
        [listener] = build([sock("100.90.0.14", 4000, "tcp", ("python3", 112443), interface="tailscale0")])
        self.assertEqual(listener["owner"]["kind"], "process")
        self.assertEqual(listener["owner"]["name"], "python3")

    def test_real_process_name_beats_the_port_guess(self):
        [listener] = build([sock("0.0.0.0", 8096, "tcp", ("python3", 112443))])
        self.assertEqual(listener["owner"]["kind"], "process")
        self.assertEqual(listener["owner"]["name"], "python3")

    def test_vpn_only_listener_links_to_its_vpn_address(self):
        [listener] = build([sock("100.90.0.14", 57203)])
        self.assertEqual(listener["scope"], "overlay")
        self.assertEqual(listener["url"], "http://100.90.0.14:57203")

    def test_ipv6_address_is_bracketed_in_url(self):
        [listener] = build([sock("fd7a:115c:a1e0::6c01:74c1", 65009)])
        self.assertEqual(listener["url"], "http://[fd7a:115c:a1e0::6c01:74c1]:65009")

    def test_scoped_vpn_ipv6_socket_is_vpn_with_a_working_url(self):
        line = "LISTEN 0 4096 [fd7a:115c:a1e0::6c01:74c1]%tailscale0:65009 [::]:*\n"
        [listener] = build(ports.parse_sockets(line, "tcp"))
        self.assertEqual(listener["addresses"], ["fd7a:115c:a1e0::6c01:74c1"])
        self.assertEqual(listener["scope"], "overlay")
        self.assertEqual(listener["url"], "http://[fd7a:115c:a1e0::6c01:74c1]:65009")

    def test_widest_reach_sets_scope_but_loopback_keeps_localhost_url(self):
        [listener] = build([sock("127.0.0.1", 4000, "tcp", ("python3", 112443)),
                            sock("100.90.0.14", 4000, "tcp", ("python3", 112443))])
        self.assertEqual(listener["addresses"], ["127.0.0.1", "100.90.0.14"])
        self.assertEqual(listener["scope"], "overlay")
        self.assertEqual(listener["url"], "http://localhost:4000")

    def test_udp_has_no_url_or_browser_actions(self):
        [listener] = build([sock("127.0.0.1", 57983, "udp", ("python3", 112443))])
        self.assertIsNone(listener["url"])
        self.assertEqual(listener["actions"], ["terminate", "kill"])

    def test_process_of_another_user_is_read_only(self):
        [listener] = build([sock("0.0.0.0", 9090, "tcp", ("prometheus", 4242))])
        self.assertFalse(listener["owner"]["owned"])
        self.assertEqual(listener["actions"], ["open", "copy"])

    def test_process_without_a_verifiable_start_time_cannot_be_signalled(self):
        [listener] = build([sock("127.0.0.1", 3000, "tcp", ("Web Content", 5150))])
        self.assertEqual(listener["actions"], ["open", "copy"])

    def test_process_that_exited_before_it_was_described_is_read_only(self):
        [listener] = build([sock("127.0.0.1", 5001, "tcp", ("ghost", 777))])
        self.assertEqual(listener["owner"], {"kind": "process", "name": "ghost", "pid": 777, "verified": False,
                                             "owned": False,
                                             "start": 0, "startedAt": 0, "command": "", "cwd": ""})
        self.assertEqual(listener["actions"], ["open", "copy"])

    def test_ignored_ports_are_dropped(self):
        listeners = build([sock("127.0.0.53", 53), sock("127.0.0.1", 631), sock("0.0.0.0", 3001)],
                          ignored={53, 631})
        self.assertEqual([l["port"] for l in listeners], [3001])

    def test_sorted_by_port_then_protocol(self):
        listeners = build([sock("*", 5353, "udp"), sock("0.0.0.0", 5353), sock("0.0.0.0", 22)])
        self.assertEqual([(l["port"], l["proto"]) for l in listeners], [(22, "tcp"), (5353, "tcp"), (5353, "udp")])



# ------------------------------------------------------------ socket holders

def fake_process(proc_root, pid, *, comm="devserver", start=4242, fds=None, cmdline=b"devserver\0--port\x004000\0"):
    """A /proc/<pid> with just what describe_holder reads: stat, comm,
    cmdline, cwd, and fd links (fd number -> link target)."""
    directory = Path(proc_root, str(pid))
    (directory / "fd").mkdir(parents=True)
    (directory / "stat").write_text(f"{pid} ({comm}) S " + " ".join(["0"] * 18 + [str(start)] + ["0"] * 10) + "\n")
    (directory / "comm").write_text(comm + "\n")
    (directory / "cmdline").write_bytes(cmdline)
    os.symlink(proc_root, directory / "cwd")
    for fd, target in (fds or {}).items():
        os.symlink(target, directory / "fd" / str(fd))


# What ss printed for a dev server on :4000: pid 4100 holding socket 9001 on fd 3.
SS_DEVSERVER = ('LISTEN 0 128 127.0.0.1:4000 0.0.0.0:* users:(("devserver",pid=4100,fd=3)) '
                'uid:1000 ino:9001 sk:1 cgroup:/user.slice <->\n')


class SocketHolderTests(unittest.TestCase):
    """A process row carries the start time a later signal is checked
    against, so it must be the start time of the process ss saw holding the
    socket, not of whatever has the pid by the time /proc is read."""

    def setUp(self):
        self.proc = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.proc)

    def scan(self, text=SS_DEVSERVER):
        describe = functools.partial(ports.describe_holder, proc_root=self.proc)
        [listener] = ports.build_listeners(ports.parse_sockets(text, "tcp"), [], describe, set())
        return listener

    def test_the_process_still_holding_the_socket_can_be_signalled(self):
        fake_process(self.proc, 4100, fds={3: "socket:[9001]"})
        listener = self.scan()
        self.assertEqual(listener["owner"]["start"], 4242)
        self.assertTrue(listener["owner"]["verified"])
        self.assertEqual(listener["owner"]["command"], "devserver --port 4000")
        self.assertEqual(listener["actions"], ["open", "copy", "terminate", "kill"])

    def test_a_reused_pid_is_shown_read_only_with_none_of_its_details(self):
        # The dev server exited after ss ran and its pid went to an unrelated
        # shell of the same user, with a socket of its own on the same fd.
        fake_process(self.proc, 4100, comm="bash", start=9999, fds={3: "socket:[5555]"},
                     cmdline=b"bash\0")
        listener = self.scan()
        owner = listener["owner"]
        self.assertEqual((owner["name"], owner["pid"]), ("devserver", 4100))
        self.assertFalse(owner["verified"])
        self.assertFalse(owner["owned"])
        self.assertEqual((owner["start"], owner["command"]), (0, ""))
        self.assertNotIn("terminate", listener["actions"])
        self.assertNotIn("kill", listener["actions"])

    def test_a_reused_pid_without_the_fd_is_not_described(self):
        fake_process(self.proc, 4100, comm="devserver", start=9999)
        self.assertIsNone(ports.describe_holder(4100, "devserver", 3, 9001, self.proc))

    def test_the_socket_on_another_fd_is_not_enough(self):
        fake_process(self.proc, 4100, fds={3: "socket:[5555]", 4: "socket:[9001]"})
        self.assertIsNone(ports.describe_holder(4100, "devserver", 3, 9001, self.proc))

    def test_a_different_name_is_not_described(self):
        fake_process(self.proc, 4100, comm="bash", fds={3: "socket:[9001]"})
        self.assertIsNone(ports.describe_holder(4100, "devserver", 3, 9001, self.proc))

    def test_a_start_time_that_moves_during_the_check_is_not_described(self):
        fake_process(self.proc, 4100, fds={3: "socket:[9001]"})
        for reads in ([4242, 4242, 5000], [4242, 5000, 5000], [5000, 4242, 4242]):
            with mock.patch.object(ports, "read_start_time", side_effect=reads):
                self.assertIsNone(ports.describe_holder(4100, "devserver", 3, 9001, self.proc), reads)

    def test_a_socket_without_an_inode_or_fd_is_not_described(self):
        fake_process(self.proc, 4100, fds={3: "socket:[9001]"})
        self.assertIsNone(ports.describe_holder(4100, "devserver", 3, 0, self.proc))
        self.assertIsNone(ports.describe_holder(4100, "devserver", None, 9001, self.proc))

    def test_an_exited_holder_is_not_described(self):
        self.assertIsNone(ports.describe_holder(4100, "devserver", 3, 9001, self.proc))

    def test_ipv6_half_is_bound_to_its_own_socket(self):
        fake_process(self.proc, 4100, fds={3: "socket:[9001]", 4: "socket:[9002]"})
        text = ('LISTEN 0 128 [::1]:4000 [::]:* users:(("devserver",pid=4100,fd=4)) '
                'uid:1000 ino:9002 sk:2 cgroup:/user.slice v6only:1 <->\n') + SS_DEVSERVER
        listener = self.scan(text)
        self.assertEqual(listener["addresses"], ["::1", "127.0.0.1"])
        self.assertIn("terminate", listener["actions"])

    def test_names_compare_the_way_ss_prints_them(self):
        # ss stops at the first ')' and prints '.' or '?' for any byte outside
        # printable ASCII, so those bytes match a placeholder and nothing else.
        for comm, name in ((b"Web Content\n", "Web Content"), (b'a"b)c d', 'a"b'),
                           ("café x".encode(), "caf?? x"), (b"tab\tx", "tab.x")):
            self.assertTrue(ports.shown_by_ss(comm, name), (comm, name))
        for comm, name in ((b"bash", "devserver"), (b"abc", "ab."), (b"abc", "abcd"), (b"devserver2", "devserver")):
            self.assertFalse(ports.shown_by_ss(comm, name), (comm, name))


class OutputBoundsTests(unittest.TestCase):
    """The panel reads the helper's whole JSON document, so every field that
    comes from outside (command lines, working directories, image names) and
    the number of rows are bounded before they are printed."""

    def test_long_process_details_are_truncated_and_marked(self):
        details = {4001: {"owned": True, "start": 9,
                          "command": "python3 " + "x" * 5000, "cwd": "/home/alice/" + "d" * 1000}}
        [listener] = ports.build_listeners([sock("127.0.0.1", 7000, "tcp", ("python3", 4001))], [],
                                           lambda pid, *holder: details.get(pid), set())
        owner = listener["owner"]
        for field in ("command", "cwd"):
            self.assertLessEqual(len(owner[field]), 512, field)
            self.assertTrue(owner[field].endswith("…"), field)
        self.assertTrue(owner["command"].startswith("python3 xxx"))

    def test_long_container_fields_are_truncated(self):
        inspected = [{
            "Id": "ab" * 32,
            "Name": "/" + "n" * 900,
            "Config": {"Image": "registry.example/" + "i" * 2000, "Labels": {}},
            "State": {"Running": True},
            "NetworkSettings": {"Ports": {"80/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8081"}]}},
        }]
        [binding] = ports.container_ports(inspected)
        self.assertLessEqual(len(binding["container"]["name"]), 512)
        self.assertLessEqual(len(binding["container"]["image"]), 512)
        self.assertEqual(binding["container"]["id"], "ab" * 32)

    def test_listener_list_is_capped_with_a_warning(self):
        many = [{"key": f"tcp:{port}", "port": port, "proto": "tcp"} for port in range(1, 601)]
        warnings = []
        kept = ports.limit_listeners(many, warnings)
        self.assertEqual([listener["port"] for listener in kept], list(range(1, 513)))
        self.assertEqual(len(warnings), 1)
        self.assertIn("600", warnings[0])

    def test_short_listener_list_is_untouched(self):
        few = [{"key": "tcp:22", "port": 22, "proto": "tcp"}, {"key": "tcp:80", "port": 80, "proto": "tcp"}]
        warnings = []
        self.assertEqual(ports.limit_listeners(few, warnings), few)
        self.assertEqual(warnings, [])

if __name__ == "__main__":
    unittest.main()
