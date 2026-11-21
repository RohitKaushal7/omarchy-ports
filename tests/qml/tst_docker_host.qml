import QtQuick
import QtTest
import "../../lib/dockerHost.js" as DockerHost

TestCase {
  name: "DockerHost"

  function test_unset_is_the_local_daemon() {
    verify(DockerHost.isLocal(""))
    verify(DockerHost.isLocal(undefined))
    compare(DockerHost.helperEnvironment("").DOCKER_HOST, undefined)
  }

  function test_a_unix_socket_is_passed_through() {
    var host = "unix:///run/user/1000/docker.sock"
    verify(DockerHost.isLocal(host))
    compare(DockerHost.helperEnvironment(host).DOCKER_HOST, host)
  }

  // The finding: these were passed through and scanned as if local.
  function test_a_host_elsewhere_is_not_passed_through() {
    var hosts = ["tcp://10.0.0.5:2376", "ssh://me@build-box", "tcp://127.0.0.1:2375", "unix://", "npipe:////./pipe/docker"]
    for (var i = 0; i < hosts.length; i++) {
      verify(!DockerHost.isLocal(hosts[i]), hosts[i])
      compare(DockerHost.helperEnvironment(hosts[i]).DOCKER_HOST, undefined, hosts[i])
    }
  }

  function test_the_rest_of_the_environment_is_fixed() {
    var environment = DockerHost.helperEnvironment("ssh://me@build-box")
    compare(Object.keys(environment).sort(), ["LC_ALL", "PATH"])
    compare(environment.PATH, "/usr/bin:/bin")
    compare(environment.LC_ALL, "C")
  }
}
