.pragma library

// Which Docker the helper may scan: only the one on this machine. Published
// ports are listed, opened and copied as this machine's, so a daemon
// somewhere else would have its ports shown as local ones, with localhost
// URLs that reach whatever happens to be listening here instead.

// The panel's note when DOCKER_HOST names anything else. bin/ports.py says
// the same when run by hand with such a DOCKER_HOST.
var skippedNote = "Docker skipped: DOCKER_HOST isn't a local socket"

// DOCKER_HOST unset (the current Docker context decides, and the helper
// checks that one itself) or a unix socket path (rootless Docker). tcp://,
// ssh:// and anything else may be another machine.
function isLocal(host) {
  var text = String(host || "")
  return text === "" || /^unix:\/\/\S+$/.test(text)
}

// The helper runs with an emptied environment. DOCKER_HOST is passed through
// only when it is a local socket. Without it, docker picks the daemon from
// the current context, so what decides that context is passed through too:
// DOCKER_CONTEXT, and DOCKER_CONFIG for a config kept outside ~/.docker.
function helperEnvironment(host, context, config) {
  var environment = { PATH: "/usr/bin:/bin", LC_ALL: "C" }
  var text = String(host || "")
  if (text !== "") {
    if (isLocal(text)) environment.DOCKER_HOST = text
    return environment
  }
  if (context) environment.DOCKER_CONTEXT = String(context)
  if (config) environment.DOCKER_CONFIG = String(config)
  return environment
}
