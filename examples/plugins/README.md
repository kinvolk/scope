# Scope Probe Plugins

Scope probe plugins let you insert your own custom metrics into Scope and get them displayed in the UI.

<img src="../../imgs/plugin.png" width="800" alt="Scope Probe plugin screenshot" align="center">

You can find some examples at the
[the example plugins](https://github.com/weaveworks/scope/tree/master/examples/plugins)
directory. We currently provide two examples:
* A
  [Python plugin](https://github.com/weaveworks/scope/tree/master/examples/plugins/http-requests)
  using [bcc](http://iovisor.github.io/bcc/) to extract incoming HTTP request
  rates per process, without any application-level instrumentation requirements and negligible performance toll (metrics are obtained in-kernel without any packet copying to userspace).
  **Note:** This plugin needs a [recent kernel version with ebpf support](https://github.com/iovisor/bcc/blob/master/INSTALL.md#kernel-configuration). It will not compile on current [dlite](https://github.com/nlf/dlite) and boot2docker hosts.
* A
  [Go plugin](https://github.com/weaveworks/scope/tree/master/examples/plugins/iowait),
  using [iostat](https://en.wikipedia.org/wiki/Iostat) to provide host-level CPU IO wait or idle
  metrics.

The example plugins can be run by calling `make` in their directory.
This will build the plugin, and immediately run it in the foreground.
To run the plugin in the background, see the `Makefile` for examples
of the `docker run ...` command.

If the running plugin was picked up by Scope, you will see it in the list of `PLUGINS`
in the bottom right of the UI.

## Plugin ID

Each plugin should have an unique ID. It is forbidden to change it
during plugin's lifetime. The scope probe will get the plugin's ID
from the plugin's socket filename. So from the socket named
my-plugin.sock, the scope probe will deduce ID as "my-plugin". ID can
contain only alphanumeric sequences optionally separated with a dash.

## Plugin registration

All plugins should listen for HTTP connections on a unix socket in the
`/var/run/scope/plugins` directory. The scope probe will recursively scan that
directory every 5 seconds, to look for sockets being added (or removed). It is
also valid to put the plugin unix socket in a sub-directory, in case you want
to apply some permissions, or store other information with the socket.

## Protocol

There are several interfaces a plugin may (or must) implement. Usually
implementing an interface means handling specific requests. What
requests these are is described below.

### Reporter interface

The reporter interface is an interface that every plugin _must_
implement. Implementing this request means listening for HTTP requests
at `/report`.

Add the "reporter" string to the `interfaces` field in the plugin
specification.

#### Report

When the scope probe discovers a new plugin unix socket it will begin
periodically making a `GET` request to the `/report` endpoint. The
report data structure returned from this will be merged into the
probe's report and sent to the app. An example of the report structure
can be viewed at the `/api/report` endpoint of any scope app.

In addition to any data about the topology nodes, the report returned
from the plugin must include some metadata about the plugin itself.

For example:

```json
{
  "Processes": {},
  "Plugins": [
    {
      "id":          "iowait",
      "label":       "IOWait",
      "description": "Adds a graph of CPU IO Wait to hosts",
      "interfaces":  ["reporter"],
      "api_version": "1",
    }
  ]
}
```

Note that the `Plugins` section includes exactly one plugin
description. The plugin description fields are:

* `id` is used to check for duplicate plugins. It is required. Described in [the Plugin ID section](#plugin-id).
* `label` is a human readable plugin label displayed in the UI. It is required.
* `description` is displayed in the UI.
* `interfaces` is a list of interfaces which this plugin supports. It is required, and must contain at least `["reporter"]`.
* `api_version` is used to ensure both the plugin and the scope probe can speak to each other. It is required, and must match the probe.

You may notice a small chicken and egg problem - the plugin reports to
the scope probe what interfaces it supports, but the scope probe can
learn that only by doing a `GET /report` request which will be handled
by the plugin if it implements the "reporter" interface. This is
solved (or worked around) by requiring the plugin to always implements the
"reporter" interface.

### Controller interface

Implementing the controller interface means that the plugin can react
to HTTP `POST` control requests sent by the app. The plugin will
receive them only for controls it exposed in its reports. The requests
will come to the `/control` endpoint.

Add the "controller" string to the `interfaces` field in the plugin
specification.

#### Control

The `POST` requests will have a JSON-encoded body with the following contents:

```json
{
  "AppID": "some ID of an app"
  "NodeID": "an ID of the node that had the control activated"
  "Control": "the name of the activated control"
}
```

The body of the response should also be a JSON-encoded data. Usually
the body would be an empty JSON object (so, "{}" after
serialization). If some error happens during handling the control,
then the plugin can send a response with an `error ` field set, for
example:

```json
{
  "error": "An error message here"
}
```

Sometimes the control activation can make the control obsolete, so the
plugin may want to hide it (for example, control for stopping the
container should be hidden after the container is stopped). For this
to work, the plugin can send a shortcut report by filling the
`ShortcutReport` field in the response, like for example:

```json
{
  "ShortcutReport": { body of the report here }
}
```

##### How to expose controls

Each topology in the report (be it host, pod, endpoint and so on) has
a set of available controls a node in the topology may want to
show. The following (rather artificial) example shows a topology with
two controls (`ctrl-one` and `ctrl-two`) and two nodes, each having a
different control from the two:

```json
{
  "Host": {
    "controls": {
      "ctrl-one": {
        "id": "ctrl-one",
        "human": "Ctrl One",
        "icon": "fa-futbol-o",
        "rank": 1
      },
      "ctrl-two": {
        "id": "ctrl-two",
        "human": "Ctrl Two",
        "icon": "fa-beer",
        "rank": 2
      }
    },
    "nodes": {
      "host1": {
        "latestControls": {
          "latest": {
            "ctrl-one": {
              "timestamp": "2016-07-20T15:51:05Z01:00",
              "value": {
                "dead": false
              }
            }
          }
        }
      },
      "host2": {
        "latestControls": {
          "latest": {
            "ctrl-two": {
              "timestamp": "2016-07-20T15:51:05Z01:00",
              "value": {
                "dead": false
              }
            }
          }
        }
      }
    }
  }
}
```

When control "ctrl-one" is activated, the plugin will receive a request like:

```json
{
  "AppID": "some ID of an app"
  "NodeID": "host1"
  "Control": "ctrl-one"
}
```

A short note about the "icon" field of the topology control - the
value for it can be taken from [Font Awesome
Cheatsheet](http://fontawesome.io/cheatsheet/)
