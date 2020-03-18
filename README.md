# gotrace
eBPF TCP tracer with Go

## Requires

[bcc](github.com/iovisor/bcc) (compile from source)
[gobpf](github.com/iovisor/gobpf)

Started from the nettop example from [DataDog/datadog-agent](github.com/DataDog/datadog-agent/pkg/ebpf/nettop).


## Note

Currently requires building with a fork of their eBPF library until a few errors in its compilation can be resolved.
