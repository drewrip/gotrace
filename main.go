package main

import (
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/DataDog/datadog-agent/pkg/ebpf"
)

// For demonstration purposes, only tracking IPv4 TCP
func newTestConfig() *ebpf.Config {
	return &ebpf.Config{
		CollectTCPConns:              true,
		CollectUDPConns:              false,
		CollectIPv6Conns:             false,
		CollectLocalDNS:              false,
		DNSInspection:                false,
		UDPConnTimeout:               30 * time.Second,
		TCPConnTimeout:               2 * time.Minute,
		MaxTrackedConnections:        65536,
		ConntrackMaxStateSize:        65536,
		ConntrackShortTermBufferSize: 100,
		ProcRoot:                     "/proc",
		BPFDebug:                     false,
		EnableConntrack:              true,
		// With clients checking connection stats roughly every 30s, this gives us roughly ~1.6k + ~2.5k objects a second respectively.
		MaxClosedConnectionsBuffered: 50000,
		MaxConnectionsStateBuffered:  75000,
		ClientStateExpiry:            2 * time.Minute,
		ClosedChannelSize:            500,
	}
}

func main() {
	kernelVersion, err := ebpf.CurrentKernelVersion()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	fmt.Printf("-- Kernel: %d (%d.%d)--\n", kernelVersion, (kernelVersion>>16)&0xff, (kernelVersion>>8)&0xff)

	if supported, msg := ebpf.IsTracerSupportedByOS(nil); !supported {
		fmt.Fprintf(os.Stderr, "system-probe is not supported: %s\n", msg)
		os.Exit(1)
	}

	cfg := newTestConfig()
	cfg.BPFDebug = true

	t, err := ebpf.NewTracer(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Initialization complete. Starting nettop\n")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	printConns := func(now time.Time) {
		fmt.Printf("-- %s --\n", now)
		cs, err := t.GetActiveConnections(fmt.Sprintf("%d", os.Getpid()))
		if err != nil {
			fmt.Println(err)
		}
		for _, c := range cs.Conns {
			fmt.Println(ebpf.ConnectionSummary(c, cs.DNS))
		}
	}

	stopChan := make(chan struct{})
	go func() {
		// Print active connections immediately, and then again every 5 seconds
		tick := time.NewTicker(10 * time.Second)
		printConns(time.Now())
		for {
			select {
			case now := <-tick.C:
				printConns(now)
			case <-stopChan:
				tick.Stop()
				return
			}
		}
	}()

	<-sig
	stopChan <- struct{}{}

	t.Stop()
}
