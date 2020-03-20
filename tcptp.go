package main

import(
	"fmt"
	"time"
	"log"
	"bytes"
	"encoding/binary"
	bpf "github.com/iovisor/gobpf/bcc"
)

import "C"

// Using tracepoint
// tcp/tcp_probe
// specification can be found /sys/kernel/debug/tracing/events/tcp/tcp_probe

// This is the C code compiled by bcc to generate the bpf bytecode
const source string = `
#include <uapi/linux/ptrace.h>

typedef struct {
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u16 sport;
    u16 dport;
    u32 mark;
    u16 data_len;
    u32 snd_nxt;
    u32 snd_una;
    u32 snd_cwnd;
    u32 ssthresh;
    u32 snd_wnd;
    u32 srtt;
    u32 rcv_wnd;
    u64 sock_cookie;
} tcp_probe_t;

typedef struct {
    u16 data_len;
    u16 sport;
    u16 dport;
    u32 mark;
} tcp_data;

BPF_HASH(tcpinfo, u64, tcp_data);

int tcptp(tcp_probe_t *args) {
    u64 pid = bpf_get_current_pid_tgid();
    tcp_data dat = {};
    dat.data_len = args->data_len;
    dat.sport = args->sport;
    dat.dport = args->dport;
    dat.mark = args->mark;
    tcpinfo.update(&pid, &dat);
    return 0;
};
`
type tcpInfo struct {
	Datalen uint16
	Sport uint16
	Dport uint16
	Mark uint32
}

func check(err error){
	if err != nil{
		log.Fatalf("err: %v", err)
	}
}

func main(){
	
	m := bpf.NewModule(source, []string{})
	defer m.Close()
	
	fd, err := m.LoadTracepoint("tcptp")
	check(err)
	err = m.AttachTracepoint("tcp:tcp_probe", fd)
	check(err)
	
	table := bpf.NewTable(m.TableId("tcpinfo"), m) 
	time.Sleep(5 * time.Second)
	var dat tcpInfo
	for it := table.Iter(); it.Next(); {
		err := binary.Read(bytes.NewBuffer(it.Leaf()), binary.LittleEndian, &dat)
		check(err)
		k := binary.LittleEndian.Uint16(it.Key())
		fmt.Printf("[PID] %d: %v\n", k, dat)
	}
}
