package main

import(
	//"fmt"
	"time"
	"log"
	bpf "github.com/iovisor/gobpf/bcc"
)

import "C"

// Using tracepoint
// tcp/tcp_probe
// specification can be found /sys/kernel/debug/tracing/events/tcp/tcp_probe

// This is the C code compiled by bcc to generate the bpf bytecode
const source string = `
typedef struct {
    u64 __unused__;
    u8 saddr;
    u32 daddr;
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

BPF_HASH(tcpinfo, u64, tcp_probe_t);

int tcptp(tcp_probe_t *args) {
    u64 pid = bpf_get_current_pid_tgid();
    tcp_probe_t ctcpi = *args; 
    tcpinfo.update(&pid, &ctcpi);
    return 0;
};
`

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

	recv := make(chan []byte)

	perfMap, err := bpf.InitPerfMap(table, recv)
	check(err)
	/*
	for{
		in := <-
	}
        */
	perfMap.Start()
	time.Sleep(10 * time.Second)
	perfMap.Stop()
}
