nettop:
	go build -o nettop -tags "linux_bpf" main.go

tcpinfo:
	go build -o tcpinfo tcptp.go

clean:
	rm tcpinfo nettop
