all: read_pcap.c
	gcc read_pcap.c -lpcap -o read_pcap
clean: read_pcap
	rm read_pcap