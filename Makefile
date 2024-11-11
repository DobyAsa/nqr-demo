all: ping ping6

ping: ping.c
	gcc ping.c -o ping -lpcap
ping6: ping6.c
	gcc ping6.c -o ping6 -lpcap
clean: 
	rm ping ping6