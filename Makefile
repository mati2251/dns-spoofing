INPUT_FILE = main.c

.PHONY: dns-spoofing
dns-spoofing: $(INPUT_FILE)
	gcc -o $@ $< -lpcap -lm -lnet -g

.PHONY: clean
clean: 
	rm -f dns-spoofing

.PHONY: nginx-run
nginx-run:
	sudo nginx -p $(shell pwd) -c nginx.conf

.PHONY: nginx-stop
nginx-stop:
	sudo nginx -s stop

.PHONY: dnsmasq-run
dnsmasq-run:
	sudo dnsmasq -C dnsmasq.conf

.PHONY: dnsmasq-stop
dnsmasq-stop:
	sudo killall dnsmasq

.PHONY: iptables
iptables:
	iptables -A FORWARD -p udp --dport 53 -j DROP
