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
	sudo dnsmasq -C spoof.conf
	cp /etc/resolv.conf /etc/resolv.conf.bak
	echo nameserver 127.0.0.1 > /etc/resolv.conf

.PHONY: dnsmasq-stop
dnsmasq-stop:
	sudo killall dnsmasq
	cp /etc/resolv.conf.bak /etc/resolv.conf

.PHONY: iptables
iptables:
	iptables -A FORWARD -p udp --sport 53 -j DROP
