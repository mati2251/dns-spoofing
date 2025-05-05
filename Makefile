INPUT_FILE = main.c

.PHONY: dns-spoofing
dns-spoofing: $(INPUT_FILE)
	gcc -o $@ $< -lpcap -lm -lnet -g

.PHONY: clean
clean: 
	rm -f dns-spoofing
