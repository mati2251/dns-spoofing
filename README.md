# DNS spoofing + ARP spoofing
## How it works?
* ARP spoofing by flooding the ARP responses with faked MAC addresses of the default gateway.
* DNS spoofing by redirecting all DNS queries to the local DNS server, which will respond with faked IP addresses.
## Build
```bash
make
```
## Requirements
Every DNS query will be redirected to the local DNS server. 
To spoof the DNS, you need to run a local DNS server. 
I recommend using `dnsmasq`; an example configuration can be found in `dnsmasq.conf`. To run this configuration, you can use the specific `make` target.
```bash
make dnsmasq-run
```
You also need to block all packets forwarded to the real DNS server. You can use the specific `make` target for this.
```bash
make iptables
```
## Usage
Run the program with root privileges:
```bash
./dns_spoofing <interface>
```
## License
MIT License
