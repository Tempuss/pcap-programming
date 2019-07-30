# pcap-programming

### Intro
* Caputring Network Traffic That Has Validate IP, TCP Header

### Prepare
* tcpreplay
* wireshark



### How to use


```
make

./pcap_test {NetworkInterface}

tcpreplay -i {NetworkInterFace} {NetworkPcapFile}

```

* HTTP Debug
```
curl --trace trace.txt -I 10.0.2.15/_health
```
