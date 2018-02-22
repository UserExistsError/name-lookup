# name-lookup
Tools for resolving hostnames

## Examples
Use -4 (default) or -6 to use LLMNR/mDNS over ip4/ip6. NetBIOS NS is ip4 only.

### Resolve hosts with LLMNR, mDNS, or NBNS
```
ns.py --llmnr computer-1
ns.py --mdns computer-1
ns.py --netbios <IFACE|BCAST> computer-1
```

### Detect Responder with LLMNR, mDNS, or NBNS
```
ns.py --responder --llmnr
ns.py --responder --mdns
ns.py --responder --netbios <IFACE|BCAST>
```

This generates 2 random hostnames and performs a lookup using either LLMNR or NetBIOS. If both names resolve to the same host, Responder is likely running. It is usually enough just to check that a random hostname resolves at all.
