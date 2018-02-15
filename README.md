# windows-name-lookup
Tools for resolving hostnames on a Windows network

## Examples

Resolve host with LLMNR

```ns.py computer-1```

Resolve with NetBIOS

```ns.py --netbios <IFACE> computer-1```

Detect Responder with LLMNR or NetBIOS

```ns.py --responder```

```ns.py --responder --netbios <IFACE>```

This generates 2 random hostnames and performs a lookup using either LLMNR or NetBIOS. If both names resolve to the same host, Responder is likely running. It is usually enough just to check that a random hostname resolves at all.
