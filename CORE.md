# Hard-coded core dataplane

The executable has one mode and no command-line control plane. It does not
contain database, policy, profile, PQC-handshake, key-rotation, CFM/failover or
MAC-learning code.

Core path:

1. AF_XDP receives on one LAN and one WAN interface using the existing
   multi-core RX/crypto/TX pipeline.
2. BPF redirects only IPv4 TCP, UDP, ICMP and OSPF. ARP and all other
   protocols, including tagged VLAN frames, use the normal kernel bridge path.
3. The selected frames are encrypted with the single 256-bit key in
   `src/core/util/static_config.c`.
4. IPv4 input accepts every valid `total_length` up to `9000`, including
   the full `1501..8999` range. Encrypted non-UDP output must still fit WAN MTU;
   TCP relies on MSS negotiation, and oversized ICMP/OSPF output is dropped.
5. UDP is split only if encrypted length exceeds 9014 bytes (14-byte Ethernet
   header plus WAN MTU 9000); equality stays in one frame. Both fragments are authenticated
   before being reassembled at the receiver. There is no reorder/hold buffer.
6. TCP SYN MSS is clamped so encrypted TCP remains within WAN MTU 9000.
7. TCP, ICMP and OSPF are authenticated/decrypted and sent directly.

The wire header contains no policy/key ID. It is:

```text
Ethernet | encrypted EtherType | crypto-worker ID | nonce | ciphertext | GCM tag
```

The single `core_key` value must be identical on both appliances. The configured
LAN and WAN NICs must already be UP with MTU exactly 9000.

```sh
make clean
make -j
./network-encryptor
```
