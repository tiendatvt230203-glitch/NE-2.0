# Hard-coded core dataplane

The executable has one mode and no command-line control plane. It does not
contain database, policy, profile, PQC-handshake, key-rotation, CFM/failover or
MAC-learning code.

Core path:

1. AF_XDP receives on two LAN and two WAN interfaces using the existing
   multi-core RX/crypto/TX pipeline.
2. Every LAN frame is encrypted with the single 256-bit key in
   `src/core/util/static_config.c`.
3. IPv4 flows move between WANs in equal 120 KB windows. There are no weights.
4. Oversized encrypted UDP is split into two wire frames. The receiver
   authenticates, reassembles and reorders UDP before LAN TX.
5. Other L2 IPv4 traffic is authenticated/decrypted and sent directly.
6. ARP uses the same key and a dedicated encrypted EtherType.
7. WAN-to-LAN selection uses only the fixed client-MAC table.

The wire header contains no policy/key ID. It is:

```text
Ethernet/VLAN | encrypted EtherType | crypto-worker ID | nonce | ciphertext | GCM tag
```

Before building, edit `client_macs` in `src/core/util/static_config.c` separately
for each appliance. The single `core_key` value must be identical on both.
All four configured NICs must already be UP with MTU 9000 or greater. The
current validation phase still accepts plaintext input frames up to 1500.

```sh
make clean
make -j
./network-encryptor
```
