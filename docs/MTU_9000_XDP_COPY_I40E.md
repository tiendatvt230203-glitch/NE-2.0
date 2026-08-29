# MTU đến 9000 với AF_XDP copy trên i40e

Nhánh này giữ `XDP_FLAGS_DRV_MODE` và ép AF_XDP chạy `XDP_COPY`. UMEM dùng
chunk 4096 byte; packet jumbo được truyền bằng chuỗi descriptor AF_XDP có cờ
`XDP_PKT_CONTD`. Hai BPF program được khai báo bằng section `xdp.frags` và XSK
được bind với `XDP_USE_SG`.

## Yêu cầu hệ thống

- Kernel và driver i40e phải công bố khả năng XDP RX scatter-gather
  (`NETDEV_XDP_ACT_RX_SG`). Nếu không có, thao tác attach/bind sẽ thất bại thay
  vì âm thầm cắt packet.
- Tất cả cổng nằm trên cùng đường bridge/bond phải được cấu hình MTU phù hợp.
- MTU IP được hỗ trợ là 576 đến 9000. Kích thước packet userspace tối đa là
  12288 byte để còn chỗ cho Ethernet/VLAN và metadata PQC.
- Hai thiết bị tunnel phải chạy cùng wire format PQC/bonding.

Kiểm tra driver và MTU:

```sh
ethtool -i eth0
ip -details link show dev eth0
```

Cấu hình ví dụ MTU 9000 cho LAN và các WAN:

```sh
ip link set dev eth0 mtu 9000
ip link set dev eth1 mtu 9000
ip link set dev eth2 mtu 9000
```

Kiểm tra không phân mảnh với IPv4 (8972 byte payload + 28 byte IP/ICMP):

```sh
ping -M do -s 8972 <peer-ip>
```

Sau đó chạy TCP/UDP bằng `iperf3` và theo dõi dòng `DP-STATS`. Các trường mới:

- `jumbo_free`: số linear jumbo buffer còn trống.
- `jumbo(rx=...)`: packet multi-buffer đã ghép thành công.
- `jumbo(tx=...)`: packet đã được tách thành descriptor chain khi TX.
- `jumbo(drop=...)`: chain lỗi, quá lớn hoặc hết jumbo buffer.

Nếu XSK bind thất bại ở MTU lớn hơn 4096, log sẽ chỉ rõ yêu cầu
`XDP_USE_SG / NETDEV_XDP_ACT_RX_SG`. Khi đó cần nâng kernel/i40e hoặc kiểm tra
firmware/NIC feature; chương trình không fallback sang generic/SKB XDP vì nhánh
này dành cho native driver mode.
