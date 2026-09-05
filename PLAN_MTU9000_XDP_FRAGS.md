# Kế hoạch core MTU 9000 / XDP fragments

## Phạm vi cố định

- Một LAN: `enp1s0f0`.
- Một WAN: `enp2s0f0`.
- NIC vật lý bắt buộc cấu hình đúng MTU 9000.
- Core nhận mọi kích thước IPv4 hợp lệ có `total_length <= 9000`, bao gồm
  toàn bộ khoảng `1501..8999`.
- Một key 256 bit khai báo trong mã nguồn, giống nhau ở hai appliance.
- BPF chỉ redirect IPv4 TCP, UDP, ICMP và OSPF. ARP và traffic khác là
  `XDP_PASS` cho kernel.
- Không có control plane, cơ sở dữ liệu, phân loại rule, vòng đời key, học MAC hay failover.
- Không có bond, chọn WAN, flow affinity hay reorder buffer trong giai đoạn
  debug này. UDP chỉ có tách/ráp wire-frame khi cần.

## Trạng thái triển khai

1. UMEM dùng chunk 4096 byte và socket yêu cầu `XDP_USE_SG`; chương trình
   trong section `xdp.frags` được loader gắn cờ `BPF_F_XDP_HAS_FRAGS`.
2. BPF dùng `bpf_xdp_get_buff_len()` để lấy tổng chiều dài multi-buffer; không
   dùng `data_end-data` làm tổng chiều dài packet 9K.
3. `struct ne_packet` chứa tối đa bốn segment. RX gom `XDP_PKT_CONTD` thành
   đúng một logical packet, và recycle toàn chain khi lỗi.
4. Crypto worker tuyến tính hóa chain vào buffer 9216 byte; kết quả được ghi
   lại thành chain trước khi TX.
5. TX đặt `XDP_PKT_CONTD` trên mọi descriptor trừ descriptor cuối.
6. TCP SYN được clamp MSS với 29 byte overhead để encrypted TCP vẫn nằm trong
   giới hạn MTU 9000.
7. UDP vượt wire MTU được tạo thành hai encrypted wire-packet: fragment đầu
   lấp đầy ngân sách MTU, fragment sau chứa payload còn lại. Receiver xác thực
   cả hai và ráp lại, không có reorder/hold buffer.
8. Kiểm tra ARP/kernel path, ping, TCP iperf3 và UDP iperf3 trên một WAN.
9. Kiểm tra kernel/XSK counter: `rx_dropped`, `rx_invalid_descs`,
   `tx_invalid_descs`, ring full và số frame UMEM rảnh.

Điều kiện qua giai đoạn: chạy lâu không treo, không loop, TCP không về 0, không rò UMEM và kết quả 1500 không kém bản core trước.

## Việc chưa làm

1. ICMP/OSPF không tách/ráp riêng; nếu cộng overhead mã hóa vượt MTU WAN thì drop.
2. Chỉ xử lý Ethernet không tag; VLAN/QinQ đi XDP_PASS cho kernel.
3. Chưa tối ưu crypto scatter/gather trực tiếp; hiện tại dùng buffer tuyến tính
   riêng theo worker để ưu tiên tính đúng đắn.

## Ngân sách bộ nhớ hiện tại

- `NE_FRAME = 4096` byte.
- `NE_N_FRAMES = 524288`.
- UMEM danh nghĩa: 2 GiB cho một pair.
- Tối đa bốn segment/logical packet; 9K thông thường dùng ba segment.
- UDP reassembly table còn 256 entry/worker, chỉ giữ hai fragment đang chờ ráp;
  đây không phải reorder buffer.
- FQ chỉ nhận tối đa 75% frame để giữ frame cho TX, mã hóa và burst.

Không tăng UMEM trước khi counter chứng minh thiếu frame. Ưu tiên recycle đúng, batch RX/TX và tránh copy.

## Thứ tự kiểm thử bắt buộc

1. Build sạch và kiểm tra binary không link thư viện DB/control-plane.
2. Một LAN ↔ một WAN, payload 1500: ARP/kernel path, ping, TCP, UDP.
3. Restart/stop nhiều lần để kiểm tra XDP detach, XSK/UMEM cleanup.
4. Test UDP với IPv4 total_length 1500, 1501, 2000, 4096, 8000, 9000 và
   sát ngưỡng tách; gói vừa ngân sách mã hóa đi một wire-packet, vượt thì hai.
5. Test TCP jumbo; xác nhận MSS được clamp và WAN không phát frame vượt MTU.

Mọi thay đổi tiếp theo phải giữ regression toàn dải đến 9000.
