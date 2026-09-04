# Kế hoạch core MTU 9000 / XDP fragments

## Phạm vi cố định

- Hai LAN: `enp1s0f0`, `enp1s0f1`.
- Hai WAN: `enp2s0f0`, `enp2s0f1`.
- NIC vật lý cấu hình MTU 9000; giai đoạn hiện tại chỉ nhận gói LAN tối đa 1500 byte.
- Một key 256 bit khai báo trong mã nguồn, giống nhau ở hai appliance.
- Tất cả Ethernet frame, kể cả ARP, đều được xác thực và mã hóa AES-256-GCM.
- Không có control plane, cơ sở dữ liệu, phân loại rule, vòng đời key, học MAC hay failover.
- Hai WAN luôn chia đều. Mỗi flow đi theo cửa sổ cố định 120000 byte rồi chuyển sang WAN tiếp theo.
- Chỉ UDP có sequence, tách frame WAN, ráp lại và reorder. TCP không đi qua reorder buffer.

## Giai đoạn 1 — xác nhận core 1500 trên topology MTU 9000

1. UMEM dùng chunk 4096 byte và socket yêu cầu `XDP_USE_SG`; chương trình `xdp.frags` được attach khi driver hỗ trợ.
2. BPF vẫn chặn dữ liệu LAN lớn hơn 1500 byte. Mục tiêu giai đoạn này là chứng minh việc đổi plumbing sang jumbo/XDP fragments không làm thay đổi đường dữ liệu 1500 cũ.
3. Userspace từ chối một packet nhiều descriptor thay vì hiểu nhầm từng fragment là một packet độc lập.
4. Kiểm tra ping, TCP iperf3 và UDP iperf3 trên một WAN, sau đó hai WAN.
5. Kiểm tra kernel/XSK counter: `rx_dropped`, `rx_invalid_descs`, `tx_invalid_descs`, ring full và số frame UMEM rảnh.

Điều kiện qua giai đoạn: chạy lâu không treo, không loop, TCP không về 0, không rò UMEM và kết quả 1500 không kém bản core trước.

## Giai đoạn 2 — nhận packet lớn bằng descriptor chain

1. Mở guard BPF cho Ethernet frame tới 9018/9022 byte.
2. Thay `struct ne_packet` một descriptor bằng packet descriptor chứa tối đa bốn segment UMEM.
3. RX gom chuỗi `XDP_PKT_CONTD` thành đúng một packet; chỉ publish packet sau khi nhận segment cuối.
4. Khi ring đầy hoặc chain lỗi, recycle toàn bộ segment đúng một lần.
5. Parser Ethernet/IP/UDP đọc qua segment boundary mà không giả định dữ liệu liên tục.

Với chunk 4096 byte, một frame 9000 cần tối đa ba chunk; giới hạn bốn chunk giữ headroom nhưng không tăng kích thước mỗi chunk vượt giới hạn driver.

## Giai đoạn 3 — mã hóa và TX jumbo

1. AES-GCM xử lý packet dạng scatter/gather hoặc copy có kiểm soát sang packet output chain.
2. Nếu encrypted frame vừa MTU WAN, TX bằng một logical packet gồm nhiều descriptor với `XDP_PKT_CONTD`.
3. Nếu không vừa MTU WAN, chỉ UDP được chia thành hai wire packet độc lập, mỗi packet có nonce/tag/sequence riêng.
4. Receiver xác thực đủ các phần UDP trước khi publish frame gốc sang LAN.
5. TCP tiếp tục dựa vào MSS; không đưa TCP vào bộ ráp/reorder UDP.

## Ngân sách bộ nhớ hiện tại

- `NE_FRAME = 4096` byte.
- `NE_N_FRAMES = 524288`.
- UMEM danh nghĩa: 2 GiB cho một pair.
- Tối đa bốn segment/logical packet, nhưng 9K dự kiến dùng ba segment.
- FQ chỉ nhận tối đa 75% frame để giữ frame cho TX, mã hóa và burst.

Không tăng UMEM trước khi counter chứng minh thiếu frame. Ưu tiên recycle đúng, batch RX/TX và tránh copy.

## Thứ tự kiểm thử bắt buộc

1. Build sạch và kiểm tra binary không link thư viện DB/control-plane.
2. Một LAN ↔ một WAN, payload 1500: ping, TCP, UDP.
3. Hai WAN chia đều, payload 1500: TCP dài hạn và UDP dài hạn.
4. Restart/stop nhiều lần để kiểm tra XDP detach, XSK/UMEM cleanup.
5. Chỉ sau khi bốn bước trên ổn định mới mở RX jumbo 3000, 6000 rồi 9000.

Mỗi lần mở kích thước mới phải giữ test regression 1500; không gộp thay đổi jumbo RX, crypto chain và TX chain vào một lần triển khai.
