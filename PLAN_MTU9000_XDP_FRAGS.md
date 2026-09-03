# Kế hoạch tích hợp MTU 9000 bằng XDP fragments

## 1. Mục tiêu của tài liệu

Tài liệu này là bản thiết kế và checklist triển khai MTU 9000 cho Network Encryptor (NE).
Một AI hoặc lập trình viên ở lần làm việc sau phải đọc tài liệu này trước, sau đó đọc lại
repository và xác nhận các giả định bằng code hiện tại trước khi sửa.

Baseline khi lập kế hoạch:

- Nhánh: `main`.
- Commit: `3254f03` (`Don dataplane va chi giu UDP reorder`).
- UMEM hiện tại dùng frame 2048 byte và chỉ biểu diễn được một packet bằng một descriptor.
- XDP LAN/WAN hiện dùng section `xdp`, chưa dùng `xdp.frags`.
- UDP mã hóa hiện chỉ chia đúng hai mảnh `FRAG0/FRAG1`.
- Reassembly hiện chỉ ghép hai mảnh và kết quả không được vượt `NE_FRAME`.
- TCP không dùng reorder buffer; TCP dùng MSS clamp.

Tài liệu này chỉ là kế hoạch. Không được coi các phase bên dưới là đã triển khai.

Thứ tự công việc cấp cao:

- [ ] Chốt baseline MTU 1500 để làm mốc chống regression.
- [ ] Hạng mục triển khai đầu tiên: nền tảng `xdp.frags`/AF_XDP multi-buffer.
- [ ] Bổ sung packet-chain và ownership cho nhiều descriptor (điều kiện để `xdp.frags` chạy đúng).
- [ ] RX/TX được một jumbo frame dạng nhiều segment.
- [ ] Chuẩn hóa packet jumbo thành packet-chain có tối đa 4 XDP segments để xử lý nội bộ.
- [ ] Giữ UDP wire output tối đa 2 Ethernet packet: `FULL` hoặc `FRAG0 + FRAG1`.
- [ ] Đổi UDP reassembly hai mảnh để output được packet-chain jumbo, không bị giới hạn `NE_FRAME`.
- [ ] Đưa packet đã ráp qua UDP reorder đúng một lần.
- [ ] Chuyển TCP MSS clamp sang effective path MTU; không fragment/reassemble TCP.
- [ ] Kiểm thử 1500, 9000, 1 WAN, 2 WAN, lỗi/mất/đảo fragment và giới hạn RAM.
- [ ] Chỉ bật jumbo sau capability negotiation và hoàn thành soak test.

## 2. Yêu cầu bất biến

1. Luồng MTU 1500 hiện tại phải tiếp tục hoạt động như trước.
2. Không tăng toàn bộ `NE_FRAME` lên 9216 hoặc 16384 một cách trực tiếp.
3. Application fragmentation và reassembly chỉ áp dụng cho UDP.
4. TCP tiếp tục dùng MSS clamp, không đi qua UDP fragment table hoặc UDP reorder table.
5. Packet UDP không vượt effective path MTU phải đi theo đường `FULL`, không vào bảng reassembly.
6. Packet logic lớn hơn 1500 được xử lý bằng packet-chain có sức chứa tối đa 4 XDP segments.
7. UDP TX WAN chỉ được tạo một packet `FULL` hoặc hai packet `FRAG0 + FRAG1`.
8. Nếu hai wire packet vẫn vượt MTU WAN thì cấu hình/path đó không hỗ trợ UDP jumbo 9000; phải
   drop có counter hoặc không bật jumbo trên path đó, tuyệt đối không phát frame vượt MTU.
9. Reorder chỉ xử lý một UDP datagram hoàn chỉnh sau khi reassembly thành công.
10. Không được chuyển các fragment nội bộ của NE ra cổng LAN cho client.
11. Mất một fragment chỉ được loại bỏ datagram đó sau timeout; không leak hoặc double-free UMEM.
12. Nếu kernel/NIC/libxdp không hỗ trợ multi-buffer thì phải fallback an toàn về MTU 1500,
    không được làm dịch vụ chết vì lỗi `EINVAL (-22)`.

## 3. Làm rõ hai loại "fragment"

Phải phân biệt hai cơ chế độc lập:

### 3.1. XDP multi-buffer (`xdp.frags`)

Một Ethernet jumbo frame là **một packet logic**, nhưng dữ liệu nằm trong tối đa 4 UMEM chunk và
tối đa 4 `xdp_desc`. Các descriptor nối tiếp dùng cờ `XDP_PKT_CONTD`.

Số 4 ở đây là sức chứa của representation nội bộ (`NE_PACKET_MAX_SEGS = 4`), không phải bốn packet
trên dây. Driver quyết định jumbo RX ban đầu được đặt vào bao nhiêu fragment. Không nên copy chỉ để
ép mọi packet lớn thành đúng bốn descriptor không rỗng; NE gom chúng thành một chain có tối đa bốn
slot và xử lý như một packet. Với chunk 4 KiB, frame khoảng 9 KiB thường dùng 3/4 slot.

Cơ chế này cho phép RX/TX một frame lớn hơn kích thước một UMEM chunk. Nó không tự giải quyết
việc frame mã hóa lớn hơn MTU của WAN.

### 3.2. UDP application fragmentation của NE

Khi một UDP datagram sau khi cộng overhead mã hóa lớn hơn MTU WAN đã chọn, NE được tạo tối đa hai
Ethernet wire packet độc lập: `FRAG0` và `FRAG1`. Mỗi wire packet có nonce/tag và fragment metadata
riêng. Phía nhận giải mã hai mảnh rồi dựng lại datagram gốc.

Luồng quyết định:

```text
LAN RX packet-chain
        |
        +-- TCP ----> MSS clamp ----> encrypt FULL ----> WAN
        |
        `-- UDP
             |
             +-- encrypted_wire_len <= selected_path_mtu
             |       `--> FULL, không application fragmentation
             |
             `-- encrypted_wire_len > selected_path_mtu
                     +--> chia thành FRAG0 + FRAG1 nếu cả hai vừa path MTU
                     `--> nếu hai mảnh vẫn không vừa: path không hỗ trợ, drop có counter

WAN RX UDP
        |
        +-- FULL ------> decrypt ------> UDP reorder ------> LAN TX
        |
        `-- FRAGMENT --> decrypt từng mảnh --> nhận đủ FRAG0 + FRAG1
                                           --> dựng packet-chain gốc
                                           --> UDP reorder một lần
                                           --> LAN TX
```

Nếu LAN egress không đủ MTU để phát packet gốc sau khi ráp, NE phải drop và tăng counter cấu hình
sai MTU. Không được "khỏi ráp" rồi đưa fragment nội bộ ra LAN vì client không hiểu wire format NE.

## 4. Bốn XDP segments nội bộ và tối đa hai wire packet

Đây là hai giới hạn khác nhau:

```text
Một jumbo packet logic
    = tối đa 4 XDP/UMEM segments trong NE
    = TX WAN dưới dạng 1 FULL hoặc 2 wire packet FRAG0/FRAG1
```

Kích thước hai wire fragment vẫn phải tính theo exact overhead:

```text
max_fragment_plain = selected_path_mtu
                   - ethernet_or_vlan_prefix
                   - NE wire header
                   - UDP fragment shim v2
                   - AEAD tag

two_frag_capacity = 2 * max_fragment_plain
```

Quyết định:

```text
encrypted FULL vừa path MTU       => phát 1 wire packet
FULL không vừa, plain <= capacity => phát 2 wire packet
hai fragment vẫn không vừa        => drop/disable jumbo trên path, không tạo mảnh thứ ba
```

Các phép cộng/trừ phải dùng checked arithmetic. Giới hạn:

- `NE_JUMBO_MAX_L3_MTU = 9000`.
- `NE_JUMBO_MAX_FRAME` phải cộng thêm Ethernet/VLAN theo định nghĩa MTU thực tế.
- `NE_PACKET_MAX_SEGS = 4` cho XDP packet-chain.
- `NE_UDP_WIRE_MAX_FRAGS = 2` cho UDP application fragmentation.
- Từ chối fragment có index/count sai, offset chồng lấn hoặc tổng length vượt jumbo max.

Lưu ý: WAN có MTU 9000 chưa chắc chở được nguyên packet IP 9000 sau khi NE thêm crypto overhead.
Điều kiện đúng là **encrypted wire length không vượt giới hạn frame của WAN**, không chỉ so sánh
plain packet với số 9000. Tuy nhiên hai mảnh khoảng một nửa packet sẽ vừa WAN 9000. Ngược lại,
UDP jumbo 9000 không thể đi qua WAN MTU 1500 nếu giới hạn wire output chỉ là hai packet; path đó
cần tối thiểu xấp xỉ nửa jumbo cộng overhead. Đây là giới hạn chủ động của thiết kế này.

## 5. Thiết kế packet-chain

`struct ne_packet` hiện có một `addr` và một `len`. Không nên nhét một mảng 4 segment trực tiếp
vào mọi phần tử ring vì các ring rất lớn. Thiết kế đề xuất:

```c
struct ne_packet {
    uint64_t addr;          /* fast path: địa chỉ segment đầu */
    uint32_t len;           /* tổng chiều dài packet logic */
    uint16_t chain_id;      /* NONE nếu packet một segment */
    uint8_t  seg_count;
    uint8_t  flags;
    uint8_t  dir;
    uint8_t  wan_idx;
    uint8_t  local_idx;
    uint8_t  tx_slot;
};

struct ne_packet_chain {
    uint64_t addr[NE_PACKET_MAX_SEGS];
    uint32_t len[NE_PACKET_MAX_SEGS];
    uint8_t  count;
    /* generation/refcount/state nếu cần */
};
```

Tên và layout cuối cùng có thể thay đổi sau benchmark, nhưng phải có các API ownership thống nhất:

```text
ne_packet_total_len()
ne_packet_segment_count()
ne_packet_segment_data()
ne_packet_copy_out(offset, length)
ne_packet_copy_in(offset, source, length)
ne_packet_alloc_chain(total_len)
ne_packet_release()             # giải phóng toàn bộ chain đúng một lần
ne_packet_tx_descriptors_needed()
```

Mọi đường drop/timeout/queue-full phải gọi `ne_packet_release()`, không gọi trực tiếp
`ne_frame_free(packet.addr)` khi packet có thể là chain.

Giữ fast path cho packet một segment để MTU 1500 không phải duyệt danh sách segment.

## 6. Phân tích RAM/UMEM

### 6.1. Hiện trạng

```text
NE_N_FRAMES = 1,048,576
NE_FRAME    = 2,048 byte
UMEM        = 1,048,576 * 2,048 = 2 GiB
pool addr   = 1,048,576 * 8     = 8 MiB
```

Nếu giữ nguyên số frame nhưng tăng chunk:

| Chunk | UMEM |
|---:|---:|
| 2 KiB | 2 GiB |
| 4 KiB | 4 GiB |
| 8 KiB | 8 GiB |
| 16 KiB | 16 GiB |

Do giới hạn packet-chain là 4 XDP segments, chunk 2 KiB hiện tại không chứa được worst-case frame
9 KiB (`4 * 2048 = 8192`). Phương án dự kiến là chunk 4 KiB và giảm `NE_N_FRAMES` còn 524,288 để
tổng UMEM vẫn khoảng 2 GiB. Một jumbo frame khoảng 9 KiB cần 3 segment 4 KiB; slot thứ tư là headroom
cho Ethernet/VLAN/driver layout. Phải xác nhận driver thực tế không trả về hơn 4 descriptors.

### 6.2. Chain metadata

Nếu một chain entry chứa 4 địa chỉ 64-bit và 4 length 32-bit, raw metadata khoảng 48 byte trước
padding. Với pool 65,536 chain đang hoạt động, RAM khoảng 3–4 MiB cộng freelist. Không cấp một
chain entry cho packet 1500; chỉ cấp khi `seg_count > 1`.

### 6.3. UDP reassembly hiện tại

`opt_entry` hiện chứa hai buffer 1600 byte. Kích thước thực tế xấp xỉ 3.2 KiB:

```text
4096 entries / table ~= 12.7 MiB
6 crypto workers cho một profile ~= 76 MiB
32 profiles x 6 workers ở worst case > 2.4 GiB
```

Các table được cấp lazy nhưng hai mảng inline vẫn không phù hợp với output jumbo. Không được đổi
chúng thành hai mảng 4500 byte cho mọi entry; payload phải cấp theo nhu cầu hoặc giữ UMEM ownership.

Thiết kế mới phải tách:

- Hash entry chỉ chứa metadata, bitmap, deadline và handle đến payload storage.
- Payload storage chỉ cấp cho datagram đang thực sự chờ mảnh.
- Đặt global/per-worker cap để reassembly không chiếm cạn UMEM.
- Ưu tiên giữ ownership của các UMEM frame nhận được thay vì copy payload vào mảng inline.

Budget ban đầu cần đo và cấu hình, ví dụ:

```text
active fragmented datagrams / worker = 1024
worst-case retained data             = 1024 * ~10 KiB = ~10 MiB/worker
6 workers                            = ~60 MiB payload retained
metadata                             = dưới vài MiB
```

Đây là upper bound cấu hình, không phải mục tiêu giữ đầy thường xuyên. Khi đạt cap, drop datagram
cũ nhất/hết hạn và tăng counter; không cấp RAM vô hạn.

### 6.4. UDP reorder hiện tại

Reorder table đang giữ `ne_packet` trong `dp_udp_reorder_item`. Sau khi `ne_packet` hỗ trợ chain,
reorder chỉ giữ handle/ownership của packet-chain, không copy 9 KiB payload vào reorder slot.

Trước khi merge phải in và ghi lại:

```text
sizeof(struct ne_packet)
sizeof(struct ne_packet_chain)
sizeof(struct udp_reorder_slot)
sizeof(struct udp_frag_entry_v2)
UMEM bytes
chain pool bytes
reassembly upper-bound bytes
```

## 7. Wire format UDP fragment v2

V1 hiện chỉ mã hóa `kind + epoch + seq + datagram_id` và chỉ hiểu `FRAG0/FRAG1/FULL`.
V2 cần tối thiểu:

```text
version
kind: FULL hoặc FRAGMENT
epoch
bond_seq
datagram_id
fragment_index
fragment_count
original_length
fragment_offset
fragment_plain_length
```

Yêu cầu:

- Metadata phải nằm trong phần được AEAD xác thực/mã hóa hoặc được dùng làm AAD.
- Mỗi wire fragment dùng nonce/tag riêng.
- Một UDP datagram chỉ có một `bond_seq`; mọi fragment mang cùng giá trị đó.
- Receiver giữ decoder v1 trong giai đoạn tương thích.
- Sender chỉ phát v2 jumbo sau khi xác nhận peer hỗ trợ.
- Không trộn fragment v1 và v2 trong cùng datagram.
- Key epoch là một phần của khóa reassembly để key rotation không ghép nhầm dữ liệu.

## 8. MTU và lựa chọn WAN

Hiện `resolve_runtime_frag_mtu()` lấy min MTU toàn bộ WAN và bắt đầu từ 1500, nên không thể mở
rộng trên 1500. Thiết kế mới cần lưu:

```text
LAN MTU theo từng local interface
WAN MTU theo từng dataplane WAN
wire overhead theo crypto option/protocol/VLAN
effective plaintext MTU theo từng WAN
khả năng multi-buffer theo từng interface
```

Phase đầu nên tính fragment theo MTU nhỏ nhất của tất cả WAN đang tham gia bond. Đây là phương án
an toàn khi scheduler có thể đưa fragment lên bất kỳ WAN nào. Phase tối ưu sau mới cho scheduler
chọn WAN trước rồi fragment theo MTU WAN đó.

Không dùng `CRYPTO_OPT_FRAG_MTU_DEFAULT` hard-code trong MSS clamp. TCP MSS cap phải dùng effective
MTU của bond/WAN và crypto overhead thực tế.

## 9. Các file cần sửa

### 9.1. XDP/BPF và build

| File | Thay đổi dự kiến |
|---|---|
| `bpf/lan.c` | Tạo chương trình jumbo `SEC("xdp.frags")`; bỏ hard-drop 1500 trong jumbo mode; chỉ đọc header trong linear first fragment. Giữ program legacy. |
| `bpf/wan.c` | Tạo chương trình jumbo `SEC("xdp.frags")`; giữ redirect marker và CFM; giữ program legacy. |
| `Makefile` | Build object legacy và jumbo riêng, ví dụ `lan.o/wan.o` và `lan_frags.o/wan_frags.o`; thêm test mới. |
| `src/core/iface/profile_xdp.c` | Chọn object/program legacy hoặc frags theo capability; fallback có log rõ; không attach frags mù quáng. |
| `inc/core/iface/profile_iface_xdp.h` | Khai báo API chọn mode/capability nếu cần. |

### 9.2. UMEM, RX/TX và ownership

| File | Thay đổi dự kiến |
|---|---|
| `inc/core/iface/interface.h` | Thêm packet-chain, flags, max segments, capability/mode; khai báo API release/copy/segment. |
| `src/core/iface/xdp_interface.c` | Bind `XDP_USE_SG` trong jumbo mode; RX gom descriptor đến khi hết `XDP_PKT_CONTD`; TX reserve N descriptor và set continuation; CQ/FQ/reclaim xử lý mọi segment; validate chain. |
| `src/core/dataplane/packet_util.c` | Ring/drop dùng `ne_packet_release`; không giới hạn `pkt->len` bằng một `frame_size`; cung cấp helper chuyển ownership. |
| `inc/core/dataplane/dataplane_util.h` | Khai báo helper packet-chain cần dùng xuyên dataplane. |
| `inc/core/forwarder/forwarder.h` | Thay `split_tail_cache` cố định một tail bằng batch/cache có thể cấp N output fragments; thêm runtime MTU/capability state. |
| `src/core/forwarder/forwarder.c` | Probe MTU/capability; tính runtime path MTU; log mode; cleanup toàn bộ chain pool. |

Nên tạo module mới thay vì dồn thêm vào `xdp_interface.c`:

```text
inc/core/iface/packet_chain.h
src/core/iface/packet_chain.c
```

### 9.3. Crypto fragmentation/reassembly

| File | Thay đổi dự kiến |
|---|---|
| `inc/crypto/crypto_option.h` | Giữ mô hình FULL hoặc hai output nhưng đổi API để input/output là packet-chain; truyền selected path MTU; reassembly trả về packet-chain/handle thay vì buffer `NE_FRAME`. |
| `src/crypto/common/crypto_option_router.c` | Bỏ clamp logical MTU vào `NE_FRAME`; route API chain-aware; phân biệt logical max MTU và wire path MTU. |
| `src/crypto/pqc/pqc_l2_option.c` | Implement shim v2 chain-aware, reassembly hai mảnh output jumbo, validation, timeout, v1 compatibility; bỏ `first[1600]/second[1600]` khỏi hot table. |
| `src/crypto/options/common/opt_no_frag_ops.c` | Cập nhật signature API mới; bypass/no-frag không tạo chain thừa. |
| `src/crypto/options/common/opt_no_frag_ops.h` | Cập nhật macro ops/signature. |
| `src/crypto/options/bypass.c` | Cập nhật ownership/signature nếu interface chung thay đổi. |
| `inc/crypto/packet_crypto.h` | Chỉ sửa nếu crypto context cần scatter/gather cursor hoặc AAD v2. |
| `src/crypto/common/packet_crypto.c` | Thêm helper encrypt/decrypt theo vùng packet-chain nếu không xử lý ở option layer. |
| `inc/crypto/eth_parse.h` | Thêm parser đọc qua packet-chain hoặc parser cho prefix đã linearize. |
| `src/crypto/common/eth_parse.c` | MSS/path MTU theo runtime; parser chain-safe. |

Khuyến nghị tách reassembly ra module riêng để `pqc_l2_option.c` không tiếp tục phình:

```text
inc/core/dataplane/udp_frag.h
src/core/dataplane/udp_frag.c
```

### 9.4. Dataplane

| File | Thay đổi dự kiến |
|---|---|
| `src/core/dataplane/local_egress.c` | UDP: chọn FULL hoặc emit đúng hai fragments. Reserve tài nguyên trước khi enqueue để tránh đã gửi frag đầu nhưng thiếu frag sau. TCP: chỉ MSS clamp. |
| `src/core/dataplane/wan_ingress.c` | Xóa stack buffer `wire_buf[NE_FRAME]` cho jumbo; decrypt/reassemble chain; chỉ submit UDP reorder sau full reassembly; mọi drop giải phóng chain. |
| `inc/core/dataplane/udp_reorder.h` | Giữ reorder UDP-only; item sở hữu packet-chain handle. |
| `src/core/dataplane/udp_reorder.c` | Không copy jumbo payload; drop/emit gọi unified release; không thay đổi thuật toán reorder nếu chưa có benchmark yêu cầu. |
| `src/core/dataplane/arp_bridge.c` | Audit `scratch[NE_FRAME]`; ARP vẫn nhỏ nhưng ownership API phải đúng. Không đưa ARP vào UDP fragmentation. |
| `src/core/dataplane/crypto_route.c` | Audit hash/worker routing để mọi fragment cùng datagram về cùng crypto worker. |
| `src/core/forwarder/wan_scheduler.c` | Đảm bảo lựa chọn WAN và path MTU nhất quán; không đổi WAN sau khi đã tính layout fragment nếu dùng per-WAN MTU. |

### 9.5. Cấu hình và service

| File | Thay đổi dự kiến |
|---|---|
| `inc/core/util/config.h` | Thêm jumbo mode/capability/runtime MTU fields hoặc cấu trúc riêng. |
| `src/db/db_config.c` | Đọc default object legacy/jumbo và jumbo mode nếu cấu hình từ DB/env. |
| `main.c` | Validate config; reload phải từ chối thay mode cần rebuild UMEM nếu không restart dataplane an toàn. |
| `systemd/network-encryptor.service` | Chỉ thêm `NE_JUMBO_MODE=off/auto/on` sau khi code hoàn chỉnh; mặc định rollout đầu là `off`. |

## 10. API FULL hoặc split hai mảnh đề xuất

API hiện tại nhận buffer liên tục `frag0` và `frag1`; cần đổi thành API packet-chain để đọc được
jumbo input và tạo tối đa hai wire packet:

```c
struct crypto_fragment_sink {
    void *ctx;
    int (*reserve)(void *ctx, uint16_t count); /* count chỉ là 1 hoặc 2 */
    int (*emit)(void *ctx, struct ne_packet *fragment,
                uint16_t index, uint16_t count);
    void (*abort)(void *ctx);
};

int crypto_option_emit_udp(...,
                           const struct ne_packet *plain,
                           uint32_t selected_path_mtu,
                           struct crypto_fragment_sink *sink);
```

Quy tắc atomicity:

1. Tính trước kết quả là FULL, SPLIT2 hoặc UNSUPPORTED.
2. Kiểm tra TX ring còn chỗ cho một hoặc hai wire packet.
3. Cấp đủ segment cho toàn bộ output trước khi sửa packet gốc.
4. Nếu bất kỳ bước mã hóa nào lỗi, giải phóng toàn bộ output và chưa enqueue mảnh nào.
5. Chỉ enqueue sau khi cả datagram đã được tạo thành công.

Điều này sửa rủi ro hiện tại: frag đầu có thể đã vào ring nhưng frag tail enqueue thất bại.

## 11. Các phase triển khai

### Phase 0 — Chốt baseline 1500

- Build và chạy unit test hiện tại.
- Lưu throughput, pps, CPU, drop, reorder cho 1 WAN và 2 WAN.
- Test packet sizes quanh biên 1500.
- Thêm counters ownership: allocated/free/in-flight.
- Không sửa wire format trong phase này.

Điều kiện qua phase: có kết quả baseline đủ để phát hiện regression.

### Phase 1 — Nền tảng cho `xdp.frags`: packet-chain nhưng vẫn chạy legacy 1500

- Thêm abstraction packet-chain và unified release.
- Chuyển toàn bộ 144 vị trí tham chiếu `ne_packet/addr/len` qua helper khi ownership có thể đổi.
- `seg_count == 1` vẫn đi fast path như cũ.
- Chưa bật `XDP_USE_SG`, chưa đổi wire format.

Packet-chain là bước con đầu tiên bắt buộc của hạng mục `xdp.frags`: nếu đổi section BPF trước mà
userspace vẫn coi mỗi descriptor là một packet thì jumbo frame sẽ bị tách sai thành nhiều packet.

Điều kiện qua phase: test MTU 1500 cho kết quả chức năng như baseline, không leak, hiệu năng giảm không
quá ngưỡng đã thống nhất (đề xuất tối đa 1–2%).

### Phase 2 — XDP/AF_XDP multi-buffer pass-through

- Build/load `xdp.frags` object riêng.
- Thêm capability probe và `XDP_USE_SG` khi tạo XSK.
- Implement RX/TX descriptor chain.
- Test jumbo plain/bypass trước, chưa tích hợp crypto fragmentation.
- Fallback legacy nếu probe hoặc bind thất bại.

Điều kiện qua phase: packet jumbo bypass đi qua byte-for-byte; MTU 1500 vẫn dùng legacy path.

### Phase 3 — UDP FULL/SPLIT2 chain-aware

- Định nghĩa shim v2 và decoder validation.
- Giữ tối đa hai wire fragments nhưng thay API để nhận jumbo packet-chain.
- Tính exact capacity của FULL và SPLIT2 theo selected path MTU và crypto overhead.
- Nếu SPLIT2 không đủ thì đánh dấu path không hỗ trợ UDP jumbo đó; không sinh mảnh thứ ba.
- Preallocate/reserve cả datagram trước enqueue.
- TCP, ARP, ICMP, OSPF không đi vào API này.

Điều kiện qua phase: mọi wire fragment đều <= path MTU và decrypt độc lập được.

### Phase 4 — UDP reassembly hai mảnh thành jumbo packet-chain

- Metadata table hai-bit + bounded payload/UMEM ownership.
- Xử lý đảo FRAG0/FRAG1, duplicate, missing fragment, timeout và key epoch.
- Tạo lại một logical packet-chain gốc.
- Submit đúng một item vào UDP reorder.

Điều kiện qua phase: packet sau ráp giống byte-for-byte packet trước chia; không leak sau fault test.

### Phase 5 — TCP MSS và per-WAN MTU

- MSS clamp dùng effective path MTU thực tế thay vì hard-code 1500.
- Scheduler và fragmenter thống nhất WAN/path MTU.
- Ban đầu dùng min MTU trong bonded set; chỉ tối ưu per-WAN sau khi ổn định.

Điều kiện qua phase: TCP không application-fragment, không vào reorder, iperf TCP ổn định.

### Phase 6 — Negotiation và rollout

- Hai NE trao đổi capability wire v2/jumbo trước khi sử dụng.
- Mixed version mặc định giữ v1/1500.
- Thêm `off/auto/on`, mặc định production đầu tiên là `off`.
- Log startup một lần: kernel, driver, MTU từng interface, XDP mode, SG capability, chunk size,
  max segments, estimated RAM và selected wire version.

## 12. Kế hoạch kiểm thử

### 12.1. Unit test

- Quyết định FULL/SPLIT2/UNSUPPORTED ở nhiều path MTU.
- Packet sizes: 64, 1472, đúng boundary FULL, boundary+1, 2048, 4096, 8996, 9000.
- Ethernet thường và VLAN.
- Fragment đến đúng thứ tự, đảo hoàn toàn, mất giữa, duplicate, index/count giả, offset overlap.
- Timeout và table pressure.
- Wrap `datagram_id`, `bond_seq`, đổi epoch/key khi fragment đang bay.
- Packet-chain allocate/release và CQ reclaim.

### 12.2. Integration test

- Kernel/NIC không hỗ trợ SG: dịch vụ chạy legacy 1500, không lỗi 22.
- Kernel/NIC hỗ trợ SG: jumbo RX và TX qua từng interface.
- LAN 9000 / WAN 1500: xác nhận báo unsupported/drop có counter vì hai fragment không thể vừa.
- LAN 9000 / WAN đủ chứa hai nửa: UDP split hai wire packet và ráp lại.
- LAN 9000 / WAN đủ wire MTU: UDP FULL, không reassembly.
- LAN 1500 / WAN 1500: kết quả giống baseline.
- 1 WAN và 2 WAN bằng latency.
- 2 WAN lệch latency, fragment đảo thứ tự mạnh.
- Queue full giữa quá trình tạo hai fragment: không gửi datagram dở dang.
- Restart/reload/teardown khi còn chain và reassembly entry.

### 12.3. Soak/performance

- UDP iperf tối thiểu vài giờ ở packet size hỗn hợp.
- Theo dõi UMEM free count, active chains, reassembly occupancy/timeouts, invalid descriptors,
  RX drop, TX no-free và CPU từng worker.
- So sánh MTU 1500 trước/sau thay đổi.
- Dùng ASan/UBSan cho unit test userspace; fault injection cho allocation và enqueue.

## 13. Tiêu chí hoàn thành

- Không có regression chức năng MTU 1500.
- MTU 1500 không bị ép đi qua chain slow path hoặc reassembly table.
- Không có wire frame vượt MTU của WAN được chọn.
- UDP 9000 qua WAN đủ capacity SPLIT2 được chia hai wire packet và phục hồi chính xác.
- UDP 9000 qua WAN 1500 bị từ chối rõ ràng; không phát frame quá MTU hoặc datagram dở dang.
- UDP dưới effective path MTU phát FULL và không chờ reassembly.
- TCP chỉ dùng MSS clamp, không dùng UDP fragment/reorder.
- Reorder nhận đúng một packet cho mỗi UDP datagram gốc.
- Không leak/double-free khi mất mảnh, timeout, queue full, reload hoặc shutdown.
- RAM có hard limit và không tăng theo traffic vô hạn.
- Unsupported kernel/driver fallback về legacy thay vì báo lỗi 22.
- Hai phiên bản NE không tương thích jumbo không tự phát v2 cho nhau.

## 14. Những việc không được làm

- Không chỉ đổi `SEC("xdp")` thành `SEC("xdp.frags")` rồi coi là hoàn thành.
- Không chỉ thêm `XDP_USE_SG` mà bỏ qua RX/TX descriptor chaining.
- Không tăng `NE_FRAME` lên 9000/16384 với `NE_N_FRAMES` giữ nguyên.
- Không nhầm bốn XDP segments nội bộ thành bốn wire packet.
- Không ép RX copy dữ liệu chỉ để mọi jumbo packet luôn có đúng bốn descriptor không rỗng.
- Không tạo mảng payload jumbo inline cho mọi reassembly slot.
- Không reassemble từng fragment vào một stack buffer 9 KiB trên hot path.
- Không đưa TCP vào application fragment/reassembly hoặc UDP reorder.
- Không đưa fragment wire nội bộ ra LAN khi LAN MTU không đủ.
- Không xóa decoder v1 trước khi có cơ chế capability/rolling upgrade.

## 15. Trình tự cho AI ở lần làm việc sau

1. Đọc toàn bộ tài liệu này.
2. Chạy `git status` và xác định commit mới nhất; không giả định baseline vẫn là `3254f03`.
3. Đọc lại toàn bộ các file trong mục 9 vì code có thể đã thay đổi.
4. Kiểm tra header kernel/libxdp đang build có `XDP_USE_SG` và `XDP_PKT_CONTD`.
5. Kiểm tra support thực tế của kernel, driver và NIC trên máy test; không suy luận chỉ từ version.
6. Đo `sizeof` và RAM thật trước khi chốt cấu trúc.
7. Chỉ triển khai một phase mỗi lần; build/test/commit riêng cho từng phase.
8. Không bật jumbo mặc định trước khi toàn bộ tiêu chí phase 0–6 đạt.
