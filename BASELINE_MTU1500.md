# Mốc MTU 1500

Nhánh `baseline/mtu1500` lưu bản dự án 1500 được người dùng đưa lại vào
workspace, để tối ưu riêng trước khi tiếp tục jumbo. Nhánh main không bị sửa lịch sử.

- XDP thường (`SEC("xdp")`), một frame UMEM 2048 byte cho mỗi gói.
- LAN giới hạn MTU 1500; ngân sách crypto runtime không vượt 1500.
- Giữ DB, policy, PQC handshake, đa core, scheduler và UDP reorder/tách ráp
  của bản 1500 được cung cấp. Chưa tối ưu hay xác nhận lại các chức năng này.
- Không dùng đường multi-buffer/xdp.frags của bản 9000.
- Thư viện runtime được lưu cùng baseline; object và executable build không commit.

Build: `make -j4`. Makefile theo dõi dependency header để thay đổi header được
biên dịch lại. Cần test thực tế LAN/WAN MTU 1500 trước khi coi đây là bản ổn định.

Kiểm tra khi tạo baseline: các file C/BPF biên dịch được, còn warning ở code
được nhập lại. Link chưa thành công trên máy phát triển vì `libpq.so.5.14`
đi kèm yêu cầu `libldap-2.5.so.0` đang thiếu. Cần dependency đúng ABI trên máy
build/deploy; không thay symlink sang một bản LDAP khác ABI.
