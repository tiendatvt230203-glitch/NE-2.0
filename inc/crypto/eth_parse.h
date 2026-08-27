#ifndef ETH_PARSE_H
#define ETH_PARSE_H

#include <stddef.h>
#include <stdint.h>

#define ETH_L2_HDR_MAX  18
#define ETH_HEADER_SIZE 14
#define NE_L2_FAKE_ETHERTYPE      0x104Au
/* Encrypted ARP L2 wire (IANA 823E–8240: Advanced Encryption Systems, Inc.). */
#define NE_L2_FAKE_ETHERTYPE_ARP  0x1048u

#define CRYPTO_L2_POLICY_OFF     ETH_HEADER_SIZE
#define CRYPTO_L2_POLICY_LEN     1
#define CRYPTO_L2_CORE_ID_OFF    (CRYPTO_L2_POLICY_OFF + CRYPTO_L2_POLICY_LEN)
#define CRYPTO_L2_CORE_ID_LEN    1
#define CRYPTO_L2_NONCE_OFF      (CRYPTO_L2_CORE_ID_OFF + CRYPTO_L2_CORE_ID_LEN)

/** Vị trí byte bắt đầu của IPv4 (0x45): Trả về vị trí (ví dụ: 14, 18), -1 = Lỗi */
int crypto_eth_ipv4_offset(const uint8_t *pkt, size_t pkt_len);
/** Trả về độ dài tiền tố L2: 12 = Thường, 16 = VLAN, -1=Lỗi */
int crypto_eth_inner_et_off(const uint8_t *pkt, size_t pkt_len);
/** Độ dài của tiền tố trước EthenetType nếu là gói bình thường sẽ là 14B gói Vlan là 16B */
int crypto_eth_l2_prefix_len(const uint8_t *pkt, size_t pkt_len);
/** Check xem gói tin có phải IPv4 không: 1 = Đúng (True), 0 = Sai (False) */
int crypto_pkt_is_ipv4(const uint8_t *pkt, size_t pkt_len);
/** Ghi đè mã EtherType chuẩn của IPv4 (0x0800) vào vị trí chỉ định sau khi giải mã xong*/
void crypto_eth_set_ipv4_et(uint8_t *pkt, int inner_et_off);

/** L2 IP encrypt marker (0x88B5) — not ARP. */
int crypto_eth_l2_has_marker(const uint8_t *pkt, size_t pkt_len);
/** L2 ARP encrypt marker (0x823E). */
int crypto_eth_l2_has_arp_marker(const uint8_t *pkt, size_t pkt_len);
int crypto_eth_l2_policy_off(const uint8_t *packet, size_t pkt_len);
int crypto_eth_l2_read_policy_id(const uint8_t *packet, uint32_t pkt_len, uint8_t *policy_id_out);
int crypto_eth_l2_core_id_off(const uint8_t *packet, size_t pkt_len);
int crypto_eth_l2_frag_magic_off(const uint8_t *packet, size_t pkt_len, int nonce_size);
int crypto_eth_l2_read_worker_idx(const uint8_t *packet, uint32_t pkt_len, uint8_t *worker_idx_out);

int crypto_eth_arp_offset(const uint8_t *pkt, size_t pkt_len);
int crypto_pkt_is_arp(const uint8_t *pkt, size_t pkt_len);
void crypto_eth_set_arp_et(uint8_t *pkt, int inner_et_off);

int crypto_tcp_clamp_mss(uint8_t *pkt, uint32_t pkt_len, uint32_t path_mtu, uint32_t wire_overhead);

#endif