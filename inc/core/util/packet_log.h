#ifndef NE_PACKET_LOG_H
#define NE_PACKET_LOG_H

#define NE_PACKET_LOG_DEFAULT_PATH "/var/log/NE/packet.log"

/*
 * Redirect daemon stdout/stderr to one append-only file. The path can be
 * overridden with NE_PACKET_LOG_PATH (it must be an absolute path).
 */
int ne_packet_log_redirect(void);
const char *ne_packet_log_path(void);

#endif
