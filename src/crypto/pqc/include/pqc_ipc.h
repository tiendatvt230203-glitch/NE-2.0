#ifndef PQC_IPC_H
#define PQC_IPC_H

// IPC - Inter-Process Communication
int sig_pqc_handle_ipc_cli(int argc, char **argv);
void sig_pqc_start_ipc_server(void);
void sig_pqc_cleanup_ipc(void);
void sig_pqc_handle_gen_identity(void);

#endif // PQC_IPC_H