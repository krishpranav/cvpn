#include "vpn.h"
#include "charm.h"
#include "os.h"

static const int POLLFD_TUN = 0, POLLFD_LISTENER = 1, POLLFD_CLIENT = 2, POLLFD_COUNT = 3;

typedef struct __attribute__((aligned(16))) Buf_ {
#if TAG_LEN < 16 - 2
    unsigned char _pad[16 - TAG_LEN - 2];
#endif
    unsigned char len[2];
    unsigned char tag[TAG_LEN];
    unsigned char data[MAX_PACKET_LEN];
    size_t        pos;
} Buf;

typedef struct Context_ {
    const char *  wanted_if_name;
    const char *  local_tun_ip;
    const char *  remote_tun_ip;
    const char *  local_tun_ip6;
    const char *  remote_tun_ip6;
    const char *  server_ip_or_name;
    const char *  server_port;
    const char *  ext_if_name;
    const char *  wanted_ext_gw_ip;
    char          client_ip[NI_MAXHOST];
    char          ext_gw_ip[64];
    char          server_ip[64];
    char          if_name[IFNAMSIZ];
    int           is_server;
    int           tun_fd;
    int           client_fd;
    int           listen_fd;
    int           congestion;
    int           firewall_rules_set;
    Buf           client_buf;
    struct pollfd fds[3];
    uint32_t      uc_kx_st[12];
    uint32_t      uc_st[2][12];
} Context;

volatile sig_atomic_t exit_signal_received;

static void signal_handler(int sig)
{
    signal(sig, SIG_DFL);
    exit_signal_received = 1;
}

static int firewall_rules(Context *context, int set, int silent)
{
    const char *       substs[][2] = { { "$LOCAL_TUN_IP6", context->local_tun_ip6 },
                                { "$REMOTE_TUN_IP6", context->remote_tun_ip6 },
                                { "$LOCAL_TUN_IP", context->local_tun_ip },
                                { "$REMOTE_TUN_IP", context->remote_tun_ip },
                                { "$EXT_IP", context->server_ip },
                                { "$EXT_PORT", context->server_port },
                                { "$EXT_IF_NAME", context->ext_if_name },
                                { "$EXT_GW_IP", context->ext_gw_ip },
                                { "$IF_NAME", context->if_name },
                                { NULL, NULL } };
    const char *const *cmds;
    size_t             i;

    if (context->firewall_rules_set == set) {
        return 0;
    }
    if ((cmds = (set ? firewall_rules_cmds(context->is_server).set
                     : firewall_rules_cmds(context->is_server).unset)) == NULL) {
        fprintf(stderr,
                "Routing commands for that operating system have not been "
                "added yet.\n");
        return 0;
    }
    for (i = 0; cmds[i] != NULL; i++) {
        if (shell_cmd(substs, cmds[i], silent) != 0) {
            fprintf(stderr, "Unable to run [%s]: [%s]\n", cmds[i], strerror(errno));
            return -1;
        }
    }
    context->firewall_rules_set = set;
    return 0;
}

static int tcp_client(const char *address, const char *port)
{
    struct addrinfo hints, *res;
    int             eai;
    int             client_fd;
    int             err;

    printf("Connecting to %s:%s...\n", address, port);
    memset(&hints, 0, sizeof hints);
    hints.ai_flags    = 0;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_addr     = NULL;
    if ((eai = getaddrinfo(address, port, &hints, &res)) != 0 ||
        (res->ai_family != AF_INET && res->ai_family != AF_INET6)) {
        fprintf(stderr, "Unable to create the client socket: [%s]\n", gai_strerror(eai));
        errno = EINVAL;
        return -1;
    }
    if ((client_fd = socket(res->ai_family, SOCK_STREAM, IPPROTO_TCP)) == -1 ||
        tcp_opts(client_fd) != 0 ||
        connect(client_fd, (const struct sockaddr *) res->ai_addr, res->ai_addrlen) != 0) {
        freeaddrinfo(res);
        err = errno;
        (void) close(client_fd);
        errno = err;
        return -1;
    }
    freeaddrinfo(res);
    return client_fd;
}

