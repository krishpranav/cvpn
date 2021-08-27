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

static int tcp_listener(const char *address, const char *port)
{
    struct addrinfo hints, *res;
    int             eai, err;
    int             listen_fd;
    int             backlog = 1;

    memset(&hints, 0, sizeof hints);
    hints.ai_flags    = AI_PASSIVE;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_addr     = NULL;
#if defined(__OpenBSD__) || defined(__DragonFly__)
    if (address == NULL) {
        hints.ai_family = AF_INET;
    }
#endif
    if ((eai = getaddrinfo(address, port, &hints, &res)) != 0 ||
        (res->ai_family != AF_INET && res->ai_family != AF_INET6)) {
        fprintf(stderr, "Unable to create the listening socket: [%s]\n", gai_strerror(eai));
        errno = EINVAL;
        return -1;
    }
    if ((listen_fd = socket(res->ai_family, SOCK_STREAM, IPPROTO_TCP)) == -1 ||
        setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (char *) (int[]){ 1 }, sizeof(int)) != 0) {
        err = errno;
        (void) close(listen_fd);
        freeaddrinfo(res);
        errno = err;
        return -1;
    }
#if defined(IPPROTO_IPV6) && defined(IPV6_V6ONLY)
    (void) setsockopt(listen_fd, IPPROTO_IPV6, IPV6_V6ONLY, (char *) (int[]){ 0 }, sizeof(int));
#endif
#ifdef TCP_DEFER_ACCEPT
    (void) setsockopt(listen_fd, SOL_TCP, TCP_DEFER_ACCEPT,
                      (char *) (int[]){ ACCEPT_TIMEOUT / 1000 }, sizeof(int));
#endif
    printf("Listening to %s:%s\n", address == NULL ? "*" : address, port);
    if (bind(listen_fd, (struct sockaddr *) res->ai_addr, (socklen_t) res->ai_addrlen) != 0 ||
        listen(listen_fd, backlog) != 0) {
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);

    return listen_fd;
}

static void client_disconnect(Context *context)
{
    if (context->client_fd == -1) {
        return;
    }
    (void) close(context->client_fd);
    context->client_fd          = -1;
    context->fds[POLLFD_CLIENT] = (struct pollfd){ .fd = -1, .events = 0 };
    memset(context->uc_st, 0, sizeof context->uc_st);
}

static int server_key_exchange(Context *context, const int client_fd)
{
    uint32_t st[12];
    uint8_t  pkt1[32 + 8 + 32], pkt2[32 + 32];
    uint8_t  h[32];
    uint8_t  k[32];
    uint8_t  iv[16] = { 0 };
    uint64_t ts, now;

    memcpy(st, context->uc_kx_st, sizeof st);
    errno = EACCES;
    if (safe_read(client_fd, pkt1, sizeof pkt1, ACCEPT_TIMEOUT) != sizeof pkt1) {
        return -1;
    }
    uc_hash(st, h, pkt1, 32 + 8);
    if (memcmp(h, pkt1 + 32 + 8, 32) != 0) {
        return -1;
    }
    memcpy(&ts, pkt1 + 32, 8);
    ts  = endian_swap64(ts);
    now = time(NULL);
    if ((ts > now && ts - now > TS_TOLERANCE) || (now > ts && now - ts > TS_TOLERANCE)) {
        fprintf(stderr,
                "Clock difference is too large: %" PRIu64 " (client) vs %" PRIu64 " (server)\n", ts,
                now);
        return -1;
    }
    uc_randombytes_buf(pkt2, 32);
    uc_hash(st, pkt2 + 32, pkt2, 32);
    if (safe_write_partial(client_fd, pkt2, sizeof pkt2) != sizeof pkt2) {
        return -1;
    }
    uc_hash(st, k, NULL, 0);
    iv[0] = context->is_server;
    uc_state_init(context->uc_st[0], k, iv);
    iv[0] ^= 1;
    uc_state_init(context->uc_st[1], k, iv);

    return 0;
}

static int tcp_accept(Context *context, int listen_fd)
{
    char                    client_ip[NI_MAXHOST] = { 0 };
    struct sockaddr_storage client_ss;
    socklen_t               client_ss_len = sizeof client_ss;
    int                     client_fd;
    int                     err;

    if ((client_fd = accept(listen_fd, (struct sockaddr *) &client_ss, &client_ss_len)) < 0) {
        return -1;
    }
    if (client_ss_len <= (socklen_t) 0U) {
        (void) close(client_fd);
        errno = EINTR;
        return -1;
    }
    if (tcp_opts(client_fd) != 0) {
        err = errno;
        (void) close(client_fd);
        errno = err;
        return -1;
    }
    getnameinfo((const struct sockaddr *) (const void *) &client_ss, client_ss_len, client_ip,
                sizeof client_ip, NULL, 0, NI_NUMERICHOST | NI_NUMERICSERV);
    printf("Connection attempt from [%s]\n", client_ip);
    context->congestion = 0;
    fcntl(client_fd, F_SETFL, fcntl(client_fd, F_GETFL, 0) | O_NONBLOCK);
    if (context->client_fd != -1 &&
        memcmp(context->client_ip, client_ip, sizeof context->client_ip) != 0) {
        fprintf(stderr, "Closing: a session from [%s] is already active\n", context->client_ip);
        (void) close(client_fd);
        errno = EBUSY;
        return -1;
    }
    if (server_key_exchange(context, client_fd) != 0) {
        fprintf(stderr, "Authentication failed\n");
        (void) close(client_fd);
        errno = EACCES;
        return -1;
    }
    memcpy(context->client_ip, client_ip, sizeof context->client_ip);
    return client_fd;
}
