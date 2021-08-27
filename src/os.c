#include "os.h"
#include "vpn.h"

ssize_t safe_read_partial(const int fd, void *const buf_, const size_t max_count)
{
    unsigned char *const buf = (unsigned char *) buf_;
    ssize_t              readnb;

    while ((readnb = read(fd, buf, max_count)) < (ssize_t) 0 && errno == EINTR &&
           !exit_signal_received)
        ;
    return readnb;
}

ssize_t safe_write_partial(const int fd, void *const buf_, const size_t max_count)
{
    unsigned char *const buf = (unsigned char *) buf_;
    ssize_t              writenb;

    while ((writenb = write(fd, buf, max_count)) < (ssize_t) 0 && errno == EINTR &&
           !exit_signal_received)
        ;
    return writenb;
}

#ifdef __linux__
int tun_create(char if_name[IFNAMSIZ], const char *wanted_name)
{
    struct ifreq ifr;
    int          fd;
    int          err;

    fd = open("/dev/net/tun", O_RDWR);
    if (fd == -1) {
        fprintf(stderr, "tun module not present. See https://sk.tl/2RdReigK\n");
        return -1;
    }
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", wanted_name == NULL ? "" : wanted_name);
    if (ioctl(fd, TUNSETIFF, &ifr) != 0) {
        err = errno;
        (void) close(fd);
        errno = err;
        return -1;
    }
    snprintf(if_name, IFNAMSIZ, "%s", ifr.ifr_name);

    return fd;
}
#elif defined(__APPLE__)
static int tun_create_by_id(char if_name[IFNAMSIZ], unsigned int id)
{
    struct ctl_info     ci;
    struct sockaddr_ctl sc;
    int                 err;
    int                 fd;

    if ((fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)) == -1) {
        return -1;
    }
    memset(&ci, 0, sizeof ci);
    snprintf(ci.ctl_name, sizeof ci.ctl_name, "%s", UTUN_CONTROL_NAME);
    if (ioctl(fd, CTLIOCGINFO, &ci)) {
        err = errno;
        (void) close(fd);
        errno = err;
        return -1;
    }
    memset(&sc, 0, sizeof sc);
    sc = (struct sockaddr_ctl){
        .sc_id      = ci.ctl_id,
        .sc_len     = sizeof sc,
        .sc_family  = AF_SYSTEM,
        .ss_sysaddr = AF_SYS_CONTROL,
        .sc_unit    = id + 1,
    };
    if (connect(fd, (struct sockaddr *) &sc, sizeof sc) != 0) {
        err = errno;
        (void) close(fd);
        errno = err;
        return -1;
    }
    snprintf(if_name, IFNAMSIZ, "utun%u", id);

    return fd;
}
