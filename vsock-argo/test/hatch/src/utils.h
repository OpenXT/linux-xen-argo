#ifndef _UTILS_H_
# define _UTILS_H_

# include "project.h"

/*
 * Socket helpers.
 */
static inline int __vsock_dgram(void)
{
    int s;

    s = socket(AF_VSOCK, SOCK_DGRAM, 0);
    if (s < 0) {
        perror("socket");
        exit(errno);
    }

    return s;
}

static inline int __vsock_bdgram(struct sockaddr_vm *sa)
{
    int s;

    s = __vsock_dgram();
    if (bind(s, (struct sockaddr *)sa, sizeof (*sa))) {
        perror("bind");
        exit(errno);
    }

    return s;
}

/*
 * Sanity checks.
 */
static inline int is_valid_port(unsigned long port)
{
    return (port > 0) && (port < 65536);
}

/*
 * Parsing helpers.
 */
static inline int parse_uint(const char *nptr, unsigned int *ui)
{
    char *end;
    unsigned long ul;

    assert(nptr != NULL);
    assert(ui != NULL);

    ul = strtoul(nptr, &end, 0);
    if (end == nptr)
        return -EINVAL;

    if (ul >= UINT_MAX)
        return -ERANGE;

    *ui = ul;

    return 0;
}

static inline int parse_domid(const char *nptr, unsigned int *domid)
{
    int rc;

    assert(nptr != NULL);
    assert(domid != NULL);

    rc = parse_uint(nptr, domid);
    if (rc < 0)
        return rc;

    if (*domid >= VMADDR_CID_ANY)
        return -ERANGE;

    return 0;
}

#endif /* !_UTILS_H_ */

