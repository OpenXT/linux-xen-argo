#include "project.h"

/*
 * Parameter agregation.
 */
struct hatch_args {
    int recv;
    unsigned int local_port;
    unsigned int port;
    unsigned int domid;
};

/*
 * Sanity check helpers.
 */
static int hatch_sanity(const struct hatch_args *args)
{
    assert(args != NULL);

    if (!args->recv && (args->domid == VMADDR_CID_ANY)) {
        printe("Missing domid.");
        return -EINVAL;
    }
    if (args->recv && !args->local_port) {
        printe("Missing local port.");
        return -EINVAL;
    }
    if (!args->recv && !args->port) {
        printe("Missing port.");
        return -EINVAL;
    }

    return 0;
}

/*
 * Recving end.
 */
static int hatch_recvfrom_run(unsigned long port)
{
    struct sockaddr_vm sa = { 0 };
    struct sockaddr_vm sar = {
        .svm_family = AF_VSOCK,
        .svm_port = port,
        .svm_cid = VMADDR_CID_ANY,
        .svm_zero = { 0 },
    };
    socklen_t sa_len = 0;
    char msg[1025] = { 0 };
    int s, rc;

    s = __vsock_bdgram(&sar);

    while (1) {
        rc = recvfrom(s, msg, sizeof (msg) - 1, 0,
                      (struct sockaddr *)&sa, &sa_len);
        if (rc < 0) {
            rc = -errno;
            perror("recvfrom");
            goto out;
        }
        printd("received from dom%u:%u %dB.", sa.svm_cid, sa.svm_port, rc);
        msg[rc] = '\0';
        rc = write(STDOUT_FILENO, msg, rc);
        if (rc < 0) {
            rc = -errno;
            perror("write");
            goto out;
        }
    }

out:
    close(s);
    return rc;
}

/*
 * Sending side.
 */
static int hatch_sendto_run(unsigned int domid, unsigned long port)
{
    int s, rc;
#define AUTOBIND
#ifndef AUTOBIND
    struct sockaddr_vm sal = {
        .svm_family = AF_VSOCK,
        .svm_cid = VMADDR_CID_ANY,
        .svm_port = VMADDR_PORT_ANY,
        .svm_zero = { 0 },
    };
#endif /* AUTOBIND */
    struct sockaddr_vm sa = {
        .svm_family = AF_VSOCK,
        .svm_cid = domid,
        .svm_port = port,
        .svm_zero = { 0 },
    };
    char msg[1025] = { 0 };
    size_t offset, msg_len = 0;

#ifdef AUTOBIND
    s = __vsock_dgram();
#else /* !AUTOBIND */
    s = __vsock_bdgram(&sal);
#endif /* AUTOBIND */

    while (1) {
        do {
            rc = read(0, msg, sizeof (msg) - 1);
            if (rc < 0) {
                rc = -errno;
                perror("read");
                goto out;
            } else if (rc == 0)
                goto out;

            msg_len = rc;
        } while (msg_len == 0);

        printd("%zuB read from stdin.", msg_len);

        offset = 0;
        do {
            rc = sendto(s, msg + offset, msg_len, 0,
                        (struct sockaddr *)&sa, sizeof (sa));
            if (rc < 0) {
                rc = -errno;
                perror("sendto");
                goto out;
            }
            printd("%dB sent to dom%u:%u.", rc, sa.svm_cid, sa.svm_port);
            offset += rc;
            msg_len -= rc;
        } while (msg_len != 0);
    }

out:
    close(s);
    return rc;
}

static int hatch_run(const struct hatch_args *args)
{
    int rc;

    assert(args != NULL);

    rc = hatch_sanity(args);
    if (rc < 0)
        return -rc;

    if (args->recv)
        rc = hatch_recvfrom_run(args->local_port);
    else
        rc = hatch_sendto_run(args->domid, args->port);

    return rc;
}

/*
 * Usage.
 */
static int usage(int rc)
{
    printi("Basic usage:");
    printi("	hatch domid port");
    printi("	hatch -r -p local_port");
    printi("Options:");
    printi("	-r, --recv	receive mode, wait for incoming packets.");
    printi("	-p, --port	set local port number.");
    printi("	-D	        enable debug output on stderr.");

    return rc;
}

/*
 * Option handling.
 */
#define OPT_STR "hrp:D"
static struct option long_options[] = {
    { "help", no_argument,       0, 'h' },
    { "recv", no_argument,       0, 'r' },
    { "port", required_argument, 0, 'p' },
    { ""    , no_argument,       0, 'D' },
    { 0,      0,                 0, 0 }
};

int main(int argc, char *argv[])
{
    int rc;
    struct hatch_args args = {
        .recv = 0,
        .local_port = 0,
        .port = 0,
        .domid = VMADDR_CID_ANY,
    };

    if (argc < 1)
        return usage(EINVAL);

    while (1) {
        int opt, longindex;

        opt = getopt_long(argc, argv, OPT_STR, long_options, &longindex);
        switch (opt) {
            case -1:
                goto getopt_done;
            case 0:
                printe("Malformed option \"%s\", please fix the code.",
                       long_options[longindex].name);
                return EINVAL;
            case 'h':
                return usage(0);
            case 'r':
                args.recv = 1;
                continue;
            case 'p':
                rc = parse_uint(optarg, &args.local_port);
                if (rc || !is_valid_port(args.local_port)) {
                    printe("Invalid local port %u.", args.local_port);
                    return -rc;
                }
                continue;
            case 'D':
                __enable_debug_print = 1;
                continue;

            default:
                printe("Unknown option '%c'.", opt);
                return usage(EINVAL);
        }
    }

getopt_done:
    while (optind < argc) {
        if (args.domid == VMADDR_CID_ANY)
            parse_domid(argv[optind++], &args.domid);
        else if (!args.port) {
            rc = parse_uint(argv[optind++], &args.port);
            if (rc || !is_valid_port(args.port)) {
                printe("Invalid port %s.", argv[optind - 1]);
                return -rc;
            }
        } else
            printw("Argument \"%s\" not handled.", argv[optind++]);
    }

    return hatch_run(&args);
}
