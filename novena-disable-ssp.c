#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <endian.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <syslog.h>

#define PIDFILE_NAME "/var/run/novena-disable-ssp.pid"

struct mgmt_hdr {
	uint16_t opcode;
	uint16_t index; 
	uint16_t len;
} __attribute__((__packed__)); 
#define MGMT_HDR_SIZE   6 

struct mgmt_addr_info {
	bdaddr_t bdaddr;
	uint8_t type;
} __attribute__((__packed__));

#define MGMT_EV_NEW_SETTINGS            0x0006

#define MGMT_EV_DEVICE_ADDED            0x001a
struct mgmt_ev_device_added {
	struct mgmt_addr_info addr;
	uint8_t action;
} __attribute__((__packed__));

static int is_daemon = 1; /* Daemonize by default */
static int is_debug = 0;

static int open_socket(uint16_t channel)
{
	struct sockaddr_hci addr;
	int fd, opt = 1;

	fd = socket(AF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC, BTPROTO_HCI);
	if (fd < 0) {
		perror("Failed to open channel");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.hci_family = AF_BLUETOOTH;
	addr.hci_dev = HCI_DEV_NONE;
	addr.hci_channel = channel;

	if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		if (errno == EINVAL) {
			close(fd);
			return -1;
		}
		perror("Failed to bind channel");
		close(fd);
		return -1;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_TIMESTAMP, &opt, sizeof(opt)) < 0) {
		perror("Failed to enable timestamps");
		close(fd);
		return -1;
	}

	return fd;
}

static int disable_ssp(int index)
{
	int dd;

	if (is_daemon)
		syslog(LOG_USER | LOG_INFO, 
			"disabling SSP on hci%d\n", index);
	else
		fprintf(stderr, "SSP detected on hci%d!  "
			"Trying to disable it...\n", index);

	dd = hci_open_dev(index);
	if (dd < 0) {
		if (is_daemon)
			syslog(LOG_USER | LOG_ERR,
				"couldn't open hci%d: %s (%d)\n",
				index, strerror(errno), errno);
		else
			fprintf(stderr, "Can't open hci%d: %s (%d)\n",
				index, strerror(errno), errno);
		return 1;
	}

	if (hci_write_simple_pairing_mode(dd, 0, 2000) < 0) {
		if (is_daemon)
			syslog(LOG_USER | LOG_ERR,
				"Unable to disable SSP on hci%d: %s (%d)\n",
				index, strerror(errno), errno);
		else
			fprintf(stderr, "Unable to disable SSP on "
				"hci%d: %s (%d)\n",
				index, strerror(errno), errno);
	}
	hci_close_dev(dd);

	return 0;
}

void packet_control(struct timeval *tv, uint16_t index, uint16_t opcode,
					const void *data, uint16_t size)
{
	const struct mgmt_ev_device_added *device_added;

	switch(opcode) {
	case MGMT_EV_DEVICE_ADDED: {
		char str[18];
		device_added = data;
		if (size < sizeof(*device_added)) {
			if (is_debug)
				fprintf(stderr,
					"Bad 'Device Added' control packet\n");
			return;
		}
		ba2str(&device_added->addr.bdaddr, str);

		if (is_debug)
			printf("Device added: %s (%d) %d\n", str,
				device_added->addr.type, device_added->action);
		}
		break;

	case MGMT_EV_NEW_SETTINGS: {
		uint32_t settings;

		if (size < 4) {
			if (is_debug)
				fprintf(stderr,
					"Bad 'New Settings' control packet\n");
			return;
		}

		settings = le32toh(data);
		if (is_debug)
			fprintf(stderr, "New settings: 0x%4.4x\n", settings);

		/* If "SSP" settings flag is set, clear it */
		if (settings & (1 << 6))
			disable_ssp(index);
		}
		break;

	default:
		if (is_debug)
			fprintf(stderr,
				"Control packet (unknown) 0x%04x 0x%04x\n",
				opcode, size);
	}
}

static void run(int fd)
{
	unsigned char control[32];
	struct mgmt_hdr hdr;
	struct msghdr msg;
	struct iovec iov[2];
	uint8_t buf[4096];

	iov[0].iov_base = &hdr;
	iov[0].iov_len = MGMT_HDR_SIZE;
	iov[1].iov_base = buf;
	iov[1].iov_len = sizeof(buf);

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	while (1) {
		struct cmsghdr *cmsg;
		struct timeval *tv = NULL;
		struct timeval ctv;
		uint16_t opcode, index, pktlen;
		ssize_t len;

		len = recvmsg(fd, &msg, 0);

		if (-1 == len) {
			if (errno == EAGAIN)
				continue;
			perror("Fatal: Unable to read from socket");
			return;
		}

		if (0 == len) {
			fprintf(stderr, "Fatal: Control socket closed\n");
			return;
		}

		if (len < MGMT_HDR_SIZE) {
			fprintf(stderr, "Short read\n");
			continue;
		}

		for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
		     cmsg = CMSG_NXTHDR(&msg, cmsg)) {
			if (cmsg->cmsg_level != SOL_SOCKET)
				continue;

			if (cmsg->cmsg_type == SCM_TIMESTAMP) {
				memcpy(&ctv, CMSG_DATA(cmsg), sizeof(ctv));
				tv = &ctv;
			}
		}

		opcode = le16toh(hdr.opcode);
		index  = le16toh(hdr.index);
		pktlen = le16toh(hdr.len);

		packet_control(tv, index, opcode, buf, pktlen);
	}
}


static int init(void)
{
	int fd;

	fd = open_socket(HCI_CHANNEL_CONTROL);
	if (fd == -1) {
		perror("Fatal: Unable to open control socket");
		return -1;
	}

	return fd;
}

static int parseopt(int argc, char **argv)
{
	int opt;

	while ((opt = getopt(argc, argv, "dn")) != -1) {
		switch (opt) {
		case 'd':
			is_daemon = 0;
			break;

		case 'n':
			is_debug = 1;
			break;

		default:
			return 1;
		}
	}
	return 0;
}

static void createpid(void)
{
	/* Create a pidfile for us */
	int fd = open(PIDFILE_NAME, O_WRONLY | O_CREAT, 0600);
	if (-1 == fd) {
		perror("Unable to open pidfile " PIDFILE_NAME);
	}
	char bfr[32];
	snprintf(bfr, sizeof(bfr) - 1, "%ld\n", (long)getpid());
	if (-1 == write(fd, bfr, strlen(bfr))) {
		perror("Unable to update pidfile");
		close(fd);
	}
	close(fd);
}

static void removepid(void)
{
	unlink(PIDFILE_NAME);
}

int main(int argc, char **argv)
{
	int fd;

	fd = init();
	if (fd < 0) {
		fprintf(stderr, "Unable to init\n");
		return 1;
	}

	if (parseopt(argc, argv)) {
		printf("Usage: %s [-d] [-n]\n"
			"	-d	Print out debug information\n"
			"	-n	Don't daemonize\n"
			"", argv[0]);
		return 1;
	}

	if (is_daemon)
		daemon(0, 0);

	createpid();
	atexit(removepid);

	run(fd);

	return 0;
}
