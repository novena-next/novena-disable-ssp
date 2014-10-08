#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <fcntl.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <syslog.h>

#include "swap.h"

typedef void (*mainloop_event_func) (int fd, uint32_t events, void *user_data);
typedef void (*mainloop_destroy_func) (void *user_data);
typedef void (*mainloop_signal_func) (int signum, void *user_data);

#define MAX_MAINLOOP_ENTRIES 128
#define MAX_EPOLL_EVENTS 10
#define PIDFILE_NAME "/var/run/novena-disable-ssp.pid"

 /* value taken from btsnoop.h, from bluez */
#define BTSNOOP_MAX_PACKET_SIZE		(1486 + 4)


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

struct mainloop_data {
	int fd;
	uint32_t events;
	mainloop_event_func callback;
	mainloop_destroy_func destroy;
	void *user_data;
};

struct signal_data {
	int fd;
	sigset_t mask;
	mainloop_signal_func callback;
	mainloop_destroy_func destroy;
	void *user_data;
};

struct control_data {
	uint16_t channel;
	int fd;
	unsigned char buf[BTSNOOP_MAX_PACKET_SIZE];
	uint16_t offset;
};

#define MGMT_EV_NEW_SETTINGS            0x0006

#define MGMT_EV_DEVICE_ADDED            0x001a
struct mgmt_ev_device_added {
	struct mgmt_addr_info addr;
	uint8_t action;
} __attribute__((__packed__));

static struct mainloop_data *mainloop_list[MAX_MAINLOOP_ENTRIES];
static struct signal_data *signal_data;

static int epoll_fd;
static int epoll_terminate;

static int is_daemon = 1; /* Daemonize by default */
static int is_debug = 0;

static void signal_callback(int signum, void *user_data)
{
	switch (signum) {
	case SIGINT:
	case SIGTERM:
		epoll_terminate = 1;
		break;
	}
}

int setup_signals(mainloop_signal_func callback, void *user_data,
		mainloop_destroy_func destroy)
{
	struct signal_data *data;
	sigset_t mask;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);

	if (!callback)
		return -EINVAL;

	data = malloc(sizeof(*data));
	if (!data)
		return -ENOMEM;

	memset(data, 0, sizeof(*data));
	data->callback = callback;
	data->destroy = destroy;
	data->user_data = user_data;

	data->fd = -1;
	memcpy(&data->mask, &mask, sizeof(sigset_t));

	free(signal_data);
	signal_data = data;

	return 0;
}

static void run(void)
{
	while (!epoll_terminate) {
		struct epoll_event events[MAX_EPOLL_EVENTS];
		int n, nfds;

		nfds = epoll_wait(epoll_fd, events, MAX_EPOLL_EVENTS, -1);
		if (nfds < 0)
			continue;

		for (n = 0; n < nfds; n++) {
			struct mainloop_data *data = events[n].data.ptr;

			data->callback(data->fd, events[n].events,
							data->user_data);
		}
	}
}

int mainloop_add_fd(int fd, uint32_t events, mainloop_event_func callback,
                                void *user_data, mainloop_destroy_func destroy)
{
	struct mainloop_data *data;
	struct epoll_event ev;
	int err;

	if (fd < 0 || fd > MAX_MAINLOOP_ENTRIES - 1 || !callback)
		return -EINVAL;

	data = malloc(sizeof(*data));
	if (!data)
		return -ENOMEM;

	memset(data, 0, sizeof(*data));
	data->fd = fd;
	data->events = events;
	data->callback = callback;
	data->destroy = destroy;
	data->user_data = user_data;

	memset(&ev, 0, sizeof(ev));
	ev.events = events;
	ev.data.ptr = data;

	err = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, data->fd, &ev);
	if (err < 0) {
		free(data);
		return err;
	}

	mainloop_list[fd] = data;

	return 0;
}

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

int mainloop_remove_fd(int fd)
{
	struct mainloop_data *data;
	int err;

	if (fd < 0 || fd > MAX_MAINLOOP_ENTRIES - 1)
		return -EINVAL;

	data = mainloop_list[fd];
	if (!data)
		return -ENXIO;

	mainloop_list[fd] = NULL;

	err = epoll_ctl(epoll_fd, EPOLL_CTL_DEL, data->fd, NULL);

	if (data->destroy)
		data->destroy(data->user_data);

	free(data);

	return err;
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

		settings = get_le32(data);
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


static void data_callback(int fd, uint32_t events, void *user_data)
{
	struct control_data *data = user_data;
	unsigned char control[32];
	struct mgmt_hdr hdr;
	struct msghdr msg;
	struct iovec iov[2];

	if (events & (EPOLLERR | EPOLLHUP)) {
		mainloop_remove_fd(data->fd);
		return;
	}

	iov[0].iov_base = &hdr;
	iov[0].iov_len = MGMT_HDR_SIZE;
	iov[1].iov_base = data->buf;
	iov[1].iov_len = sizeof(data->buf);

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

		len = recvmsg(data->fd, &msg, MSG_DONTWAIT);
		if (len < 0)
			break;

		if (len < MGMT_HDR_SIZE)
			break;

		for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
					cmsg = CMSG_NXTHDR(&msg, cmsg)) {
			if (cmsg->cmsg_level != SOL_SOCKET)
				continue;

			if (cmsg->cmsg_type == SCM_TIMESTAMP) {
				memcpy(&ctv, CMSG_DATA(cmsg), sizeof(ctv));
				tv = &ctv;
			}
		}

		opcode = le16_to_cpu(hdr.opcode);
		index  = le16_to_cpu(hdr.index);
		pktlen = le16_to_cpu(hdr.len);

		switch (data->channel) {
		case HCI_CHANNEL_CONTROL:
			packet_control(tv, index, opcode, data->buf, pktlen);
			break;
		case HCI_CHANNEL_MONITOR:
			//packet_monitor(tv, index, opcode, data->buf, pktlen);
			//fprintf(stderr, "Monitor packet 0x%04x 0x%04x\n",
			//		opcode, pktlen);
			break;
		}
	}
}

static void free_data(void *user_data)
{
	struct control_data *data = user_data;

	close(data->fd);

	free(data);
}

static int open_channel(uint16_t channel)
{
	struct control_data *data;

	data = malloc(sizeof(*data));
	if (!data)
		return -1;

	memset(data, 0, sizeof(*data));
	data->channel = channel;

	data->fd = open_socket(channel);
	if (data->fd < 0) {
		free(data);
		return -1;
	}

	mainloop_add_fd(data->fd, EPOLLIN, data_callback, data, free_data);

	return 0;
}

static int init(void)
{
	unsigned int i;

	epoll_fd = epoll_create1(EPOLL_CLOEXEC);

	for (i = 0; i < MAX_MAINLOOP_ENTRIES; i++)
		mainloop_list[i] = NULL;

	epoll_terminate = 0;

	if (open_channel(HCI_CHANNEL_MONITOR) < 0)
		return -1;

	if (open_channel(HCI_CHANNEL_CONTROL) < 0)
		return -1;

	return 0;
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

int main(int argc, char **argv)
{
	setup_signals(signal_callback, NULL, NULL);

	if (init()) {
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

	/* Create a pidfile for us */
	int fd = open(PIDFILE_NAME, O_WRONLY | O_CREAT, 0600);
	if (-1 == fd) {
		perror("Unable to open pidfile " PIDFILE_NAME);
		return 1;
	}
	char bfr[32];
	snprintf(bfr, sizeof(bfr) - 1, "%ld\n", (long)getpid());
	if (-1 == write(fd, bfr, strlen(bfr))) {
		perror("Unable to update pidfile");
		close(fd);
		return 1;
	}
	close(fd);

	run();

	return 0;
}
