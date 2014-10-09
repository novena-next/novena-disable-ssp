CFLAGS += `pkg-config bluez --cflags --libs` -Wall -g $(shell dpkg-buildflags --get CFLAGS)
LDFLAGS += `pkg-config bluez --libs` -g $(shell dpkg-buildflags --get LDFLAGS)

all:
	$(CC) $(CFLAGS) $(LDFLAGS) novena-disable-ssp.c -o novena-disable-ssp

clean:
	rm -f novena-disable-ssp

install:
	mkdir -p $(DESTDIR)/usr/sbin
	mkdir -p $(DESTDIR)/lib/systemd/system
	mkdir -p $(DESTDIR)/usr/share/man/man1
	cp novena-disable-ssp $(DESTDIR)/usr/sbin/
	cp novena-disable-ssp.service $(DESTDIR)/lib/systemd/system/
	cp novena-disable-ssp.1 $(DESTDIR)/usr/share/man/man1
