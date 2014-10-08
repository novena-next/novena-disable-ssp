CFLAGS=`pkg-config bluez --cflags --libs` -Wall

all: novena-disable-ssp.c
	${CC} ${CFLAGS} novena-disable-ssp.c -o novena-disable-ssp

clean:
	rm -f novena-disable-ssp

install:
	cp novena-disable-ssp /usr/sbin
	cp novena-disable-ssp.service /lib/systemd/system/
	systemctl enable novena-disable-ssp.service
