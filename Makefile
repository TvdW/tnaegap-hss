CC = cc
CFLAGS = -Wall

all:
	$(CC) $(CFLAGS) -o tnaegap-hss.exe security.c tnaegap-hss.c
