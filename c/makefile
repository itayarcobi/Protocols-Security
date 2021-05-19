CC =gcc
FLAGS=-Wall -g
all: ipv4 ipv6
ipv4: ipv4.c
	$(CC) $(FLAGS)  -o ipv4 ipv4.c
ipv6:ipv6.c
	$(CC) $(FLAGS)  -o ipv6 ipv6.c
.PHONY: clean all
clean:
	rm -f ipv6 ipv4