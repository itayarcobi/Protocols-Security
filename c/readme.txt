two .c files:
ipv4.c
ipv6.c
and one makefile

ipv4.c:
the first one demonstrates tcp rst flood and udp flood
compile with: gcc -o ipv4 ipv4.c
run with: sudo ./ipv4 <can add more- a detailed explanation is below>
(must use sudo to run because i used raw socket )
There are several options for the user to decide
when run the ipv4 execution file can add 3 options:
-t <ip_address> ---> after -t write ip dest addrees (defult: 127.0.0.1)
-p <port>----> after -p write dest port address (defult:443)
-r <"UDP">---> If you add -r you willl choose the protocol udp
else the defult is tcp rst.

ipv6.c:
the second one demonstrates udp flood
compile with: gcc -o ipv6 ipv6.c
run with: sudo ./ipv6 <can add more- a detailed explanation is below>
(must use sudo to run because i used raw socket )
There are several options for the user to decide
when run the ipv6 execution file can add 2 options:
-t <ip_address> ---> after -t write ip dest addrees (defult: ::1)
-p <port>----> after -p write dest port address (defult:443)

makefile:
make all: make two exection files:ipv4 and ipv6
make ipv4: make ipv4 exe file
make ipv6: make ipv6 exe file
make clean: delete the two exe files
