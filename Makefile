CC = g++
CFLAGS = -Wall -O2
LIBS = -loqs -lcrypto -lssl

all: server client

server: src/server.cpp
	$(CC) $(CFLAGS) -o server src/server.cpp $(LIBS)

client: src/client.cpp
	$(CC) $(CFLAGS) -o client src/client.cpp $(LIBS)

clean:
	rm -f server client
