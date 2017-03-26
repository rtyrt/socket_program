
all: server.cpp
	g++ server.cpp -o server -lcrypto -lssl -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib


