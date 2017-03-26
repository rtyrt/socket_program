
all: client.cpp
	g++ client.cpp -o client -lcrypto -lssl -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib

