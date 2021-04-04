CC=gcc
CFLAGS= -Wall -pedantic -framework Security -sectcreate __TEXT __info_plist ./Info.plist
INCLUDES=-Iinclude/
LIBS=BeaEngine.o
BIN=crash
TARGET=/usr/local/bin

CODESIGN_CERT=codesigning-cert

all:
	$(CC) $(INCLUDES) $(CFLAGS) $(LIBS) $(BIN).c -o $(BIN)

install:
	-cp $(BIN) $(TARGET)
	-chgrp procmod $(TARGET)/$(BIN)
	-chmod 2755 $(TARGET)/$(BIN)
	-codesign -s $(CODESIGN_CERT) $(TARGET)/$(BIN)
