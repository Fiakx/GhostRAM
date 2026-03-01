#  GhostRAM v2 — Makefile
#  Dependances : raylib (≥4.5), pthread, libm

CC      = gcc
TARGET  = main
SRC     = main.c
CFLAGS  = -O2 -Wall -Wextra -std=c11
LDFLAGS = -lraylib -lpthread -lm -ldl

# Detection auto de l'OS
UNAME := $(shell uname)
ifeq ($(UNAME), Linux)
    LDFLAGS += -lGL
endif
ifeq ($(UNAME), Darwin)
    LDFLAGS += -framework OpenGL -framework Cocoa -framework IOKit
endif

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo " Compilation OK -> ./$(TARGET)"
	@echo " Lance avec : sudo ./$(TARGET)"

clean:
	rm -f $(TARGET)

install-deps-ubuntu:
	sudo apt update && sudo apt install -y libraylib-dev

install-deps-arch:
	sudo pacman -S raylib

.PHONY: all clean install-deps-ubuntu install-deps-arch
