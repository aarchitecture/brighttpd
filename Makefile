CXX := g++
LD := ld
OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl)
OPENSSL_LIBS := $(shell pkg-config --libs openssl)
CXXFLAGS_BASE := -std=c++17 -Wall -Wextra -Wpedantic -pthread
CXXFLAGS_RELEASE := -O3 -march=native -mtune=native -flto -DNDEBUG
CXXFLAGS_SANITIZE := -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined
LDFLAGS_RELEASE := -flto
LDFLAGS_SANITIZE := -fsanitize=address,undefined

SANITIZE ?= 0

ifeq ($(SANITIZE),1)
CXXFLAGS := $(CXXFLAGS_BASE) $(CXXFLAGS_SANITIZE)
LDFLAGS := $(LDFLAGS_SANITIZE)
TARGET := brighttpd-asan
else
CXXFLAGS := $(CXXFLAGS_BASE) $(CXXFLAGS_RELEASE)
LDFLAGS := $(LDFLAGS_RELEASE)
TARGET := brighttpd
endif

SRC := brighttpd.cpp
OBJ := $(SRC:.cpp=.o)
EMBED_OBJ := index_html.o 404_html.o

.PHONY: all clean asan bench bench-tls

all: $(TARGET)

asan:
	$(MAKE) SANITIZE=1 all

$(TARGET): $(OBJ) $(EMBED_OBJ)
	$(CXX) $(OBJ) $(EMBED_OBJ) -o $@ $(LDFLAGS) $(OPENSSL_LIBS)

%.o: %.cpp io_uring_ring.hpp
	$(CXX) $(CXXFLAGS) $(OPENSSL_CFLAGS) -c $< -o $@

index_html.o: index.html
	$(LD) -r -b binary -o $@ $<

404_html.o: 404.html
	$(LD) -r -b binary -o $@ $<

bench: $(TARGET)
	./bench/benchmark.sh

bench-tls: $(TARGET)
	./bench/benchmark_tls.sh

clean:
	rm -f $(OBJ) $(EMBED_OBJ) brighttpd brighttpd-asan
