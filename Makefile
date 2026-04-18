# =============================================================================
# scatter — Makefile
# =============================================================================
#
# Targets:
#   make                 — release build, dynamic link against system OpenSSL
#                          (stripped, no build-id)
#   make debug           — -O0 -g -fsanitize=address,undefined (build-id kept)
#   make static-musl     — fully static musl binary, no runtime deps
#                          (stripped, no build-id). Requires:
#                              - musl-gcc
#                              - static OpenSSL under $(MUSL_SSL_PREFIX)
#                          Does NOT need linux-kernel-headers: scatter
#                          provides a fallback BLKGETSIZE64 definition.
#   make clean
#   make install
#   make test
#   make dist            — produce scatter-$(VERSION).tar.gz
# =============================================================================

CC          ?= cc
PREFIX      ?= /usr/local
BIN         := scatter
SRC         := scatter.c
VERSION     := 2.1.0

WARN_FLAGS  := -Wall -Wextra -Wpedantic -Wshadow -Wformat=2 \
               -Wstrict-prototypes -Wmissing-prototypes -Wcast-align \
               -Wpointer-arith -Wnull-dereference -Wdouble-promotion

HARD_CFLAGS := -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
               -fPIE -fno-strict-aliasing

# --build-id=none drops the BuildID[sha1] ELF note so the binary does not
# carry a per-build fingerprint (better for reproducibility and lower
# metadata footprint).
HARD_LDFLAGS:= -pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack \
               -Wl,--build-id=none

CFLAGS_BASE := -std=c11 $(WARN_FLAGS)
CFLAGS_REL  := $(CFLAGS_BASE) -O2 $(HARD_CFLAGS)
CFLAGS_DBG  := $(CFLAGS_BASE) -O0 -g3 -fsanitize=address,undefined
LDFLAGS_REL := $(HARD_LDFLAGS)
LDFLAGS_DBG := -fsanitize=address,undefined
LIBS_SYS    := -lcrypto

STRIP       ?= strip

MUSL_CC         ?= musl-gcc
MUSL_SSL_PREFIX ?= /usr/local/musl

.PHONY: all debug static-musl clean install test dist help

all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS_REL) $(CPPFLAGS) -o $@ $< $(LDFLAGS_REL) $(LIBS_SYS) $(LDFLAGS)
	$(STRIP) --strip-all $@
	@echo "Release: $$(file $@ | sed 's/,.*,/,/')"

debug: $(SRC)
	$(CC) $(CFLAGS_DBG) $(CPPFLAGS) -o $(BIN)-debug $< $(LDFLAGS_DBG) $(LIBS_SYS) $(LDFLAGS)

# Fully static musl binary.
#
# Prerequisites (once, on Arch):
#     sudo pacman -S musl
#     # build a static OpenSSL under /usr/local/musl:
#     curl -LO https://www.openssl.org/source/openssl-3.3.1.tar.gz
#     tar xf openssl-3.3.1.tar.gz && cd openssl-3.3.1
#     CC=musl-gcc ./Configure linux-x86_64 no-shared no-async no-engine \
#         --prefix=/usr/local/musl
#     make -j && sudo make install_sw
#
# Arch auto-picks lib/ or lib64/ depending on where install_sw dropped the
# archives. --start-group/--end-group removes order sensitivity between
# libssl.a and libcrypto.a.
static-musl: $(SRC)
	@test -d "$(MUSL_SSL_PREFIX)" || { \
	    echo "ERROR: $(MUSL_SSL_PREFIX) not found. Set MUSL_SSL_PREFIX or build musl-OpenSSL first."; \
	    exit 1; }
	@LIBDIR=""; \
	for d in $(MUSL_SSL_PREFIX)/lib64 $(MUSL_SSL_PREFIX)/lib; do \
	    if [ -f "$$d/libcrypto.a" ] && [ -f "$$d/libssl.a" ]; then LIBDIR=$$d; break; fi; \
	done; \
	if [ -z "$$LIBDIR" ]; then \
	    echo "ERROR: libssl.a / libcrypto.a not found under $(MUSL_SSL_PREFIX)"; \
	    exit 1; fi; \
	echo "using static OpenSSL from $$LIBDIR"; \
	$(MUSL_CC) -std=c11 $(WARN_FLAGS) -O2 -static \
	    -I$(MUSL_SSL_PREFIX)/include \
	    -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
	    -Wl,--build-id=none \
	    -o $(BIN)-static $(SRC) \
	    -Wl,--start-group $$LIBDIR/libssl.a $$LIBDIR/libcrypto.a -Wl,--end-group \
	    -lpthread -ldl
	$(STRIP) --strip-all $(BIN)-static
	@echo "Static musl: $$(file $(BIN)-static | sed 's/,.*,/,/')"
	@echo "Size:        $$(stat -c%s $(BIN)-static) bytes"

install: $(BIN)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(BIN) $(DESTDIR)$(PREFIX)/bin/$(BIN)

clean:
	rm -f $(BIN) $(BIN)-debug $(BIN)-static

test: $(BIN)
	./test_scatter.sh

dist:
	tar --transform "s,^,scatter-$(VERSION)/," \
	    -czf scatter-$(VERSION).tar.gz \
	    scatter.c Makefile README.md test_scatter.sh
	@echo "Created: scatter-$(VERSION).tar.gz"
	@sha256sum scatter-$(VERSION).tar.gz

help:
	@echo "Targets: all | debug | static-musl | clean | install | test | dist"
	@echo "Variables:"
	@echo "  PREFIX=/usr/local           (install prefix)"
	@echo "  MUSL_CC=musl-gcc            (musl compiler wrapper)"
	@echo "  MUSL_SSL_PREFIX=/usr/local/musl  (static OpenSSL root)"
