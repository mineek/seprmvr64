SRC = $(wildcard src/*)
OBJDIR = obj
OBJS = $(patsubst src/%,$(OBJDIR)/%,$(SRC:.c=.o))
PLOOSHFINDER = plooshfinder/libplooshfinder.a
INCLDIRS = -I./include -I./plooshfinder/include

LDFLAGS += -L./plooshfinder
CFLAGS ?= -O2
CC := clang
LIBS = -lplooshfinder

.PHONY: $(PLOOSHFINDER) all

all: dirs $(PLOOSHFINDER) $(OBJS) seprmvr64

submodules:
	@git submodule update --init --remote --recursive || true

dirs:
	@mkdir -p $(OBJDIR)

clean:
	@rm -rf seprmvr64 obj
	@$(MAKE) -C plooshfinder clean

seprmvr64: $(OBJS) $(PLOOSHFINDER)
	$(CC) $(CFLAGS) $(LDFLAGS) $(LIBS) $(INCLDIRS) $(OBJS) -o $@

$(OBJDIR)/%.o: src/%.c
	$(CC) $(CFLAGS) $(INCLDIRS) -c -o $@ $<

$(PLOOSHFINDER):
	$(MAKE) -C plooshfinder all
