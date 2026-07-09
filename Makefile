CLANG      ?= clang
BPFTOOL    ?= bpftool
BUILD      := build
BPF_SRC    := bpf/edr.bpf.c
BPF_OBJ    := $(BUILD)/edr.bpf.o
SKEL       := include/edr.skel.h
INC        := -Iinclude -Iexternal
BPF_CFLAGS := -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 $(INC)

.PHONY: all bpf skel app clean test

all: bpf skel app

$(BUILD):
	@mkdir -p $(BUILD)

bpf: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC) include/common.h include/vmlinux.h | $(BUILD)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(BPFTOOL) gen object $@.tmp $@ 2>/dev/null || true
	@[ -f $@.tmp ] && mv $@.tmp $@ || true

skel: $(SKEL)

$(SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< name edr_bpf > $@

app: skel
	@cmake -S . -B $(BUILD) -DCMAKE_BUILD_TYPE=Release >/dev/null
	@cmake --build $(BUILD) -j$$(nproc)

test:
	$(CLANG) -O0 -g test/trigger_suite.c -o $(BUILD)/trigger_suite

clean:
	rm -rf $(BUILD) $(SKEL)