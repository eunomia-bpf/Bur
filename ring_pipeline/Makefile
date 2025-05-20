CC ?= gcc
CFLAGS := -Wall -g
LDFLAGS := -luring -lbpf

all: four_ring_pipeline

four_ring_pipeline: four_ring_pipeline.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm -f four_ring_pipeline

.PHONY: all clean
