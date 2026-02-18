BINARY = gossh.wasm
GOROOT_WASM_EXEC = $(shell go env GOROOT)/lib/wasm/wasm_exec.js

.PHONY: build clean wasm-exec check

# Build the WASM binary with optimized flags
build: wasm-exec
	GOOS=js GOARCH=wasm go build \
		-ldflags="-s -w" \
		-o $(BINARY) \
		./cmd/gossh/
	@ls -lh $(BINARY) | awk '{print "Built:", $$5, $$9}'

# Copy wasm_exec.js from the Go SDK (must match the Go version used to build)
wasm-exec:
	@if [ ! -f wasm_exec.js ] || ! diff -q $(GOROOT_WASM_EXEC) wasm_exec.js > /dev/null 2>&1; then \
		cp $(GOROOT_WASM_EXEC) wasm_exec.js; \
		echo "Copied wasm_exec.js from Go SDK"; \
	fi

# Verify the build compiles without errors
check:
	GOOS=js GOARCH=wasm go vet ./...

# Run wasm-opt if available (Binaryen)
optimize: build
	@if command -v wasm-opt > /dev/null 2>&1; then \
		wasm-opt -Oz $(BINARY) -o $(BINARY); \
		ls -lh $(BINARY) | awk '{print "Optimized:", $$5, $$9}'; \
	else \
		echo "wasm-opt not found. Install binaryen: brew install binaryen"; \
	fi

clean:
	rm -f $(BINARY)
