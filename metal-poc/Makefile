METAL_SDK := $(shell xcrun --sdk macosx --show-sdk-path)

.PHONY: build build-noselect verify bench bench-quick compare clean

build:
	xcrun metal -O2 -DUSE_SELECT -c ntlm_md4.metal -o ntlm_md4.air
	xcrun metallib ntlm_md4.air -o ntlm_md4.metallib
	swiftc -O -framework Metal -framework Foundation \
		main.swift -o ntlm_bench

build-noselect:
	xcrun metal -O2 -c ntlm_md4.metal -o ntlm_md4_nosel.air
	xcrun metallib ntlm_md4_nosel.air -o ntlm_md4.metallib
	swiftc -O -import-objc-header /dev/null -framework Metal -framework Foundation \
		main.swift -o ntlm_bench

verify: build
	./ntlm_bench --verify

bench: build
	./ntlm_bench --candidates 10000000 --trials 30 --json > results_select.json
	@cat results_select.json

bench-quick: build
	./ntlm_bench --candidates 10000000 --trials 3 --warmup 1

compare: build
	./ntlm_bench --candidates 10000000 --trials 10 --json > results_select.json
	@echo "--- select() variant ---"
	@cat results_select.json
	@echo ""
	$(MAKE) build-noselect
	./ntlm_bench --candidates 10000000 --trials 10 --json > results_noselect.json
	@echo "--- bitwise variant ---"
	@cat results_noselect.json

clean:
	rm -f *.air *.metallib ntlm_bench results_*.json
