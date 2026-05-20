IMAGE ?= pa-course-starter
TARGET ?= toy_command_runner
TARGETS_DIR ?= $(CURDIR)/targets
OUT ?= $(abspath $(CURDIR)/../out)
EXPLOIT ?=
VALIDATOR ?=
RUN_USER ?= $(shell id -u):$(shell id -g)

.PHONY: build run-target run-all validate-exploit clean

build:
	docker build -t $(IMAGE) .

run-target:
	mkdir -p "$(OUT)"
	docker run --rm \
		$(if $(wildcard .env),--env-file ".env") \
		--user "$(RUN_USER)" \
		-v "$(TARGETS_DIR)":/targets:ro \
		-v "$(OUT)":/out \
		--entrypoint /bin/sh \
		$(IMAGE) \
		-c 'find /out -mindepth 1 -maxdepth 1 -exec rm -rf {} +; analyze /targets /out $(TARGET)'

run-all:
	mkdir -p "$(OUT)"
	docker run --rm \
		$(if $(wildcard .env),--env-file ".env") \
		--user "$(RUN_USER)" \
		-v "$(TARGETS_DIR)":/targets:ro \
		-v "$(OUT)":/out \
		--entrypoint /bin/sh \
		$(IMAGE) \
		-c 'find /out -mindepth 1 -maxdepth 1 -exec rm -rf {} +; analyze /targets /out'

validate-exploit:
	test -n "$(EXPLOIT)"
	test -n "$(VALIDATOR)"
	docker run --rm \
		--network none \
		--user "$(RUN_USER)" \
		--read-only \
		--tmpfs /tmp:rw,nosuid,nodev \
		--tmpfs /work:rw,nosuid,nodev,mode=1777 \
		-v "$(TARGETS_DIR)":/targets_src:ro \
		-v "$(OUT)":/submission_out:ro \
		-v "$(abspath $(VALIDATOR))":/validator.py:ro \
		-w /work \
		--entrypoint /bin/sh \
		$(IMAGE) \
		-c 'set -eu; mkdir -p /work/targets /work/validator; cp -R /targets_src/. /work/targets/; export TARGET_ROOT=/work/targets/$(TARGET); export PYTHONPATH=$$TARGET_ROOT:$$TARGET_ROOT/lib; export EXPLOIT_PATH=/submission_out/$(EXPLOIT); export EXPLOIT_MARKER=/work/marker; export VALIDATOR_WORK=/work/validator; python /validator.py'

clean:
	rm -rf $(OUT)
