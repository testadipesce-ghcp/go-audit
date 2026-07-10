BUILD_NUMBER ?= dev+$(shell date -u '+%Y%m%d%H%M%S')+$(shell pwd -P)+$(shell /usr/bin/git  log -n1 --pretty=format:"%h")
GO111MODULE = on
export GO111MODULE

LDFLAGS = -X main.Build=$(BUILD_NUMBER)

ALL = linux-amd64 linux-arm64

bin:
	go build -ldflags "$(LDFLAGS)"

install:
	/usr/bin/cp -fvp go-audit /usr/local/sbin/ec-go-audit
	/usr/bin/perl -i.backup -pe 's#^\#\s*BUILD_NUMBER\s*=\s*#\# BUILD_NUMBER='$(BUILD_NUMBER)'#g;' ec-go-audit.yaml
	/usr/bin/cp -fvp ec-go-audit.yaml /etc/
	/usr/bin/chmod -v 640 /etc/ec-go-audit.yaml

test:
	go test -v

test-cov-html:
	go test -coverprofile=coverage.out
	go tool cover -html=coverage.out

bench:
	go test -bench=.

bench-cpu:
	go test -bench=. -benchtime=5s -cpuprofile=cpu.pprof
	go tool pprof go-audit.test cpu.pprof

bench-cpu-long:
	go test -bench=. -benchtime=60s -cpuprofile=cpu.pprof
	go tool pprof go-audit.test cpu.pprof

release: $(ALL:%=build/go-audit-%.tar.gz)

build/%/go-audit: .FORCE
	GOOS=$(firstword $(subst -, , $*)) \
		GOARCH=$(word 2, $(subst -, ,$*)) \
		go build -trimpath -ldflags "$(LDFLAGS)" -o $@ .

build/go-audit-%.tar.gz: build/%/go-audit
	tar -zcv -C build/$* -f $@ go-audit

.FORCE:
.PHONY: test test-cov-html bench bench-cpu bench-cpu-long bin release
.DEFAULT_GOAL := bin
