.PHONY: all clean proxy agent

ifndef TOKEN
CONN_STRING ?=
else
CONN_STRING = -X 'main.ConnString=$(TOKEN)'
endif

all: clean proxy agent

proxy:
	go build -ldflags="-s -w" -trimpath -o proxy cmd/proxy/main.go

agent:
	go build -ldflags="-s -w $(CONN_STRING)" -trimpath -o agent cmd/agent/main.go

clean:
	rm -f proxy agent