ENV=CGO_ENABLED=0
all:
	$(ENV) go build clickjack.go

clean:
	rm clickjack
