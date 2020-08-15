.PHONY: build

all: build

build:
	go build -o build/scan.bin main.go
	GOOS=linux GOARCH=amd64 go build -o build/scan64.bin main.go
	#GOOS=linux GOARCH=386 go build -o build/scan86.bin main.go
	#GOOS=linux GOARCH=arm GOARM=6 go build -o build/scanArm.bin main.go
	#GOOS=freebsd GOARCH=amd64 go build -o build/scanFreebsd64.bin main.go
	#GOOS=windows GOARCH=amd64 go build -o build/scanWin64.bin main.go