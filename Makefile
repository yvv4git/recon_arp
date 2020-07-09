all: build

build:
	go build -o cmd/build/scan.bin cmd/main.go
	#GOOS=linux GOARCH=386 go build -o cmd/build/scan86.bin cmd/main.go
	GOOS=linux GOARCH=amd64 go build -o cmd/build/scan64.bin cmd/main.go
	#GOOS=linux GOARCH=arm GOARM=6 go build -o cmd/build/scanArm.bin cmd/main.go
	#GOOS=freebsd GOARCH=amd64 go build -o cmd/build/scanFreebsd64.bin cmd/main.go
	#GOOS=windows GOARCH=amd64 go build -o cmd/build/scanWin64.bin cmd/main.go