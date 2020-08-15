all: build

build:
	go build -o app/build/scan.bin app/main.go
	#GOOS=linux GOARCH=386 go build -o app/build/scan86.bin app/main.go
	GOOS=linux GOARCH=amd64 go build -o app/build/scan64.bin app/main.go
	#GOOS=linux GOARCH=arm GOARM=6 go build -o app/build/scanArm.bin app/main.go
	#GOOS=freebsd GOARCH=amd64 go build -o app/build/scanFreebsd64.bin app/main.go
	#GOOS=windows GOARCH=amd64 go build -o app/build/scanWin64.bin app/main.go