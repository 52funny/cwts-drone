.PHONE: build tools clean

all: build tools

build:
	go build cmd/ta/*
	go build cmd/uav/*
	go build cmd/aggregate/*

tools:
	go build cmd/tools/*

clean: 
	rm -f ta uav aggregate launch
