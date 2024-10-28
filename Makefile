build:
	go build cmd/ta/*
	go build cmd/uav/*
	go build cmd/aggregate/*

tools:
	go build cmd/tools/*