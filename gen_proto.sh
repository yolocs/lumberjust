#!/bin/bash

protoc --go_out=. --go-grpc_out=. ./pkg/apis/lumberjust.proto
