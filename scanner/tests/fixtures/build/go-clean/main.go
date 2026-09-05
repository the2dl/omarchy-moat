package main

import "fmt"

//go:generate stringer -type=Pill
//go:generate mockgen -source=store.go -destination=mock_store.go
//go:generate protoc --go_out=. api.proto
//go:generate go run golang.org/x/tools/cmd/goimports@latest -w .

type Pill int

const (
	Placebo Pill = iota
	Aspirin
)

func main() { fmt.Println(Placebo) }
