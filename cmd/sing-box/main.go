//go:build !generate

package main

import "github.com/konglong147/securefile/log"

func main() {
	if err := mainCommand.Execute(); err != nil {
		log.Fatal(err)
	}
}
