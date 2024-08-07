package main

import (
	"log"

	"github.com/deepfactor-io/trivy/v3/pkg/dependency/parser/golang/mod"
)

func main() {
	if _, err := mod.Parse(nil); err != nil {
		log.Fatal(err)
	}
}
