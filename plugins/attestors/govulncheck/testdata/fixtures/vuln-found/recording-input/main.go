package main

import (
	"fmt"

	"golang.org/x/text/language"
)

func main() {
	// Reachable call into the vulnerable symbol of GO-2022-1059:
	// golang.org/x/text/language.ParseAcceptLanguage (DoS on long input).
	tags, q, _ := language.ParseAcceptLanguage("en-US,en;q=0.9,fr;q=0.8")
	fmt.Println(tags, q)
}
