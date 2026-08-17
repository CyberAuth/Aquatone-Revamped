package main

import (
	"os"

	"github.com/CyberAuth/Aquatone-Revamped/v2/internal/app"
)

func main() {
	os.Exit(app.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
