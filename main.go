package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println(dkgray + "usage:" + reset)
		fmt.Println(gray + "  juubi --setup              " + reset + dkgray + "first time setup" + reset)
		fmt.Println(gray + "  juubi -t <target>          " + reset + dkgray + "run enumeration" + reset)
		fmt.Println(gray + "  juubi -t <target> --passive" + reset + dkgray + "passive only" + reset)
		os.Exit(1)
	}

	switch os.Args[1] {
	case "--setup":
		runSetup()
	case "-t":
		if len(os.Args) < 3 {
			fmt.Println("usage: juubi -t <target>")
			os.Exit(1)
		}
		runEnum(os.Args[2], "tools.yaml")
	default:
		fmt.Println("unknown command:", os.Args[1])
		os.Exit(1)
	}
}
