package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func decodeUnicode(escaped string) (string, error) {
	// wrap string in quotes so strconv.Unquote can decode it
	result, err := strconv.Unquote(`"` + escaped + `"`)
	return result, err
}

func main() {
	var input string

	// If argument provided, use it
	if len(os.Args) > 1 {
		input = strings.Join(os.Args[1:], " ")
	} else {
		// Otherwise, read from stdin
		fmt.Print("Enter unicode string: ")
		reader := bufio.NewReader(os.Stdin)
		inp, _ := reader.ReadString('\n')
		input = strings.TrimSpace(inp)
	}

	decoded, err := decodeUnicode(input)
	if err != nil {
		fmt.Println("Error decoding string:", err)
		os.Exit(1)
	}

	fmt.Println(decoded)
}
