package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func decodeUnicode(escaped string) (string, error) {
	result, err := strconv.Unquote(`"` + escaped + `"`)
	return result, err
}

func decodeFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var output strings.Builder

	for scanner.Scan() {
		line := scanner.Text()
		decoded, err := decodeUnicode(line)
		if err != nil {
			return "", err
		}
		output.WriteString(decoded + "\n")
	}

	return output.String(), scanner.Err()
}

func main() {
	fileFlag := flag.String("f", "", "Path of file containing unicode text to decode")
	flag.Parse()

	// If -f is used, decode file
	if *fileFlag != "" {
		res, err := decodeFile(*fileFlag)
		if err != nil {
			fmt.Println("Error:", err)
			os.Exit(1)
		}
		fmt.Println(res)
		return
	}

	var input string

	// If arguments passed (not flag), decode argument
	if len(flag.Args()) > 0 {
		input = strings.Join(flag.Args(), " ")
	} else {
		// Otherwise read from stdin
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
