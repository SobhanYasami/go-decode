package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
)

func decodeUnicode(str string) (string, error) {
	return strconv.Unquote(`"` + str + `"`)
}

func encodeUnicode(str string) string {
	var b strings.Builder
	for _, r := range str {
		if r >= 128 {
			b.WriteString(fmt.Sprintf("\\u%04x", r))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func decodeJSON(str string) (string, error) {
	var output strings.Builder
	dec := json.NewDecoder(strings.NewReader(str))

	for {
		t, err := dec.Token()
		if err != nil {
			break
		}
		switch v := t.(type) {
		case string:
			decoded, _ := decodeUnicode(v)
			output.WriteString(decoded + "\n")
		}
	}
	return output.String(), nil
}

// Read file content
func readFile(path string) (string, error) {
	data, err := ioutil.ReadFile(path)
	return string(data), err
}

// Save output
func writeFile(path, content string) error {
	return ioutil.WriteFile(path, []byte(content), 0644)
}

func main() {
	inputFile := flag.String("f", "", "Input file")
	outputFile := flag.String("o", "", "Output file")
	// decodeFlag := flag.Bool("d", false, "Decode Unicode (default)")
	encodeFlag := flag.Bool("e", false, "Encode to Unicode")
	jsonFlag := flag.Bool("json", false, "Auto decode all string values from JSON")

	flag.Parse()

	// Grab input (priority: file > arg > stdin)
	var input string
	if *inputFile != "" {
		content, err := readFile(*inputFile)
		if err != nil {
			fmt.Println("File read error:", err)
			return
		}
		input = content
	} else if len(flag.Args()) > 0 {
		input = strings.Join(flag.Args(), " ")
	} else {
		// Read from stdin (pipe support)
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			data, _ := ioutil.ReadAll(os.Stdin)
			input = string(data)
		} else {
			fmt.Print("Enter text: ")
			reader := bufio.NewReader(os.Stdin)
			in, _ := reader.ReadString('\n')
			input = strings.TrimSpace(in)
		}
	}

	// Process input
	var output string
	var err error

	// Default mode is decode unless encode flag exists
	if *encodeFlag {
		output = encodeUnicode(input)
	} else if *jsonFlag {
		output, err = decodeJSON(input)
	} else {
		output, err = decodeUnicode(input)
	}

	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// If -o provided write to file
	if *outputFile != "" {
		if err := writeFile(*outputFile, output); err != nil {
			fmt.Println("Write output file error:", err)
		} else {
			fmt.Println("Saved to:", *outputFile)
		}
		return
	}

	fmt.Print(output)
}
