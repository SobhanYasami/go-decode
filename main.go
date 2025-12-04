package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/url"
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

func readFile(path string) (string, error) {
	data, err := ioutil.ReadFile(path)
	return string(data), err
}

func writeFile(path, content string) error {
	return ioutil.WriteFile(path, []byte(content), 0644)
}

func main() {
	// Existing flags
	inputFile := flag.String("f", "", "Input file")
	outputFile := flag.String("o", "", "Output file")
	// decodeFlag := flag.Bool("d", false, "Decode Unicode (default)")
	encodeFlag := flag.Bool("e", false, "Encode to Unicode")
	jsonFlag := flag.Bool("json", false, "Decode string values from JSON")

	// New flags
	urlEncode := flag.Bool("url-encode", false, "URL encode input")
	urlDecode := flag.Bool("url-decode", false, "URL decode input")
	b64Encode := flag.Bool("b64-encode", false, "Base64 encode input")
	b64Decode := flag.Bool("b64-decode", false, "Base64 decode input")

	flag.Parse()

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

	var output string
	var err error

	// Priority order for encoding/decoding
	switch {
	case *encodeFlag:
		output = encodeUnicode(input)
	case *jsonFlag:
		output, err = decodeJSON(input)
	case *urlEncode:
		output = url.QueryEscape(input)
	case *urlDecode:
		decoded, err2 := url.QueryUnescape(input)
		if err2 != nil {
			fmt.Println("URL decode error:", err2)
			return
		}
		output = decoded
	case *b64Encode:
		output = base64.StdEncoding.EncodeToString([]byte(input))
	case *b64Decode:
		decoded, err2 := base64.StdEncoding.DecodeString(strings.TrimSpace(input))
		if err2 != nil {
			fmt.Println("Base64 decode error:", err2)
			return
		}
		output = string(decoded)
	default:
		output, err = decodeUnicode(input)
	}

	// Check decodeUnicode error
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

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
