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

// Decode \uXXXX Unicode escapes
func decodeUnicode(str string) (string, error) {
	return strconv.Unquote(`"` + str + `"`)
}

// Encode string to \uXXXX Unicode escapes
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

// Decode JSON string values
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

// Read file content as string
func readFile(path string) (string, error) {
	data, err := ioutil.ReadFile(path)
	return string(data), err
}

// Write string content to file
func writeFile(path, content string) error {
	return ioutil.WriteFile(path, []byte(content), 0644)
}

// Decode JWT token parts and pretty print
func decodeJWT(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("Invalid JWT token format")
	}

	decodeSegment := func(seg string) (map[string]interface{}, error) {
		// Add padding if missing
		if l := len(seg) % 4; l != 0 {
			seg += strings.Repeat("=", 4-l)
		}
		data, err := base64.URLEncoding.DecodeString(seg)
		if err != nil {
			return nil, err
		}
		var res map[string]interface{}
		if err := json.Unmarshal(data, &res); err != nil {
			return nil, err
		}
		return res, nil
	}

	header, err := decodeSegment(parts[0])
	if err != nil {
		return "", fmt.Errorf("Failed to decode JWT header: %w", err)
	}

	payload, err := decodeSegment(parts[1])
	if err != nil {
		return "", fmt.Errorf("Failed to decode JWT payload: %w", err)
	}

	// Pretty print JSON
	headerJSON, _ := json.MarshalIndent(header, "", "  ")
	payloadJSON, _ := json.MarshalIndent(payload, "", "  ")

	result := fmt.Sprintf("Header:\n%s\n\nPayload:\n%s\n", string(headerJSON), string(payloadJSON))
	return result, nil
}

func main() {
	// Flags
	inputFile := flag.String("f", "", "Input file")
	outputFile := flag.String("o", "", "Output file")
	// decodeFlag := flag.Bool("d", false, "Decode Unicode (default)")
	encodeFlag := flag.Bool("e", false, "Encode to Unicode")
	jsonFlag := flag.Bool("json", false, "Decode string values from JSON")
	urlEncode := flag.Bool("url-encode", false, "URL encode input")
	urlDecode := flag.Bool("url-decode", false, "URL decode input")
	b64Encode := flag.Bool("b64-encode", false, "Base64 encode input")
	b64Decode := flag.Bool("b64-decode", false, "Base64 decode input")
	jwtDecode := flag.Bool("jwt-decode", false, "Decode JWT token")

	flag.Parse()

	// Read input
	var input string
	if *inputFile != "" {
		content, err := readFile(*inputFile)
		if err != nil {
			fmt.Println("File read error:", err)
			return
		}
		input = strings.TrimSpace(content)
	} else if len(flag.Args()) > 0 {
		input = strings.Join(flag.Args(), " ")
	} else {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			data, _ := ioutil.ReadAll(os.Stdin)
			input = strings.TrimSpace(string(data))
		} else {
			fmt.Print("Enter text: ")
			reader := bufio.NewReader(os.Stdin)
			in, _ := reader.ReadString('\n')
			input = strings.TrimSpace(in)
		}
	}

	var output string
	var err error

	switch {
	case *jwtDecode:
		output, err = decodeJWT(input)
	case *encodeFlag:
		output = encodeUnicode(input)
	case *jsonFlag:
		output, err = decodeJSON(input)
	case *urlEncode:
		output = url.QueryEscape(input)
	case *urlDecode:
		output, err = url.QueryUnescape(input)
	case *b64Encode:
		output = base64.StdEncoding.EncodeToString([]byte(input))
	case *b64Decode:
		var decoded []byte
		decoded, err = base64.StdEncoding.DecodeString(input)
		output = string(decoded)
	default:
		output, err = decodeUnicode(input)
	}

	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	if *outputFile != "" {
		if err := writeFile(*outputFile, output); err != nil {
			fmt.Println("Write output file error:", err)
			return
		}
		fmt.Println("Saved to:", *outputFile)
		return
	}

	fmt.Print(output)
}
