# Unicode & Encoding CLI Tool

A versatile CLI utility in Go for encoding/decoding Unicode escapes, JSON strings, URL encoding/decoding, Base64 encode/decode, JWT decoding, and more.

---

## Features

- Decode/encode Unicode `\uXXXX` escapes
- Decode JSON string values with Unicode escapes
- URL encode/decode
- Base64 encode/decode
- JWT decode (header and payload)
- Supports reading from file, stdin, or command line arguments
- Output to stdout or file

---

## Requirements

- Go 1.16 or newer installed
- Compatible with Linux, macOS, Windows

---

## Installation

### Build from source

Clone the repo (or copy code), then:

```bash
go build -o unicode-tool unicode-tool.go
```

This will create an executable `unicode-tool` (or `unicode-tool.exe` on Windows).

---

## Usage

```bash
./unicode-tool [flags] [text]
```

If no input file or argument is provided, tool reads from stdin.

---

## Flags

| Flag           | Description                                           |
| -------------- | ----------------------------------------------------- |
| `-f`           | Input file                                            |
| `-o`           | Output file                                           |
| `-e`           | Encode string to Unicode escapes (`\uXXXX`)           |
| `-json`        | Decode string values from JSON (with Unicode escapes) |
| `--url-encode` | URL encode input                                      |
| `--url-decode` | URL decode input                                      |
| `--b64-encode` | Base64 encode input                                   |
| `--b64-decode` | Base64 decode input                                   |
| `--jwt-decode` | Decode JWT token (header & payload)                   |

---

## Examples

### Decode Unicode escapes

```bash
./unicode-tool '\u0646\u0627\u0645 \u06a9\u0627\u0631\u0628\u0631\u06cc'
```

### Encode to Unicode escapes

```bash
./unicode-tool -e "نام کاربری"
```

### Decode JSON string values

```bash
./unicode-tool -json '{"name":"\u0646\u0627\u0645"}'
```

### URL encode

```bash
./unicode-tool --url-encode "سلام دنیا"
```

### URL decode

```bash
./unicode-tool --url-decode "%D8%B3%D9%84%D8%A7%D9%85"
```

### Base64 encode

```bash
./unicode-tool --b64-encode "password123"
```

### Base64 decode

```bash
./unicode-tool --b64-decode "cGFzc3dvcmQxMjM="
```

### JWT decode

```bash
./unicode-tool --jwt-decode eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiam9obiJ9.signature
```

### Read input from file and save output to file

```bash
./unicode-tool -f input.txt --url-decode -o output.txt
```

### Use with pipe

```bash
echo "%D8%B3%D9%84%D8%A7%D9%85" | ./unicode-tool --url-decode
```

---

## License

MIT License

---

If you want, I can also help you with a script to **install it globally** or **package it** for your OS!
