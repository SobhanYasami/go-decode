package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// ----------------- Utility functions -----------------

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

// Read file content as string (using os.ReadFile)
func readFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	return string(data), err
}

// Write string content to file (using os.WriteFile)
func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0644)
}

// ----------------- JWT decode (existing) -----------------

// Decode JWT token parts and pretty print
func decodeJWT(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("Invalid JWT token format")
	}

	decodeSegment := func(seg string) (map[string]interface{}, error) {
		// Add padding if missing (for standard URLEncoding)
		if l := len(seg) % 4; l != 0 {
			seg += strings.Repeat("=", 4-l)
		}
		data, err := base64.URLEncoding.DecodeString(seg)
		if err != nil {
			// try RawURLEncoding
			data, err = base64.RawURLEncoding.DecodeString(seg)
			if err != nil {
				return nil, err
			}
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

// ----------------- Hash functions -----------------

func hashMD5(input string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(input)))
}
func hashSHA1(input string) string {
	return fmt.Sprintf("%x", sha1.Sum([]byte(input)))
}
func hashSHA256(input string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(input)))
}
func hashSHA512(input string) string {
	return fmt.Sprintf("%x", sha512.Sum512([]byte(input)))
}

// ----------------- JWT sign & verify (HS256) -----------------
// Supports HS256 (HMAC-SHA256). Input for signing should be a JSON payload (object or string).
// Usage:
//   - To sign: provide payload (file/arg/stdin) and --jwt-sign --jwt-key <secret>
//   - To verify: provide token and --jwt-verify --jwt-key <secret>

func jwtSignHS256(payloadInput string, key string) (string, error) {
	// header
	header := map[string]interface{}{
		"alg": "HS256",
		"typ": "JWT",
	}
	hb, _ := json.Marshal(header)

	// Determine if payloadInput is raw JSON - try to parse; if parse fails, treat as plain string
	var payloadObj interface{}
	if err := json.Unmarshal([]byte(payloadInput), &payloadObj); err == nil {
		// pretty ensure canonical JSON by re-marshalling
		pb, _ := json.Marshal(payloadObj)
		return signSegments(hb, pb, []byte(key))
	}
	// not JSON — treat as string payload (wrap as JSON string)
	pb, _ := json.Marshal(payloadInput)
	return signSegments(hb, pb, []byte(key))
}

func signSegments(headerJSON, payloadJSON, key []byte) (string, error) {
	enc := base64.RawURLEncoding
	hEnc := enc.EncodeToString(headerJSON)
	pEnc := enc.EncodeToString(payloadJSON)
	signingInput := hEnc + "." + pEnc

	mac := hmac.New(sha256.New, key)
	if _, err := mac.Write([]byte(signingInput)); err != nil {
		return "", err
	}
	sig := mac.Sum(nil)
	sEnc := enc.EncodeToString(sig)
	return signingInput + "." + sEnc, nil
}

func jwtVerifyHS256(token string, key string) (bool, string, string, error) {
	// returns (valid, headerJSON, payloadJSON, err)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false, "", "", fmt.Errorf("JWT must have 3 parts")
	}
	// enc := base64.RawURLEncoding

	hPart, pPart, sPart := parts[0], parts[1], parts[2]
	signingInput := hPart + "." + pPart

	// calculate expected signature
	mac := hmac.New(sha256.New, []byte(key))
	if _, err := mac.Write([]byte(signingInput)); err != nil {
		return false, "", "", err
	}
	expected := mac.Sum(nil)

	// decode provided signature (try RawURLEncoding and URLEncoding with padding)
	var providedSig []byte
	var err error
	providedSig, err = base64.RawURLEncoding.DecodeString(sPart)
	if err != nil {
		// try with padding
		if l := len(sPart) % 4; l != 0 {
			sPart += strings.Repeat("=", 4-l)
		}
		providedSig, err = base64.URLEncoding.DecodeString(sPart)
		if err != nil {
			return false, "", "", fmt.Errorf("failed to decode signature: %w", err)
		}
	}

	valid := hmac.Equal(expected, providedSig)

	// decode header & payload for returning
	hdrBytes, err := base64.RawURLEncoding.DecodeString(hPart)
	if err != nil {
		// try padded
		if l := len(hPart) % 4; l != 0 {
			hPart += strings.Repeat("=", 4-l)
		}
		hdrBytes, _ = base64.URLEncoding.DecodeString(hPart)
	}
	plBytes, err2 := base64.RawURLEncoding.DecodeString(pPart)
	if err2 != nil {
		if l := len(pPart) % 4; l != 0 {
			pPart += strings.Repeat("=", 4-l)
		}
		plBytes, _ = base64.URLEncoding.DecodeString(pPart)
	}

	return valid, string(hdrBytes), string(plBytes), nil
}

// ----------------- AES encryption/decryption (AES-256-CBC + PKCS7) -----------------
// aesKey input is a passphrase; we derive a 32-byte key via SHA256(passphrase).
// AES output format: base64( iv || ciphertext )
// For decryption, input is base64(iv||ciphertext)

func deriveAESKey(passphrase string) []byte {
	sum := sha256.Sum256([]byte(passphrase))
	return sum[:]
}

func pkcs7Pad(b []byte, blockSize int) []byte {
	padLen := blockSize - len(b)%blockSize
	pad := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(b, pad...)
}

func pkcs7Unpad(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("invalid padding size")
	}
	padLen := int(b[len(b)-1])
	if padLen == 0 || padLen > len(b) {
		return nil, fmt.Errorf("invalid padding")
	}
	for i := len(b) - padLen; i < len(b); i++ {
		if b[i] != byte(padLen) {
			return nil, fmt.Errorf("invalid padding")
		}
	}
	return b[:len(b)-padLen], nil
}

func aesEncryptBase64(plaintext []byte, passphrase string) (string, error) {
	key := deriveAESKey(passphrase)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	padded := pkcs7Pad(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)

	out := append(iv, ciphertext...)
	return base64.StdEncoding.EncodeToString(out), nil
}

func aesDecryptBase64(b64 string, passphrase string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return nil, err
	}
	if len(raw) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	iv := raw[:aes.BlockSize]
	ct := raw[aes.BlockSize:]
	key := deriveAESKey(passphrase)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ct)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of the block size")
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	plainPadded := make([]byte, len(ct))
	mode.CryptBlocks(plainPadded, ct)
	return pkcs7Unpad(plainPadded)
}

// ----------------- main -----------------

func main() {
	// Flags
	inputFile := flag.String("f", "", "Input file")
	outputFile := flag.String("o", "", "Output file")
	encodeFlag := flag.Bool("e", false, "Encode to Unicode")
	jsonFlag := flag.Bool("json", false, "Decode string values from JSON")
	urlEncode := flag.Bool("url-encode", false, "URL encode input")
	urlDecode := flag.Bool("url-decode", false, "URL decode input")
	b64Encode := flag.Bool("b64-encode", false, "Base64 encode input")
	b64Decode := flag.Bool("b64-decode", false, "Base64 decode input")
	jwtDecode := flag.Bool("jwt-decode", false, "Decode JWT token")
	// hashing
	md5Flag := flag.Bool("md5", false, "Generate MD5 hash")
	sha1Flag := flag.Bool("sha1", false, "Generate SHA1 hash")
	sha256Flag := flag.Bool("sha256", false, "Generate SHA256 hash")
	sha512Flag := flag.Bool("sha512", false, "Generate SHA512 hash")

	// New JWT signer/verifier flags
	jwtSign := flag.Bool("jwt-sign", false, "Sign payload as JWT (HS256). Input is payload (JSON or string). Requires --jwt-key")
	jwtVerify := flag.Bool("jwt-verify", false, "Verify JWT token (HS256). Requires --jwt-key")
	jwtKey := flag.String("jwt-key", "", "Key/secret for JWT sign/verify (HS256)")

	// AES flags
	aesEnc := flag.Bool("aes-enc", false, "AES-256-CBC encrypt input. Requires --aes-key (passphrase)")
	aesDec := flag.Bool("aes-dec", false, "AES-256-CBC decrypt input (expects base64 iv||ciphertext). Requires --aes-key")
	aesKey := flag.String("aes-key", "", "AES passphrase (used to derive 32-byte key via SHA256)")

	flag.Parse()

	// Read input (file > args > stdin / prompt)
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
			data, err := io.ReadAll(os.Stdin)
			if err != nil {
				fmt.Println("Stdin read error:", err)
				return
			}
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

	// Priority: jwt-sign, jwt-verify, aes-enc, aes-dec, then other ops
	switch {
	case *jwtSign:
		if *jwtKey == "" {
			fmt.Println("Error: --jwt-key is required for --jwt-sign")
			return
		}
		output, err = jwtSignHS256(input, *jwtKey)
	case *jwtVerify:
		if *jwtKey == "" {
			fmt.Println("Error: --jwt-key is required for --jwt-verify")
			return
		}
		valid, hdr, pl, verr := jwtVerifyHS256(input, *jwtKey)
		if verr != nil {
			err = verr
		} else {
			output = fmt.Sprintf("valid: %v\n\nHeader:\n%s\n\nPayload:\n%s\n", valid, hdr, pl)
		}
	case *aesEnc:
		if *aesKey == "" {
			fmt.Println("Error: --aes-key is required for --aes-enc")
			return
		}
		var cipherB64 string
		cipherB64, err = aesEncryptBase64([]byte(input), *aesKey)
		output = cipherB64
	case *aesDec:
		if *aesKey == "" {
			fmt.Println("Error: --aes-key is required for --aes-dec")
			return
		}
		var plainBytes []byte
		plainBytes, err = aesDecryptBase64(input, *aesKey)
		if err == nil {
			output = string(plainBytes)
		}
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
	case *md5Flag:
		output = hashMD5(input)
	case *sha1Flag:
		output = hashSHA1(input)
	case *sha256Flag:
		output = hashSHA256(input)
	case *sha512Flag:
		output = hashSHA512(input)
	case *jwtDecode:
		output, err = decodeJWT(input)
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
