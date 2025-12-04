# 🔐 Unicode & Security Encoding CLI Tool

A multi-purpose Go CLI tool for:

- Unicode encoding/decoding
- JSON string extraction & Unicode fixing
- URL & Base64 encoding/decoding
- JWT decoding, signing, and verification (HS256)
- Hash generation (MD5 / SHA1 / SHA256 / SHA512)
- AES-256-CBC encryption/decryption with PKCS7 padding

---

## 🚀 Features

### 🔡 Text & Data Encoding Tools

✔ Decode & encode Unicode `\uXXXX`  
✔ Decode JSON string values containing escaped Unicode  
✔ URL encode/decode  
✔ Base64 encode/decode

### 🔐 Security Tools

✔ Decode JWT (header + payload)  
✔ Sign JWT (HS256)  
✔ Verify JWT (HS256)  
✔ Generate Hashes (MD5/SHA1/SHA256/SHA512)  
✔ Encrypt/Decrypt using AES-256-CBC + PKCS7 + Base64 output

### 🔧 CLI Input Support

✔ Read from file (`-f`)  
✔ Read stdin & pipeline  
✔ Output to file (`-o`)

---

## 📦 Requirements

- **Go 1.16 or newer**
- Works on **Linux, macOS, Windows**

---

## 🛠 Installation

### Build from source

```bash
go build -o unicode-tool main.go
```

This creates `unicode-tool` (or `unicode-tool.exe` on Windows).

---

## 📌 Usage

```bash
./unicode-tool [flags] [text]
```

If no input or file is provided, stdin or prompt input is used.

---

## 🧾 Flags

### 📌 General Encoding Flags

| Flag           | Description                         |
| -------------- | ----------------------------------- |
| `-f <file>`    | Input file                          |
| `-o <file>`    | Save output to file                 |
| `-e`           | Encode string to Unicode (`\uXXXX`) |
| `-json`        | Decode JSON strings with Unicode    |
| `--url-encode` | URL encode input                    |
| `--url-decode` | URL decode input                    |
| `--b64-encode` | Base64 encode                       |
| `--b64-decode` | Base64 decode                       |

---

### 🔑 JWT Flags

| Flag                 | Description                           |
| -------------------- | ------------------------------------- |
| `--jwt-decode`       | Decode JWT (header + payload)         |
| `--jwt-sign`         | Sign JWT (HS256)                      |
| `--jwt-verify`       | Verify JWT (HS256)                    |
| `--jwt-key <secret>` | Secret key used for signing/verifying |

---

### 🧮 Hash Functions

| Flag       |
| ---------- |
| `--md5`    |
| `--sha1`   |
| `--sha256` |
| `--sha512` |

---

### 🔐 AES Encryption / Decryption

| Flag                     | Description                                |
| ------------------------ | ------------------------------------------ |
| `--aes-enc`              | AES-256-CBC encrypt (Base64 output)        |
| `--aes-dec`              | AES-256-CBC decrypt (expects Base64 input) |
| `--aes-key <passphrase>` | Passphrase to derive AES-256 key           |

---

## 🧪 Examples

### 🔡 Decode Unicode escapes

```bash
./unicode-tool '\u0646\u0627\u0645 \u06a9\u0627\u0631\u0628\u0631\u06cc'
```

### 🔡 Encode Unicode escapes

```bash
./unicode-tool -e "نام کاربری"
```

### 🧾 Decode JSON Unicode strings

```bash
./unicode-tool -json '{"name":"\u0646\u0627\u0645"}'
```

### 🌐 URL encode

```bash
./unicode-tool --url-encode "سلام دنیا"
```

### 🌐 URL decode

```bash
./unicode-tool --url-decode "%D8%B3%D9%84%D8%A7%D9%85"
```

### 🔐 Base64 encode

```bash
./unicode-tool --b64-encode "password123"
```

### 🔓 Base64 decode

```bash
./unicode-tool --b64-decode "cGFzc3dvcmQxMjM="
```

### 🕵️ JWT decode

```bash
./unicode-tool --jwt-decode eyJhbGciOiJIUzI1NiIsInR5...
```

### ✍️ Sign JWT

```bash
./unicode-tool --jwt-sign '{"user":"john"}' --jwt-key secret123
```

### 🔍 Verify JWT

```bash
./unicode-tool --jwt-verify <token> --jwt-key secret123
```

### 🔒 AES Encrypt

```bash
./unicode-tool --aes-enc "Sensitive data" --aes-key mypassword
```

### 🔓 AES Decrypt

```bash
./unicode-tool --aes-dec "<base64_ciphertext>" --aes-key mypassword
```

### 🧮 Generate SHA256 Hash

```bash
./unicode-tool --sha256 "admin123"
```

### ⛓ Use pipeline

```bash
echo "%D8%B3%D9%84%D8%A7%D9%85" | ./unicode-tool --url-decode
```

---

## 📄 License

MIT License

---
