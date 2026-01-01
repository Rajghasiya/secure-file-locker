# Secure File Locker

Secure File Locker is a command-line encryption utility designed to protect files using the AES-256 encryption algorithm.  
The goal of this project is simple: provide reliable file protection while giving learners hands-on experience with real-world cryptography in C.

---

## Features

- AES-256-CBC encryption
- Password entered securely (hidden, not on command line)
- Works with any file type
- macOS & Linux supported
- Simple CLI usage
- Designed to be extended for learning

---

## Installation

### 1. Install required dependencies

**Linux**
```bash
sudo apt update
sudo apt install build-essential libssl-dev
```

**macOS**
```bash
brew install openssl@3
```

### 2. Clone the repository

```bash
git clone https://github.com/Rajghasiya/secure-file-locker.git
cd secure-file-locker
```

### 3. Build the program

**Standard build**
```bash
gcc src/main.c -lcrypto -o locker
```

**If macOS reports OpenSSL not found**
```bash
gcc src/main.c \
-I$(brew --prefix openssl@3)/include \
-L$(brew --prefix openssl@3)/lib \
-lcrypto -o locker
```

## Usage

**Encrypt**
```bash
./locker enc file.txt
```

**Decrypt**
```bash
./locker dec file.txt
```

You will be prompted for the password (it will not be shown while typing).

## Notes

	•	Encryption and decryption require the same password
	•	Lost passwords cannot be recovered
	•	Always test with sample files first before encrypting important data

## Disclaimer

This project is intended strictly for educational and learning purposes.
It should not be considered a production-grade security solution without proper review, testing, and professional security auditing.

## Credits

Developed as part of a learning project.
Contributions, improvements, and suggestions are welcome.