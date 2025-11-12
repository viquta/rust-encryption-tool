# Rust Encryption/Decryption Program

A simple command-line tool for encrypting and decrypting messages using XOR cipher with Base64 encoding.

## Features

- 🔒 XOR cipher encryption/decryption
- 📝 Base64 encoding for safe text representation
- ✨ User-friendly interactive menu
- ✅ Input validation and error handling
- 🔄 Continuous operation mode (encrypt/decrypt multiple messages)

## How It Works

The program uses XOR (exclusive OR) cipher, where the same operation is used for both encryption and decryption. This works because XOR is its own inverse: `(data ⊕ key) ⊕ key = data`.

Encrypted messages are encoded in Base64 format for easy copying and sharing.

## Usage

1. **Build and run:**
   ```bash
   cargo run
   ```

2. **Choose an option:**
   - `E` - Encrypt a message
   - `D` - Decrypt a message
   - `Q` - Quit

3. **For encryption:**
   - Enter your message
   - Enter an encryption key
   - Copy the Base64-encoded result

4. **For decryption:**
   - Paste the encrypted message (Base64)
   - Enter the same key used for encryption
   - View your decrypted message

## Example

```
What would you like to do?
  [E] Encrypt a message
  [D] Decrypt a message
  [Q] Quit

Your choice: E

--- ENCRYPTION MODE ---
Enter the message to encrypt:
> Hello, World!

Enter your encryption key:
> mySecretKey

✅ Encryption successful!
Encrypted message (Base64):
Ij0mJSI9NzUnOic=

💡 Tip: Save this encrypted text and use the same key to decrypt it later.
```

## Note

⚠️ **This is a simple educational project.** XOR cipher is not secure for real-world encryption. Use established cryptographic libraries for actual security needs.

## Requirements

- Rust (2021 edition or later)

## License

This project is open source and available for educational purposes.
