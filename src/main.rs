/* XOR Cipher Implementation 
    Caution: This is a simple educational implementation and should not be used for secure applications.
*/

use std::io::{self, Write};
/*std is the standard library in Rust, providing essential functionality and types
io is a module within the standard library that deals with input and output operations
Write is a trait that provides methods for writing data to output streams*/


fn main() {
    println!("╔════════════════════════════════════════╗");
    println!("║   Encryption/Decryption Program       ║");
    println!("╚════════════════════════════════════════╝");
    println!();
    
    // Main loop
    loop {
        // Get user choice
        println!("What would you like to do?");
        println!("  [E] Encrypt a message");
        println!("  [D] Decrypt a message");
        println!("  [Q] Quit");
        print!("\nYour choice: ");
        io::stdout().flush().unwrap(); // Ensure prompt is displayed how? --> by flushing the output buffer immediately
        
        let mut choice = String::new();
        io::stdin().read_line(&mut choice).expect("Failed to read line");
        let choice = choice.trim().to_uppercase();
        
        match choice.as_str() {
            "E" => {
                println!("\n--- ENCRYPTION MODE ---");
                encrypt_mode(); //see the function below
            }
            "D" => {
                println!("\n--- DECRYPTION MODE ---");
                decrypt_mode(); //see the function below
            }
            "Q" => {
                println!("\nThank you for using the program. Goodbye!");
                break;
            }
            _ => {
                println!("\n❌ Invalid choice. Please enter E, D, or Q.\n");
                continue;
            }
        }
        
        println!("\n{}", "─".repeat(50)); //the repeat method creates a string by repeating the specified string a given number of times
        println!();
    }
}

//why i need this function?
//This function handles the encryption mode of the program
//It prompts the user for a message and a key, then 
//calls the cipher function to perform the encryption using XOR cipher,
fn encrypt_mode() {
    // Get message to encrypt
    println!("Enter the message to encrypt:");
    print!("> ");
    io::stdout().flush().unwrap();
    
    let mut message = String::new();
    io::stdin().read_line(&mut message).expect("Failed to read line");
    let message = message.trim();
    
    if message.is_empty() {
        println!("❌ Error: Message cannot be empty!");
        return;
    }
    
    // Get encryption key
    println!("\nEnter your encryption key:");
    print!("> ");
    io::stdout().flush().unwrap();
    
    let mut key = String::new();
    io::stdin().read_line(&mut key).expect("Failed to read line");
    let key = key.trim();
    
    if key.is_empty() {
        println!("❌ Error: Key cannot be empty!");
        return;
    }
    
    // Encrypt the message with cipher function: xor_cipher
    let encrypted = xor_cipher(message.as_bytes(), key);
    let encoded = base64_encode(&encrypted);
    
    println!("\n✅ Encryption successful!");
    println!("Encrypted message (Base64):");
    println!("{}", encoded);
    println!("\n💡 Tip: Save this encrypted text and use the same key to decrypt it later.");
}


// This function handles the decryption mode of the program
// It prompts the user for an encrypted message and a key,
// then calls the cipher function to perform the decryption using XOR cipher,
fn decrypt_mode() {
    // Get encrypted message
    println!("Enter the encrypted message (Base64):");
    print!("> ");
    io::stdout().flush().unwrap();
    
    let mut encrypted_text = String::new();
    io::stdin().read_line(&mut encrypted_text).expect("Failed to read line");
    let encrypted_text = encrypted_text.trim();
    
    if encrypted_text.is_empty() {
        println!("❌ Error: Encrypted message cannot be empty!");
        return;
    }
    
    // Get decryption key
    println!("\nEnter your decryption key:");
    print!("> ");
    io::stdout().flush().unwrap();
    
    let mut key = String::new();
    io::stdin().read_line(&mut key).expect("Failed to read line");
    let key = key.trim();
    
    if key.is_empty() {
        println!("❌ Error: Key cannot be empty!");
        return;
    }
    
    // Decode and decrypt with the same cipher function: xor_cipher
    match base64_decode(encrypted_text) {
        Ok(encrypted_bytes) => {
            let decrypted = xor_cipher(&encrypted_bytes, key);
            
            match String::from_utf8(decrypted) {
                Ok(message) => {
                    println!("\n✅ Decryption successful!");
                    println!("Decrypted message:");
                    println!("{}", message);
                }
                Err(_) => {
                    println!("❌ Error: Decryption failed. The result is not valid text.");
                    println!("💡 Tip: Make sure you're using the correct key.");
                }
            }
        }
        Err(e) => {
            println!("❌ Error: Invalid encrypted message format.");
            println!("   {}", e);
        }
    }
}

// XOR cipher - works for both encryption and decryption
// This is because XOR is its own inverse: (data ⊕ key) ⊕ key = data
fn xor_cipher(input: &[u8], key: &str) -> Vec<u8> {
    let mut result = Vec::new();
    let key_bytes = key.as_bytes();
    
    for (i, &byte) in input.iter().enumerate() {
        let key_byte = key_bytes[i % key_bytes.len()];
        result.push(byte ^ key_byte);
    }
    
    result
}

/*
Why XOR is its own inverse (encryption = decryption):
| x | k | x⊕k | (x⊕k)⊕k |
| - | - | --- | ------- |
| 0 | 0 | 0   | 0       |
| 0 | 1 | 1   | 0       |
| 1 | 0 | 1   | 1       |
| 1 | 1 | 0   | 1       |

Notice that the last column (x⊕k)⊕k equals the first column x.
This means: encrypt(encrypt(data, key), key) = data
*/

// Simple Base64 encoding
// Base64 works by converting 3 bytes (24 bits) into 4 characters (24 bits = 4 × 6 bits)
fn base64_encode(input: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    
    // Process input 3 bytes at a time
    // chunks(3) splits the input into groups of 3 bytes
    // Example: [72, 101, 108, 108, 111] becomes chunks: [72, 101, 108], [108, 111]
    for chunk in input.chunks(3) {
        let b1 = chunk[0];                           // First byte always exists
        let b2 = chunk.get(1).copied().unwrap_or(0); // Second byte might not exist (use 0 if missing)
        let b3 = chunk.get(2).copied().unwrap_or(0); // Third byte might not exist (use 0 if missing)
        
        // Take 3 bytes (24 bits) and split into 4 groups of 6 bits each
        // Each 6-bit group becomes one Base64 character
        result.push(CHARS[(b1 >> 2) as usize] as char);                         // First 6 bits of b1
        result.push(CHARS[(((b1 & 0x03) << 4) | (b2 >> 4)) as usize] as char); // Last 2 bits of b1 + first 4 bits of b2
        
        // If we had a second byte, encode it; otherwise use padding '='
        if chunk.len() > 1 {
            result.push(CHARS[(((b2 & 0x0F) << 2) | (b3 >> 6)) as usize] as char); // Last 4 bits of b2 + first 2 bits of b3
        } else {
            result.push('=');
        }
        
        // If we had a third byte, encode it; otherwise use padding '='
        if chunk.len() > 2 {
            result.push(CHARS[(b3 & 0x3F) as usize] as char); // Last 6 bits of b3
        } else {
            result.push('=');
        }
    }
    
    result
}

// Simple Base64 decoding
// Reverse of encoding: converts 4 Base64 characters back into 3 bytes
fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    let input = input.trim();
    
    // Base64 always outputs in groups of 4 characters
    if input.len() % 4 != 0 {
        return Err("Invalid Base64 length".to_string());
    }
    
    // Convert each Base64 character to its 6-bit value (0-63)
    let char_to_value = |c: char| -> Result<u8, String> {
        match c {
            'A'..='Z' => Ok((c as u8) - b'A'),      // A=0, B=1, ..., Z=25
            'a'..='z' => Ok((c as u8) - b'a' + 26), // a=26, b=27, ..., z=51
            '0'..='9' => Ok((c as u8) - b'0' + 52), // 0=52, 1=53, ..., 9=61
            '+' => Ok(62),
            '/' => Ok(63),
            '=' => Ok(0),                           // Padding character
            _ => Err(format!("Invalid Base64 character: {}", c)),
        }
    };
    
    let mut result = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    
    // Process 4 characters at a time
    // chunks(4) splits the Base64 string into groups of 4 characters
    // Example: "SGVsbG8=" becomes chunks: ['S','G','V','s'], ['b','G','8','=']
    for chunk in chars.chunks(4) {
        let b1 = char_to_value(chunk[0])?; // Each is a 6-bit value
        let b2 = char_to_value(chunk[1])?;
        let b3 = char_to_value(chunk[2])?;
        let b4 = char_to_value(chunk[3])?;
        
        // Combine 4 × 6-bit values back into 3 × 8-bit bytes
        result.push((b1 << 2) | (b2 >> 4)); // First byte: all of b1 + top 2 bits of b2
        
        // Only decode second byte if third character isn't padding
        if chunk[2] != '=' {
            result.push(((b2 & 0x0F) << 4) | (b3 >> 2)); // Second byte: bottom 4 bits of b2 + top 4 bits of b3
        }
        
        // Only decode third byte if fourth character isn't padding
        if chunk[3] != '=' {
            result.push(((b3 & 0x03) << 6) | b4); // Third byte: bottom 2 bits of b3 + all of b4
        }
    }
    
    Ok(result)
}