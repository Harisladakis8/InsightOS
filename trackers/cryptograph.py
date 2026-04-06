# Αντικατάσταση του Crypto με cryptography
# cryptog.py
from flask import Blueprint, request, jsonify
from flask_cors import CORS
import base64
import hashlib
import urllib.parse
import html
import binascii
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import secrets

app_crypto = Blueprint('crypto', __name__)

# ========== CRYPTO ROUTES ==========

@app_crypto.route('/process', methods=['POST'])
def crypto_process():
    try:
        data = request.json
        tool = data.get('tool')
        input_text = data.get('input', '')
        key = data.get('key', '')
        mode = data.get('mode', 'encode')
        
        print(f"[CRYPTO] Processing: {tool}, mode: {mode}")
        
        result = ""
        
        # ===== ENCODING/DECODING =====
        if tool == 'base64-encode':
            result = base64.b64encode(input_text.encode()).decode()
        elif tool == 'base64-decode':
            try:
                result = base64.b64decode(input_text).decode()
            except:
                result = "Invalid Base64 input"
        
        elif tool == 'hex-encode':
            result = binascii.hexlify(input_text.encode()).decode()
        elif tool == 'hex-decode':
            try:
                result = binascii.unhexlify(input_text).decode()
            except:
                result = "Invalid Hex input"
        
        elif tool == 'binary-encode':
            result = ' '.join(format(ord(c), '08b') for c in input_text)
        elif tool == 'binary-decode':
            try:
                binary_values = input_text.split()
                result = ''.join(chr(int(b, 2)) for b in binary_values)
            except:
                result = "Invalid Binary input"
        
        elif tool == 'url-encode':
            result = urllib.parse.quote(input_text)
        elif tool == 'url-decode':
            result = urllib.parse.unquote(input_text)
        
        elif tool == 'html-encode':
            result = html.escape(input_text)
        elif tool == 'html-decode':
            result = html.unescape(input_text)
        
        elif tool == 'base32':
            result = base64.b32encode(input_text.encode()).decode()
        elif tool == 'base58':
            # Simple Base58 implementation
            alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
            value = int.from_bytes(input_text.encode(), 'big')
            result = ''
            while value > 0:
                value, remainder = divmod(value, 58)
                result = alphabet[remainder] + result
            if not result:
                result = alphabet[0]
        
        # ===== CIPHERS =====
        elif tool == 'rot13':
            result = rot13_cipher(input_text)
        
        elif tool == 'caesar':
            shift = int(key) if key.isdigit() else 3
            if mode == 'decode':
                shift = -shift
            result = caesar_cipher(input_text, shift)
        
        elif tool == 'a1z26':
            if mode == 'decode':
                numbers = input_text.replace('-', ' ').split()
                chars = []
                for num in numbers:
                    if num.isdigit():
                        chars.append(chr(int(num) + 64))
                result = ''.join(chars)
            else:
                numbers = []
                for char in input_text.upper():
                    if 'A' <= char <= 'Z':
                        numbers.append(str(ord(char) - 64))
                result = '-'.join(numbers)
        
        elif tool == 'morse':
            result = morse_code(input_text, mode)
        
        elif tool == 'reverse':
            result = input_text[::-1]
        
        elif tool == 'atbash':
            result = atbash_cipher(input_text)
        
        elif tool == 'xor':
            if key:
                result = xor_cipher(input_text, key)
            else:
                result = "Key required for XOR"
        
        # ===== HASH FUNCTIONS =====
        elif tool == 'md5':
            result = hashlib.md5(input_text.encode()).hexdigest()
        elif tool == 'sha1':
            result = hashlib.sha1(input_text.encode()).hexdigest()
        elif tool == 'sha256':
            result = hashlib.sha256(input_text.encode()).hexdigest()
        elif tool == 'sha512':
            result = hashlib.sha512(input_text.encode()).hexdigest()
        elif tool == 'sha3-256':
            result = hashlib.sha3_256(input_text.encode()).hexdigest()
        elif tool == 'sha3-512':
            result = hashlib.sha3_512(input_text.encode()).hexdigest()
        
        # ===== SYMMETRIC ENCRYPTION =====
        elif tool == 'aes':
            result = symmetric_crypto_aes(input_text, key, mode)
        elif tool == 'des':
            result = symmetric_crypto_des(input_text, key, mode)
        elif tool == 'blowfish':
            result = symmetric_crypto_blowfish(input_text, key, mode)
        elif tool == 'rc4':
            result = symmetric_crypto_rc4(input_text, key, mode)
        
        # ===== ASCII CONVERTER =====
        elif tool == 'ascii':
            if mode == 'decode':
                try:
                    codes = input_text.split()
                    result = ''.join(chr(int(code)) for code in codes)
                except:
                    result = "Invalid ASCII codes"
            else:
                result = ' '.join(str(ord(c)) for c in input_text)
        
        else:
            result = f"Unknown tool: {tool}"
        
        return jsonify({
            'success': True,
            'result': result
        })
        
    except Exception as e:
        print(f"Crypto process error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

# ========== HELPER FUNCTIONS ==========

def rot13_cipher(text):
    result = ""
    for char in text:
        if 'a' <= char <= 'z':
            result += chr((ord(char) - ord('a') + 13) % 26 + ord('a'))
        elif 'A' <= char <= 'Z':
            result += chr((ord(char) - ord('A') + 13) % 26 + ord('A'))
        else:
            result += char
    return result

def caesar_cipher(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            shifted = (ord(char) - ascii_offset + shift) % 26
            result += chr(shifted + ascii_offset)
        else:
            result += char
    return result

def morse_code(text, mode):
    morse_dict = {
        'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.',
        'F': '..-.', 'G': '--.', 'H': '....', 'I': '..', 'J': '.---',
        'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---',
        'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-',
        'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--',
        'Z': '--..', '1': '.----', '2': '..---', '3': '...--',
        '4': '....-', '5': '.....', '6': '-....', '7': '--...',
        '8': '---..', '9': '----.', '0': '-----',
        '.': '.-.-.-', ',': '--..--', '?': '..--..', "'": '.----.',
        '!': '-.-.--', '/': '-..-.', '(': '-.--.', ')': '-.--.-',
        '&': '.-...', ':': '---...', ';': '-.-.-.', '=': '-...-',
        '+': '.-.-.', '-': '-....-', '_': '..--.-', '"': '.-..-.',
        '$': '...-..-', '@': '.--.-.', ' ': '/'
    }
    
    reverse_morse = {v: k for k, v in morse_dict.items()}
    
    if mode == 'decode':
        words = text.strip().split(' / ')
        result_words = []
        for word in words:
            chars = word.split()
            decoded_word = ''.join(reverse_morse.get(char, '?') for char in chars)
            result_words.append(decoded_word)
        return ' '.join(result_words)
    else:
        result = []
        for char in text.upper():
            if char in morse_dict:
                result.append(morse_dict[char])
            else:
                result.append('?')
        return ' '.join(result)

def atbash_cipher(text):
    result = ""
    for char in text:
        if 'a' <= char <= 'z':
            result += chr(ord('z') - (ord(char) - ord('a')))
        elif 'A' <= char <= 'Z':
            result += chr(ord('Z') - (ord(char) - ord('A')))
        else:
            result += char
    return result

def xor_cipher(text, key):
    result = ""
    key_length = len(key)
    for i, char in enumerate(text):
        key_char = key[i % key_length]
        result += chr(ord(char) ^ ord(key_char))
    return result

def symmetric_crypto_aes(text, key, mode):
    """AES encryption/decryption using cryptography module"""
    try:
        # Prepare key (AES requires 16, 24, or 32 bytes)
        key_bytes = key.ljust(32)[:32].encode()
        
        # Generate random IV
        iv = secrets.token_bytes(16)
        
        if mode == 'encrypt' or mode == 'encode':
            # Create cipher
            cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            
            # Pad the data
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(text.encode()) + padder.finalize()
            
            # Encrypt
            encrypted = encryptor.update(padded_data) + encryptor.finalize()
            
            # Return IV + encrypted data as base64
            combined = iv + encrypted
            return base64.b64encode(combined).decode()
            
        else:  # Decrypt
            # Decode base64
            combined = base64.b64decode(text)
            
            # Extract IV and encrypted data
            iv = combined[:16]
            encrypted = combined[16:]
            
            # Create cipher
            cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            
            # Decrypt
            decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()
            
            # Unpad
            unpadder = padding.PKCS7(128).unpadder()
            decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
            
            return decrypted.decode()
            
    except Exception as e:
        return f"Error: {str(e)}"

def symmetric_crypto_des(text, key, mode):
    """DES encryption/decryption"""
    try:
        # DES requires 8 byte key
        key_bytes = key.ljust(8)[:8].encode()
        
        # Generate random IV
        iv = secrets.token_bytes(8)
        
        if mode == 'encrypt' or mode == 'encode':
            cipher = Cipher(algorithms.TripleDES(key_bytes), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            
            padder = padding.PKCS7(64).padder()
            padded_data = padder.update(text.encode()) + padder.finalize()
            
            encrypted = encryptor.update(padded_data) + encryptor.finalize()
            
            combined = iv + encrypted
            return base64.b64encode(combined).decode()
            
        else:  # Decrypt
            combined = base64.b64decode(text)
            iv = combined[:8]
            encrypted = combined[8:]
            
            cipher = Cipher(algorithms.TripleDES(key_bytes), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            
            decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()
            
            unpadder = padding.PKCS7(64).unpadder()
            decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
            
            return decrypted.decode()
            
    except Exception as e:
        return f"Error: {str(e)}"

def symmetric_crypto_blowfish(text, key, mode):
    """Blowfish encryption/decryption"""
    try:
        # Blowfish key can be up to 56 bytes
        key_bytes = key.ljust(16)[:16].encode()
        
        # Generate random IV
        iv = secrets.token_bytes(8)
        
        if mode == 'encrypt' or mode == 'encode':
            cipher = Cipher(algorithms.Blowfish(key_bytes), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            
            padder = padding.PKCS7(64).padder()
            padded_data = padder.update(text.encode()) + padder.finalize()
            
            encrypted = encryptor.update(padded_data) + encryptor.finalize()
            
            combined = iv + encrypted
            return base64.b64encode(combined).decode()
            
        else:  # Decrypt
            combined = base64.b64decode(text)
            iv = combined[:8]
            encrypted = combined[8:]
            
            cipher = Cipher(algorithms.Blowfish(key_bytes), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            
            decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()
            
            unpadder = padding.PKCS7(64).unpadder()
            decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
            
            return decrypted.decode()
            
    except Exception as e:
        return f"Error: {str(e)}"

def symmetric_crypto_rc4(text, key, mode):
    """RC4 encryption/decryption (RC4 is symmetric)"""
    try:
        # Simple XOR-based RC4 simulation
        # Note: Real RC4 is not available in cryptography, so we use XOR as simulation
        key_bytes = key.encode()
        result = ""
        
        for i, char in enumerate(text):
            key_char = key_bytes[i % len(key_bytes)]
            result += chr(ord(char) ^ key_char)
        
        if mode == 'encrypt' or mode == 'encode':
            return base64.b64encode(result.encode()).decode()
        else:
            # For decryption, we expect base64 input
            decoded = base64.b64decode(text).decode()
            result = ""
            for i, char in enumerate(decoded):
                key_char = key_bytes[i % len(key_bytes)]
                result += chr(ord(char) ^ key_char)
            return result
            
    except Exception as e:
        return f"Error: {str(e)}"

# ========== OTHER ROUTES ==========

@app_crypto.route('/tools', methods=['GET'])
def list_tools():
    """List all available crypto tools"""
    tools = {
        'encoding': ['base64-encode', 'base64-decode', 'hex-encode', 'hex-decode', 
                    'binary-encode', 'binary-decode', 'url-encode', 'url-decode',
                    'html-encode', 'html-decode', 'base32', 'base58'],
        'ciphers': ['rot13', 'caesar', 'a1z26', 'morse', 'reverse', 'atbash', 'xor'],
        'hash': ['md5', 'sha1', 'sha256', 'sha512', 'sha3-256', 'sha3-512'],
        'encryption': ['aes', 'des', 'blowfish', 'rc4'],
        'analysis': ['ascii']
    }
    
    return jsonify({
        'success': True,
        'tools': tools
    })

@app_crypto.route('/test', methods=['GET'])
def test():
    return jsonify({'status': 'Crypto module working!'})