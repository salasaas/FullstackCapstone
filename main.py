#!/usr/bin/env python3
#Symohn Alasa-as, Tevanah Charlemagne, Eric Deshield, Adrian Pineda
#Fullstack Academy Final Project
#Project Ultra
import sys
import hashlib
import base64
import tkinter as tk


###############################################################################################
##################################SYMOHN ALASA-AS##############################################
class CaesarCipher:
    def __init__(self, key):
        self.key = key

    def encrypt(self, plain_text):
        cipher_text = ""

        for _ in plain_text:
            if _.isalpha():
                if _.isupper():
                    cipher_text += chr((ord(_) + self.key - 65) % 26 + 65)
                else:
                    cipher_text += chr((ord(_) + self.key - 97) % 26 + 97)
            elif _.isnumeric():
                cipher_text += chr((ord(_) + self.key - 48) % 10 + 48)
            else:
                cipher_text += _
        
        return cipher_text

    def decrypt(self, cipher_text):
        plain_text = ""

        for _ in cipher_text:
            if _.isalpha():
                if _.isupper():
                    plain_text += chr((ord(_) - self.key - 65) % 26 + 65)
                else:
                    plain_text += chr((ord(_) - self.key - 97) % 26 + 97)
            elif _.isnumeric():
                plain_text += chr((ord(_) - self.key - 48) % 10 + 48)
            else:
                plain_text += _
        
        return plain_text

    def decrypt_bf(self, cipher_text):
        possible_text = []

        for i in self.key:
            plain_text = ""

            for _ in cipher_text:
                if _.isalpha():
                    if _.isupper():
                        plain_text += chr((ord(_) - i - 65) % 26 + 65)
                    else:
                        plain_text += chr((ord(_) - i - 97) % 26 + 97)
                elif _.isnumeric():
                    plain_text += chr((ord(_) - i - 48) % 10 + 48)
                else:
                    plain_text += _
                
            possible_text.append((plain_text, i))
        
        return possible_text

def caesar():
    options = [1, 2, 3]
    keys = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25]

    try:
        user_input = input("Enter MESSAGE to encrypt/decrypt: ")
    except:
        print("An Error occurred processing input.")

    print("\nCaesar Cipher Algorithm Options:")
    print("1. Encrypt Message")
    print("2. Decrypt Message")
    print("3. Brute Force Decryption")

    while True:
        try:
            option = int(input("\nEnter Number to Select Option: "))
            while option not in options:
                option = int(input("Invalid Entry! Enter options '1', '2', or '3': "))
            break
        except ValueError:
            print("Invalid input! Please enter a valid integer.")
    
    if option == 1 or option == 2:
        while True:
            try:
                key = int(input("\nEnter encryption/decryption KEY value: "))
                while key not in keys:
                    key = int(input("Invalid Entry! Enter a key value between 1 and 25."))
                break
            except ValueError:
                print("Invalid input! Please enter a valid integer.")
        
        cipher = CaesarCipher(key)
        
        if option == 1:
            result = cipher.encrypt(user_input)
        else:
            result = cipher.decrypt(user_input)

        print(f"\nMessage: {user_input}, Key: {key}")
        print("Processing.....................")
        print(f"\n{user_input} ==> {result}")

    else:
        cipher = CaesarCipher(keys)
        result = cipher.decrypt_bf(user_input)

        mid_column = max(len(str(_[0])) for _ in result)
        print(f"\n{'Key':<3}\t{'Text':<{mid_column}}")
        for i in range(len(result)):
            print(f"{result[i][1]:<3}\t{result[i][0]:<{mid_column}}")
##################################SYMOHN ALASA-AS##############################################
###############################################################################################

###############################################################################################
##################################ADRIAN PINEDA################################################
def hashes():
    options = [1,2]

    print(".---.  .---.    ____       .-'''-. .---.  .---.         .---.  .---.    ____     _______  .-./`)  _______  .-./`  ")
    print("|   |  |_ _|  .'  __ `.   / _     \|   |  |_ _|         |   |  |_ _|  .'  __ `. \  ____  \\ .-.')\  ____  \\ .-.') ")
    print("|   |  ( ' ) /   '  \  \ (`' )/`--'|   |  ( ' )         |   |  ( ' ) /   '  \  \| |    \ |/ `-' \| |    \ |/ `-' \ ")
    print("|   '-(_{;}_)|___|  /  |(_ o _).   |   '-(_{;}_)        |   '-(_{;}_)|___|  /  || |____/ / `-'`\"\"| |____/ / `-'`\"\" ")
    print("|      (_,_)    _.-`   | (_,_). '. |      (_,_)         |      (_,_)    _.-`   ||   _ _ '. .---. |   _ _ '. .---.  ")
    print("| _ _--.   | .'   _    |.---.  \  :| _ _--.   |         | _ _--.   | .'   _    ||  ( ' )  \|   | |  ( ' )  \|   |  ")
    print("|( ' ) |   | |  _( )_  |\    `-'  ||( ' ) |   |         |( ' ) |   | |  _( )_  || (_{;}_) ||   | | (_{;}_) ||   |  ")
    print("|_{;}_)|   | \ (_ o _) / \       / |_{;}_)|   |         |_{;}_)|   | \ (_ o _) /|  (_,_)  /|   | |  (_,_)  /|   |  ")
    print("|(_,_) '---'  '.(_,_).'   `-...-'  '(_,_) '---'         '(_,_) '---'  '.(_,_).' /_______.' '---' /_______.' '---'  ")

    print("Select an option:")
    print("1. Identify a hash")
    print("2. Generate a hash")

    while True:
        try:
            option = int(input("\nEnter Number to Select Option: "))
            while option not in options:
                option = int(input("Invalid Entry! Enter options '1' or '2': "))
            break
        except ValueError:
            print("Invalid input! Please enter a valid integer.")
    
    if option == 1:
        identify_hash()
    else:
        generate_hash()

def identify_hash():
        hash_input = input("Enter a Hash to Identify: ")
        if check_hash(hash_input, hashlib.md5):
            print(f"Hash Type: MD5, {hash_input}")
        elif check_hash(hash_input, hashlib.sha1):
            print(f"Hash Type: SHA1, {hash_input}")
        elif check_hash(hash_input, hashlib.sha256):
            print(f"Hash Type: SHA256, {hash_input}")
        else:
            print(f"Hash Type Unknown: {hash_input}")

def check_hash(hash, type):
    if len(hash) != type().digest_size * 2:
        return False
    
    try:
        int(hash, 16)
    except ValueError:
        return False

    return True

def generate_hash():
    hashes = [1,2,3]

    print("Select a hash algorithm:")
    print("1. MD5")
    print("2. SHA1")
    print("3. SHA256")

    while True:
        try:
            option = int(input("\nEnter Number to Select Hash Type: "))
            while option not in hashes:
                option = int(input("Invalid Entry! Enter options '1', '2', or '3': "))
            break
        except ValueError:
            print("Invalid input! Please enter a valid integer.")
    
    message = input("Enter a Value to Hash: ")
    
    if option == 1:
        hash_algo = hashlib.md5
        result = hash_converter(message, hash_algo)
        print(f"MD5, {message}:\n{result}")
    elif option == 2:
        hash_algo = hashlib.sha1
        result = hash_converter(message, hash_algo)
        print(f"SHA1, {message}:\n{result}")
    else:
        hash_algo = hashlib.sha256
        result = hash_converter(message, hash_algo)
        print(f"SHA256, {message}:\n{result}")

def hash_converter(m, ha):
    hash_obj = ha()
    hash_obj.update(m.encode())
    return hash_obj.hexdigest()
##################################ADRIAN PINEDA################################################
###############################################################################################

###############################################################################################
##################################Tevanah Charlemagne##########################################
class EncoderDecoder:
    def __init__(self, message):
        self.message = message

    def base64_encode(self):
        message_bytes = self.message.encode('ascii')
        base64_bytes = base64.b64encode(message_bytes)
        base64_message = base64_bytes.decode('ascii')
        return base64_message

    def base64_decode(self):
        base64_bytes = self.message.encode('ascii')
        message_bytes = base64.b64decode(base64_bytes)
        decoded = message_bytes.decode('ascii')
        return decoded

def encoding():
    encoding_types = [1,2]

    print("Select Option:")
    print("1. Encode Base64")
    print("2. Decode Base64")

    while True:
        try:
            option = int(input("\nEnter Number to Select Option: "))
            while option not in encoding_types:
                option = int(input("Invalid Entry! Enter options '1' or '2': "))
            break
        except ValueError:
            print("Invalid input! Please enter a valid integer.")

    try:
        message = input("Enter MESSAGE to encode/decode: ")
    except:
        print("An Error occurred processing input.")
    
    code = EncoderDecoder(message)
    
    if option == 1:
        result = code.base64_encode()
        print(f"Input: {message} ==> Base64: {result}")
    else:
        result = code.base64_decode()
        print(f"Base 64: {message} ==> Decoded Base64: {result}")
##################################Tevanah Charlemagne##########################################
###############################################################################################

def main(argv):
    tools = [1,2,3]

    print("Select tool: ")
    print("1. Hash Generator/Identifier")
    print("2. Encoding/Decoding Methods")
    print("3. Caesar Cipher Encrypter/Decrypter and Brute Force Decrypter")

    while True:
        try:
            option = int(input("\nEnter Number to Select Tool: "))
            while option not in tools:
                option = int(input("Invalid Entry! Enter options '1', '2', or '3': "))
            break
        except ValueError:
            print("Invalid input! Please enter a valid integer.")
    
    if option == 1:
        hashes()
    elif option == 2:
        encoding()
    else:
        caesar()


if __name__ == "__main__":
    main(sys.argv[1:])