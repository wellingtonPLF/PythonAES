from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# ************************************************************************
def decrypt(key, encrypted_data):
    nonce = encrypted_data[:12] 
    ciphertext = encrypted_data[12:-16]
    tag = encrypted_data[-16:]

    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=backend)
    decryptor = cipher.decryptor()
    decryptor.authenticate_additional_data(b'') 
    plaintext = decryptor.update(ciphertext) + decryptor.finalize_with_tag(tag)

    return plaintext

def encrypt(key, plaintext):
    nonce = os.urandom(12)

    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag
    encrypted_data = nonce + ciphertext + tag

    return encrypted_data

def read_file(name):
    with open(name, 'r') as file:
        lines = file.readlines()
        lines = [line.strip() for line in lines]
        return lines

def write_file(name, array_list):
    with open(name, 'w') as file:
        for line in array_list:
            file.write(line + '\n')

# ************************************************************************
if __name__ == "__main__":

    print()
    print("* Setting configuration... ")
    print()
    username = input(">> username: ")
    password = input(">> password: ")
    print()

    key = f"{password}\n{username}"
    key = bytes(key, 'utf-8')
    index = 0

    while True:
        print("\n* selecione uma opção: \n")
        print("[1] - Encrypt data\n[2] - Decrypt data\n[3] - Exit\n")
        option = int(input("/:> "))

        if (option == 3):
            break

        while True:
            try:
                file_path = input("\n.Coloque o nome do arquivo(.extensão): ")
                if (file_path == ""):
                    break
                data = read_file(file_path)
                break
            except:
                print("\n============================================= \n    Something went wrong, try again...\n=============================================")
        try:
            if (option == 2):
                print("\n* selecione um tipo: \n")
                print("[1] - Tauri data\n[2] - Other\n")
                tipo = int(input("/:> "))
                
                decryted_list = []
                if (file_path != ""):
                    print("Decrypting...")
                for ciphertext in data:
                    index +=1
                    encrypt_data = bytes.fromhex(ciphertext)
                    plaintext = decrypt(key, encrypt_data)

                    if (tipo == 2):
                        result = plaintext.decode('utf-8').split("|")
                        print(f"""
                            **************** {result[0]} ****************** \n
                            username: {result[1]}
                            password: {result[2]}\n
                            ******************************************
                        """) 
                        decryted_list.append(f"{result[0]} | {result[1]} | {result[2]}")
                        if (len(decryted_list) > 0):
                            write_file(file_path, decryted_list)
                    else:
                        result = plaintext.decode('utf-8').split("\n")
                        print(f"""
                            **************** Auth {index} ****************** \n
                            username: {result[0]}
                            password: {result[1]}\n
                            ******************************************
                        """) 
                    
            elif (option == 1):
                if (file_path != ""):
                    print("Encrypting...")

                content = list(filter(lambda x: x != '', data))
                array = []
                for credential in content:
                    encrypted_data = encrypt(key, credential.encode())
                    array.append(encrypted_data.hex())
                if (len(array) > 0):
                    write_file(file_path, array)
        except Exception as e:
            print(f"\nError! {e}")

# ************************************************************************