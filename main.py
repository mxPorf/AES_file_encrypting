#!/usr/bin/python3
# -*- coding: utf8 -*-

#Author:              Porfirio Basaldua
#Email:               porfirioBasaldua@gmail.com
#Date of creation:    June 20th, 2020
#Version:             1.0
#License:   

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import hashlib
import os
from base64 import b64encode, b64decode


def encryptFile():
    '''
    @summary: Reads a text file and uses an AES cipher to encrypt the contents, this encrypted text
        is stored in a new file.
    
    @link:    https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html#cbc-mode
    '''
    '''
    Algorithm:
        1. Get password
        2. Hash password to obtain a 32-byte chain
        3. Generate chipher object
        4. Encrypt text
        5. Write new text to file
        6. Store IV, salt for decryption and to calculate the hash, respectively
    '''
    #Initialize constants and variables
    maxBlocks = 10                  #Arbitrary number, represents the maximum number of blocks to be held in memory
    inputFile = 'plain_text.txt'    #Name of the input file
    
    #In real situations, plain text password like this is not allowed.
    #You should use for example the python keyring library to safely store and retreive the password
    password = 'keep_this_string_secret'
    #Hash the password to abtain a 32 byte chain
    salt = os.urandom(16)#A byte array of length 16, the minimum length accepted for the hash function
#     Parameters for the scrypt function:
#     n — iterations count, usually 16384 or 2048.
#     r — block size, eg. 8.
#     p — parallelism factor (threads to run in parallel), usually 1.
#     password — the input password (must be sequence of bytes)
#     salt — securely generated random bytes
#     dklen — the length of the output key in bytes.
    hashPassword = hashlib.scrypt(bytearray(password, 'utf-8'), salt=salt, n=2048, r=16, p=1, dklen=32)
    #Generate the cipher object 
    cipher = AES.new(hashPassword, AES.MODE_CBC)
    #Get file size, will be needed to trim padding at decryption
    fileSize = os.path.getsize(inputFile)
    #This list will be used as buffer to write to the output file
    encryptedText = [b64encode(cipher.encrypt(fileSize.to_bytes(16, 'big'))).decode('utf-8'),
                      b64encode(cipher.iv).decode('utf-8'), 
                      b64encode(salt).decode('utf-8')]
    #Create the output file, overwritting if it already exists
    f = open('encrypted_text.txt', 'w')
    f.close()
    with open(inputFile, 'rb') as f:
        #Initialize variables in current scope
        block = f.read(AES.block_size)  #First block of data to enter the while loop 
        count = 0                       #Number of blocks of encrypted data in memory 
        while block:
            if len(block) == 0:
                break
            #Pad the block if it is the last one and it is not the length of an AES block
            if len(block) % AES.block_size != 0:
                block = pad(block, AES.block_size)
            #Encrypt the block
            encryptedData = cipher.encrypt(block)
            #Add the ASCII representation of the encrypted data to the memory buffer
            asciiData = b64encode(encryptedData).decode('utf-8')
            #ASCII data can be more easily shared, for example in JSON format over the web
            encryptedText.append(asciiData)
            #Write the buffer to the output file if the maximum size has been reached
            count += 1
            if count == maxBlocks:
                with open('encrypted_text.txt', 'a') as g:
                    g.writelines(encryptedText)
                encryptedText = []
                count = 0
            
            block = f.read(AES.block_size)
    #Write all remaining data to the output file. This gets executed whenever the number of blocks in the file
    #    is not a multiple of maxBlocks
    if encryptedText:
        with open('encrypted_text.txt', 'a') as f:
            f.writelines(encryptedText)
                
def decryptFile():
    '''
    @summary: Reads an encrypted file, decrypts its content and outputs this generated information to another file
    
    @link:  https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html#cbc-mode
    '''
    '''
    Algorithm:
        1. Read encrypted file
        2. Get original file size, Initialization Vector (iv) and salt from first bytes in file
        2. Generate cypher
        3. Decrypt blocks of data from file
        4. Write decoded data in another file
    '''
    with open('encrypted_text.txt', 'r') as f:
        #Initialize constants and variables used in this function
        blockSize = 24                  #The size of 16 bytes coded as ASCII characters
        maxBlocks = 32                  #Arbitrary number. Maximum blocks to hold in memory before writing to output file
        count = 0                       #Number of blocks currently in memory
        decryptedText = []              #Buffer to hold blocks of decrypted text and then write to a file
        outFile = 'decrypted_text.txt'  #Name of output file
        
        #Create the output file or overwrite if it exists
        newFile = open(outFile, 'w')
        newFile.close()
        #Get the original file size, it is used at the end to eliminate padding
        fileSize = b64decode(f.read(blockSize))
        #The initialization vector and salt used to generate the cipher. Must be the same used for encryption
        iv = b64decode(f.read(blockSize))
        salt = b64decode(f.read(blockSize))
        #The same password used in the encryption. Should be kept in a safe place.
        password = 'keep_this_string_secret'
        #The n and dklen parameters of the scrypt function must be the same used in the encryption
        hashPassword = hashlib.scrypt(bytearray(password, 'utf-8'), salt=salt, n=2048, r=16, p=1, dklen=32)
        cipher = AES.new(hashPassword, AES.MODE_CBC, iv)
        #Transform the file size to an integer
        fileSize = int.from_bytes(cipher.decrypt(fileSize), 'big')
        #Read the next bytes of the input file to enter while loop
        data = b64decode(f.read(blockSize))
        while data:
            #Decrypt the block
            decryptedData = cipher.decrypt(data)
            #Add the block as a string to the buffer
            decryptedText.append(decryptedData.decode('utf-8'))
            count += 1
            if count == maxBlocks:
                #Flush buffer if it reaches its maximum length 
                with open(outFile, 'a') as g:
                    g.writelines(decryptedText)
                decryptedText = []
                count = 0
            #Read next block, returns an empty string if the end of the file is reached
            data = b64decode(f.read(blockSize))
    #If there is still data to be written, output it to the file and take away the padding
    #Else only take away the padding
    if decryptedText:
        with open(outFile, 'a') as f:
            f.writelines(decryptedText)
            f.truncate(fileSize)
    else:
        with open(outFile, 'a') as f:
            f.truncate(fileSize)
            
def encryptString():
    '''
    @summary: Use AES to create an encrypted text given a key and raw data
    '''
    #In practice, this key cannot be written in the code
    key = b'sixteen byte key'
    data= b'The string to encode'
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data)
    print(ciphertext, tag)
    
def main():
    encryptFile()
    decryptFile()

if __name__ == '__main__':
    main()