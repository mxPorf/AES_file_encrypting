import keyring

'''
@link: https://pypi.org/project/keyring/
'''

def main():
    #This can be run in a command line, the password will be stored for the user running that command line. 
    #So it is important to store the password for the user that will run the programs that use this password
    keyring.set_password('<system>', '<name>', '<password>')
    #If other users call this function to try to see the password, it will yield an error 
    print(keyring.get_password('<system>', '<name>')) 

if __name__ == '__main__':
    main()