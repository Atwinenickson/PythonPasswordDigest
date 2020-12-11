import os
import pytz
import base64
import requests
from datetime import datetime
from hashlib import sha1
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup
import string
import json
import sys
from base64 import b64encode
#import M2Crypto
#from M2crypto import BIO, RSA

# Password_Digest = Base64(SHA-1(Nonce + Created + SHA1(Password)))

import Crypto
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
import random


class SoapClientBuilder_v2():
    """Class to handle building of the soap client
    """
    
    def __init__(self, wsdl, username, password):
        """Constructor

        Arguments:
            wsdl {str} -- WSDL url
            username {str} -- Username
            password {str} -- Password
        """
        self.wsdl = wsdl
        self.username = username
        self.password = password
    
    @classmethod
    def generatenonce_asbytes(self):
        """Generates Nonce as bytes
        """
        return os.urandom(16)

    def generatenonce_asbytearray(self):
        """Generates Nonce as bytearray
        """
        return bytearray(os.urandom(16))

    def create_requesttimestamp(self):
        """Creates timestamp to be used when
        sending request
        """
        utc_now = pytz.utc.localize(datetime.utcnow())
        eat_now = utc_now.astimezone(pytz.timezone('Africa/Kampala'))
        eat_time = eat_now.isoformat()

        timestamp = '{}+03:00'.format(eat_time[:-9])

        return timestamp

    @classmethod
    def create_timestamp(self):
        """Create timestamp
        """
        utc_now = pytz.utc.localize(datetime.utcnow())
        eat_now = utc_now.astimezone(pytz.timezone('Africa/Kampala'))
        eat_time = eat_now.isoformat()

        return eat_time

    def timestamp_forrequest(self, timestamp):
        """Formats timestamp for request

        Arguments:
            timestamp {string} -- Timestamp in the format
            to be sent with the request as Created
        """
        return '{}+03:00'.format(timestamp[:-9])

    @classmethod
    def timestamp_fordigest(self, timestamp):
        """Formates timestamp for digest

        Arguments:
            timestamp {string} -- Timestamp in the format
            to be used to creat password digest
        """
        return '{}+0300'.format(timestamp[:-9])

    @classmethod
    def gettimestamp_asbytes(self, timestamp):
        """Gets timestamp as bytes

        Arguments:
            timestamp {str} -- Timestamp
        """
        return timestamp.encode('utf-8')

    @classmethod
    def hashpassword_withdigest(self):
        """Hash password using sha1.digest() function
        """
        return sha1(self.password.encode('utf-8')).digest()

    def generatedigest_withbytesvalues(nonce, created, password_hash):
        """Generates password digest using sha1.digest
        function

        Arguments:
            nonce {bytes} -- Nonce
            created {bytes} -- Created
            password_hash {bytes} -- Hashed password
        """
        combined_bytearray = bytearray()

        combined_bytearray.extend(nonce)
        combined_bytearray.extend(created)
        combined_bytearray.extend(password_hash)

        encoded_digest = sha1(combined_bytearray).digest()

        password_digest = base64.b64encode(encoded_digest)

        return password_digest.decode('utf-8')
        
    def build_change_password_request(self, new_password):
        """
        Build request to change password

        """
        username = self.username

        nonce_bytes = self.generatenonce_asbytes()
        nonce = base64.b64encode(nonce_bytes).decode('utf-8')

        timestamp = self.create_timestamp()
        created_digest = self.timestamp_fordigest(timestamp)
        created_digest_bytes = self.gettimestamp_asbytes(created_digest)

        passwordhash_bytes = self.hashpassword_withdigest()

        password_digest = self.generatedigest_withbytesvalues(nonce_bytes, created_digest_bytes, passwordhash_bytes)

        created_request = self.timestamp_forrequest(timestamp)

        body = '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:fac="http://facade.server.pilatus.thirdparty.tidis.muehlbauer.de/" xmlns:wsse= "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"> <soapenv:Header> <wsse:UsernameToken> <wsse:Username>{0}</wsse:Username> <wsse:Password Type="PasswordDigest">{1}</wsse:Password> <wsse:Nonce>{2}</wsse:Nonce> <wsse:Created>{3}</wsse:Created> </wsse:UsernameToken> </soapenv:Header> <soapenv:Body> <fac:changePassword>  <!--Optional:--> <request> <!--Optional:--> <newPassword>{4}</newPassword> </request> </fac:changePassword> </soapenv:Body> </soapenv:Envelope>'.format(
            username,
            password_digest, 
            nonce,
            created_request,
            new_password
        )


        return body

    def send_request_new_password(self, body):
        """Sends the SOAP request
        """        
        url = self.wsdl
        headers = {'Content-Type':'text/xml'}
        response = requests.post(url, data=body, headers=headers)
        
        return response.content.decode('utf-8')
     

    def parse_change_password_request(self, response):
        """Parses the response returned from the API request
        
        Arguments:
            response {string} -- API response

        Returns:
            tuple (transactionStatus, cardStatus, matchingStatus)
        """
        soup = BeautifulSoup(response, 'lxml-xml')

        if soup.find_all('transactionStatus')[1].string == 'Ok':
            return soup.find_all('transactionStatus')[1].string, None
        else:
            return soup.find_all('transactionStatus')[1].string, soup.message.string



    def password_generator(self):
        """Generates password.
        """
        #special_characters = '!@%/()=?+.-_'
        special_characters = '@!#_+$%*'
        password_list = (
            [
                random.choice(special_characters),
                random.choice(string.digits),
                random.choice(string.ascii_lowercase),
                random.choice(string.ascii_uppercase)
            ]
            +
            [
                random.choice(
                    string.digits +
                    string.ascii_lowercase +
                    string.ascii_uppercase +
                    special_characters +
                    string.digits
                )
                for i in range(5)
            ]
        )

        random.shuffle(password_list)
        password = ''.join(password_list)
        return password
    

    def encrypt_pwd_with_PyCrypto(self,raw_password, certificate_file_path):
        """
        Encrypts raw pasword.

        """
        message = raw_password.encode('utf-8')
 
    
        the_pubkey = RSA.importKey(open(certificate_file_path, 'r').read())
        cipher = PKCS1_v1_5.new(the_pubkey)

        ciphertext = cipher.encrypt(message)

        pwd_to_base_64 = base64.b64encode(ciphertext).decode('utf-8')
        #pwd_to_base_64 = base64.b64encode(ciphertext)

        
        return pwd_to_base_64



password1 = 'NITA123'
s = SoapClientBuilder_v2
nonce_byte_arry = s.generatenonce_asbytes()
print('-----------Nonce----------')
token = b64encode(nonce_byte_arry).decode('utf-8')
print(token)
print('--------Nonce------------------')


print('-----------Created time----------')
createdTime = SoapClientBuilder_v2.create_timestamp()
created_byte = SoapClientBuilder_v2.timestamp_fordigest(createdTime)
created_byte66666 = bytes(createdTime, 'utf-8')
created_byte_arry = SoapClientBuilder_v2.gettimestamp_asbytes(created_byte)
t = base64.b64encode(bytes(str(created_byte_arry), 'utf-8'))
print(created_byte)
print('-----------Created time----------')


password1 = 'NITA123'

s.password = password1

password_hash = s.hashpassword_withdigest()

# k = sha1(password1.encode('utf-8'))
# PWSHA1 = k.digest() 
# print(PWSHA1)


# import hashlib
# PWSHA = hashlib.sha1()    
# PWSHA.update(password1.encode('utf-8'))    
# PWSHA2 = PWSHA.digest() 
# print(PWSHA2)

print('-----------Password_Digest with Conc Value----------')
concValue = s.generatedigest_withbytesvalues(nonce_byte_arry,created_byte_arry,password_hash)
print(concValue)
print('-----------Password_Digest with Conc Value----------')

# print('...........................')
# CONCAT = nonce_byte_arry + created_byte_arry + password_hash

# CSHA = sha1()

# CSHA.update(CONCAT)

# PWDIGEST = base64.b64encode(CSHA.digest())

# print(type(PWDIGEST), PWDIGEST)
# print('.................................')




# from base64 import b64encode
# random_bytes = os.urandom(16)
# print(random_bytes)
# token = b64encode(random_bytes).decode('utf-8')
# print(len(token))
# print(token)