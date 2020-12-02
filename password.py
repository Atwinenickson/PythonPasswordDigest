import base64
import hashlib
from datetime import  datetime

# Password_Digest = Base64(SHA-1(Nonce + Created + SHA1(Password)))    
now =  datetime.now()
print("Today's date:", now)

NONCE = "secretnonce10111"
TIMESTAMP = str(now)   
PASSWORD = "ATWINEVIRUS" 



PWSHA = hashlib.sha1()    
PWSHA.update(PASSWORD.encode('utf-8'))    
PWSHA1 = PWSHA.digest() 

TIMESTAMPB = TIMESTAMP.encode('utf8')

NONCEB = NONCE.encode('utf8')

CONCAT = NONCEB + TIMESTAMPB + PWSHA1

CSHA = hashlib.sha1()

CSHA.update(CONCAT)

PWDIGEST = base64.b64encode(CSHA.digest())

print(type(PWDIGEST), PWDIGEST)