"""
This script is so I can create a basic system for encrypting secrets using user
passwords as the key. It's a toy for testing cryptographic assumptions before
moving to a full implementation.

The final version will be something like this:

 - I run a website where you log in.
 - This website stores a hash of your password, as defined by Django (currently
   PBKDF2 with 20k iterations, this is nothing novel).
 - This website also allows you to encrypt a secret you type into a form, using
   your authentication password as the key.
 - When you log in again, we can verify that your login password is correct and
   we can decrypt your secret, displaying it to you.
 - When you are not logged in, we do not know your password (you have to trust
   us not to keep it) and thus cannot decrypt your secret.

The method for encrypting your secret is:

 1. Generate a key using a base64-encoded PBKDF2 hash of:
   - the user's password
   - a custom salt generated from `os.urandom`. (This is the method of
     generating random values that is [recommended by cryptography.io][1].)
   - 100,000 iterations are used (Django uses 20,000, but cryptography.io uses
     100,000)
 1. The result from that hash is used as the key for the Fernet symmetric
    encryption, which uses the OpenSSL library to complete AES in CBC mode with
    128-bit key for encryption and PKCS7 for padding.

The method for decryption is:

 1. When the user logs in, gather the salt from the database and the user's
    password from the sign-in form.
 1. Use those to re-generate the key for Fernet decryption of the secret.

So far so good. In the case of a our database being hacked, the following will
be available to the attacker:

 - The user's username and a PBKDF2 hash of their password, including the salt
   used in the hash, the number of iterations, and the algorithm (this is
   nothing new).
 - The salt used to generate an encryption key for their encrypted secret, the
   number of iterations, and the algorithm. BUT the user's password will not be
   available.
 - The encrypted secret.

Without the user's password, there is no way to generate a key for the encrypted
secret. Rainbow tables are not possible b/c a salt was used to generate the key.
Brute forcing is not possible because the key was stretched using 100,000 SHA2
iterations.

In the case that an attacker can access the server's memory, they will be able
to access secrets only for users that are presently logged in.

[1]: https://cryptography.io/en/latest/random-numbers/
"""

import base64
import os
import json
from cryptography.exceptions import InvalidKey
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

ITERATIONS = 100000  # Recommendation from cryptography.io.
ALGORITHM = 'pbkdf2_sha256'


def make_kdf(salt, iterations=ITERATIONS):
    """Make a key derivation formula"""
    return PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=str(salt),
        iterations=int(iterations),
        backend=default_backend(),
    )


# 0. Load up our user DB.
# user_db = {
#     'my-username': {
#         'pwd': '<algorithm>$<iterations>$<salt>$<hash>',
#         'secret': '<my-b64-encoded-secret>',
#         'secret_inits': '<algorithm>$<iterations>$<salt>',
#     }
# }
try:
    with open('user_db.json', 'rw') as user_db_file:
        user_db = json.load(user_db_file)
except IOError:
    print("No user DB, creating empty variable...")
    user_db = {}

# Get the user's auth
print("Welcome.\n")
login_user = raw_input("To begin, please tell me your user name: ")
login_pwd = raw_input("And now your login password: ")

if user_db.get(login_user) is not None:
    # If the user is already in our DB, check the password
    key_parts = user_db[login_user]['pwd'].split('$')
    kdf = make_kdf(key_parts[2], iterations=key_parts[1])

    try:
        kdf.verify(login_pwd, base64.b64decode(key_parts[3]))
        print("  Password accepted!")
    except InvalidKey:
        print("  Password failed. Start over!")
        exit()

    # Password is OK. Decrypt the user's secret and print it out
    secret_inits = user_db[login_user]['secret_inits'].split('$')
    kdf = make_kdf(secret_inits[2], iterations=secret_inits[1])

    key = base64.b64encode(kdf.derive(login_pwd))

    # Key is the hash of the user's password
    f = Fernet(key)
    secret = f.decrypt(str(user_db[login_user]['secret']))
    print("  Your secret is: %s" % secret)


else:
    # New user, create a salt and store the values
    print("  New user: Adding to the database.")

    # Hash the user's password for authentication
    salt = base64.b64encode(os.urandom(12))
    kdf = make_kdf(salt)
    hashed_pwd = base64.b64encode(kdf.derive(login_pwd))
    user_db[login_user] = {
        'pwd': "%s$%d$%s$%s" % (ALGORITHM, ITERATIONS, salt, hashed_pwd),
    }

    secret = raw_input("  What's your secret: ")

    # Hash their password again using a different salt
    salt = base64.b64encode(os.urandom(12))
    kdf = make_kdf(salt)
    hashed_pwd_2 = base64.b64encode(kdf.derive(login_pwd))

    f = Fernet(hashed_pwd_2)
    user_db[login_user]['secret'] = f.encrypt(secret)

    # Do NOT include a hash of the user's password, as that is the key to the
    # encryption! Only store the salt, the algo and the number of iterations.
    user_db[login_user]['secret_inits'] = "%s$%d$%s" % (
        ALGORITHM,
        ITERATIONS,
        salt,
    )

    print("\nYour secret has been encrypted with a hash of your password as "
          "\nits key and has been added to the database. Run this program "
          "\nagain to extract your secret.")

# Finally, write out the values
with open('user_db.json', 'wr') as user_db_file:
    json.dump(
        user_db,
        user_db_file,
        sort_keys=True,
        indent=2,
    )
