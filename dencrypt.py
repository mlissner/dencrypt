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
