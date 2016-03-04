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
