# install streamlit: pip install streamlit
# run: stramlit run app.py
import hashlib
import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import binascii
import streamlit as st
import os

# Define function for symmetric encryption
def symmetric_encryption():
    st.write("## Advanced Encryption Standard (AES)")
    st.write("### Discussion:")
    st.write("The Advanced Encryption Standard (AES) is a symmetric encryption algorithm that has been widely adopted as a secure and efficient cryptographic standard. It supports key sizes of 128, 192, and 256 bits and is considered highly secure against various cryptographic attacks.")
    st.write("### Application:")

    def generate_key():
        key = os.urandom(32)
        key_hex = binascii.hexlify(key).decode()
        return key_hex

    def encrypt_message(message, key):
        backend = default_backend()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(binascii.unhexlify(key)), modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()

        padded_data = padder.update(message.encode()) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return iv + ciphertext

    def cipher():
        st.write("## Message Encryption")

        # Input field for message
        message = st.text_input("Enter your message:")

        # Input field for key or generate key button
        key = st.text_input("Enter your encryption key (or leave empty to generate a key):")
        if not key:
            if st.button("Generate Key"):
                key = generate_key()
                st.success("Generated Key: " + key)

        # Encrypt button
        if st.button("Encrypt with AES"):
            if message and key:
                encrypted_message = encrypt_message(message, key)
                st.success("Encrypted message: " + binascii.hexlify(encrypted_message).decode())
            else:
                st.warning("Please enter both a message and a key.")

    def decrypt_message(encrypted_message, key):
        backend = default_backend()
        iv = encrypted_message[:16]
        ciphertext = encrypted_message[16:]
        cipher = Cipher(algorithms.AES(binascii.unhexlify(key)), modes.CBC(iv), backend=backend)
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(128).unpadder()

        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
        return unpadded_data.decode()

    def decipher():
        st.write("## Message Decryption")

        # Input field for encrypted message
        encrypted_message = st.text_input("Enter the encrypted message:")

        # Input field for secret key
        key = st.text_input("Enter your secret key:")

        # Decrypt button
        if st.button("Decrypt with AES"):
            if encrypted_message and key:
                encrypted_message_bytes = binascii.unhexlify(encrypted_message)
                decrypted_message = decrypt_message(encrypted_message_bytes, key)
                st.success("Decrypted message: " + decrypted_message)
            else:
                st.warning("Please enter both the encrypted message and the secret key.")

    tab1, tab2 = st.tabs(["Encrypt", "Decrypt"])
    with tab1: 
        cipher()
    with tab2:
        decipher()


# Define function for asymmetric encryption
def asymmetric_encryption():
    st.write("## Rivest-Shamir-Adleman (RSA)")
    st.write("### Discussion:")
    st.write("Rivest-Shamir-Adleman (RSA) is a popular encryption algorithm that provides secure communication over untrusted networks. It uses a pair of keys, a public key for encryption and a private key for decryption. The keys are mathematically related but difficult to derive from each other. RSA's security is based on the difficulty of factoring large numbers. It is widely used to secure sensitive information and is an important part of modern cryptography.")
    st.write("### Application:")

    def generate_rsa_keys():
        # Generate RSA key pair
        public_key, private_key = rsa.newkeys(515)

        # Convert keys to string format
        public_key_str = public_key.save_pkcs1().decode('utf-8')
        private_key_str = private_key.save_pkcs1().decode('utf-8')

        return public_key_str, private_key_str

    public_key, private_key = generate_rsa_keys()

    def encrypt_message(message, key_str):
        # Load the RSA key from string
        key = rsa.PublicKey.load_pkcs1(key_str.encode('utf-8'))

        # Encrypt the message using the RSA key
        encrypted_message = rsa.encrypt(message.encode('utf-8'), key)

        return encrypted_message

    def cipher():
        message = st.text_input("Enter message to be encrypted: ", "HELLO WORLD!!")
        key = st.text_area("Enter your public key for encryption (or leave empty to generate a key):")

        if st.button("Generate Keys"):
            st.text_area("Public Key", public_key, height=200)
            st.text_area("Private Key", private_key, height=200)

        if st.button("Encrypt with RSA"):
            if message and key:
                encrypted_message = encrypt_message(message, key)
                st.success("Encrypted message: " + encrypted_message.hex())
            else:
                st.warning("Please enter both a message and a key.")

    def decrypt_message(encrypted_message, key_str):
        # Load the RSA key from string
        key = rsa.PrivateKey.load_pkcs1(key_str.encode('utf-8'))

        # Decrypt the message using the RSA key
        decrypted_message = rsa.decrypt(encrypted_message, key)

        return decrypted_message.decode('utf-8')

    def decipher():
        encrypted_message = st.text_area("Enter the encrypted message: ")
        private_key = st.text_area("Enter your private key for decryption: ", height=200)

        if st.button("Decrypt with RSA"):
            if encrypted_message and private_key:
                encrypted_message_bytes = bytes.fromhex(encrypted_message)
                decrypted_message = decrypt_message(encrypted_message_bytes, private_key)
                st.success("Decrypted message: " + decrypted_message)
            else:
                st.warning("Please enter both an encrypted message and a private key.")

    tab1, tab2 = st.tabs(["Encrypt", "Decrypt"])
    with tab1: 
        cipher()
    with tab2:
        decipher()


# Define function for hashing
def hashing():
    st.write("## Secure Hash Algorithm 256 (SHA-256)")
    st.write("### Discussion:")
    st.write("The Secure Hash Algorithm 256 (SHA-256) is a widely used cryptographic hash function that belongs to the SHA-2 family. It generates a fixed-size 256-bit hash value that is considered highly secure and resistant to collision attacks.")
    st.write("### Application:")

    def calculate_sha256(data):
        sha256_hash = hashlib.sha256()
        sha256_hash.update(data)
        return sha256_hash.hexdigest()

    def message_hash():
        message = st.text_input("Enter message to hash:", "Hello World!!")
        if st.button("Hash"):
            sha256_hash = calculate_sha256(message.encode('utf-8'))
            st.success("SHA-256 Hash: " + sha256_hash)

    def file_hash():
        uploaded_files = st.file_uploader("Choose files to hash", accept_multiple_files=True)
        for uploaded_file in uploaded_files:
            file_contents = uploaded_file.read()
            sha256_hash = calculate_sha256(file_contents)
            st.write("---")
            st.success(f"File: {uploaded_file.name}")
            st.success(f"SHA-256 Hash: {sha256_hash}")

    tab1, tab2 = st.tabs(["Message Hashing", "File Hashing"])
    with tab1:
        message_hash()
    with tab2:
        file_hash()


# Main Streamlit app
def main():
    st.title("Cryptographic Application")
    st.write("## Introduction:")
    st.write("Cryptography is the science and practice of secure communication in the presence of adversaries. It involves techniques and methods used to protect information from unauthorized access or modification. Cryptography plays a crucial role in maintaining the safety and accuracy of information on the Internet, as well as in various other domains such as finance, government, healthcare, and telecommunications.")
    st.write("The primary goal of cryptography is to provide confidentiality, integrity, authentication, and non-repudiation of data. It achieves these goals through the use of cryptographic algorithms and protocols. Let's explore three fundamental concepts in cryptography: symmetric encryption, asymmetric encryption, and hashing.")
    st.write("- Symmetric Cryptography, also known as secret-key encryption, is a cryptographic method where the same key is used for both encryption and decryption. The sender and receiver share a secret key that they use to transform plaintext into ciphertext and vice versa. Symmetric encryption is fast and efficient, making it suitable for encrypting large amounts of data.")
    st.write("- Asymmetric Cryptography, also known as public-key encryption, uses a pair of mathematically related keys: a public key and a private key. The public key is widely distributed and used for encryption, while the private key is kept secret and used for decryption. Messages encrypted with the public key can only be decrypted using the corresponding private key.")
    st.write("- Hashing is a one-way process that converts input data of any size into a fixed-size output called a hash value or hash code. The output is unique to the input data, meaning even a slight change in the input will produce a completely different hash value. Hashing is primarily used for data integrity verification and password storage.")
    st.write("## Project Objectives:")
    st.write("1. Implement Advanced Encryption Standard (AES), Rivest-Shamir-Adleman (RSA), and Secure Hash Algorithm 256 (SHA-256) in the system.")
    st.write("2. Develop a Streamlit-based user interface for encrypting and decrypting messages using the implemented Advanced Encryption Standard (AES) and Rivest-Shamir-Adleman (RSA) algorithms. The interface should allow users to choose the encryption algorithm, enter a message, and provide the necessary encryption parameters. It should also display the progress and provide feedback during the encryption and decryption processes.")
    st.write("3. Create a separate tab in the UI for generating and verifying Secure Hash Algorithm 256 (SHA-256) hash values of messages or files. The interface should allow users to enter a message and generate a hash for it or to select multiple files and calculate SHA-256 hash value for each file uploaded.")
    # Create tabs
    tab1, tab2, tab3 = st.tabs(["Symmetric Cryptography (AES)", "Asymmetric Cryptography (RSA)", "Hashing (SHA-256)"])
    with tab1:
        symmetric_encryption()
    with tab2:
        asymmetric_encryption()
    with tab3:
        hashing()


    # Custom CSS styles for the footer
    st.markdown(
        """
        <style>
        .footer {
            position: fixed;
            right: 0;
            bottom: 0;
            background-color: #f8f9fa;
            padding: 10px;
            text-align: center;
            font-family: Arial, sans-serif;
            font-size: 14px;
            color: #333333;
        }
        </style>
        """
    , unsafe_allow_html=True)

    # You can customize the footer content here
    footer_text = """
    <div style="text-align: center;">
        <p>Submitted by:</p>
        <h3>Abalos, Rojhon</h3>
        <h3>Lomeda, Kristine Joy</h3>
        <h3>Secopito, Omar</h3>
        <p>BSCS 3A - Group_2</p>
    </div>
    """

    # Add the footer to the sidebar
    st.sidebar.markdown(footer_text, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
