import streamlit as st
import hashlib
from Crypto.Cipher import AES, DES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64

st.set_page_config(page_title="Cryptography Toolkit", layout="wide")

st.title("🔐 Cryptography Toolkit Web App")
st.write("CSC232 – Information Security Lab Project")

menu = st.sidebar.selectbox(
    "Select Module",
    [
        "Caesar Cipher",
        "Vigenère Cipher",
        "AES Encryption",
        "RSA Encryption",
        "SHA-256 Hash"
    ]
)

# ---------------- CAESAR CIPHER ----------------
if menu == "Caesar Cipher":
    st.header("Caesar Cipher")

    text = st.text_area("Enter Text")
    shift = st.slider("Shift Key", 1, 25, 3)

    def caesar_encrypt(text, shift):
        result = ""
        for char in text:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                result += chr((ord(char) - base + shift) % 26 + base)
            else:
                result += char
        return result

    if st.button("Encrypt"):
        st.success(caesar_encrypt(text, shift))

# ---------------- VIGENERE CIPHER ----------------
elif menu == "Vigenère Cipher":
    st.header("Vigenère Cipher")

    text = st.text_area("Enter Text")
    key = st.text_input("Enter Key").upper()

    def vigenere_encrypt(text, key):
        result = ""
        key_index = 0
        for char in text.upper():
            if char.isalpha():
                shift = ord(key[key_index % len(key)]) - 65
                result += chr((ord(char) - 65 + shift) % 26 + 65)
                key_index += 1
            else:
                result += char
        return result

    if st.button("Encrypt"):
        if key:
            st.success(vigenere_encrypt(text, key))
        else:
            st.error("Key required")

# ---------------- AES ----------------
elif menu == "AES Encryption":
    st.header("AES Encryption (Text)")

    plaintext = st.text_area("Enter Plain Text")
    key = get_random_bytes(16)

    def aes_encrypt(text, key):
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(text.encode())
        return base64.b64encode(cipher.nonce + ciphertext).decode()

    if st.button("Encrypt"):
        encrypted = aes_encrypt(plaintext, key)
        st.success("Encrypted Text:")
        st.code(encrypted)
        st.info(f"Secret Key (Save it): {base64.b64encode(key).decode()}")

# ---------------- RSA ----------------
elif menu == "RSA Encryption":
    st.header("RSA Encryption")

    message = st.text_area("Enter Message")

    key = RSA.generate(2048)
    public_key = key.publickey()
    cipher = PKCS1_OAEP.new(public_key)

    if st.button("Encrypt"):
        encrypted = cipher.encrypt(message.encode())
        st.success("Encrypted Message:")
        st.code(base64.b64encode(encrypted).decode())

# ---------------- HASH ----------------
elif menu == "SHA-256 Hash":
    st.header("SHA-256 Hash Generator")

    text = st.text_area("Enter Text")

    if st.button("Generate Hash"):
        hash_value = hashlib.sha256(text.encode()).hexdigest()
        st.success(hash_value)

st.sidebar.markdown("---")
st.sidebar.info("Developed for CSC232 – Information Security")
