import streamlit as st
import hashlib
import base64
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

st.set_page_config(page_title="Cryptography Toolkit", layout="wide")
st.title("🔐 Cryptography Toolkit (Encrypt & Decrypt)")
st.write("CSC232 – Information Security")

menu = st.sidebar.selectbox(
    "Select Algorithm",
    ["Caesar Cipher", "Vigenère Cipher", "AES", "RSA", "SHA-256 Hash"]
)

# ================= CAESAR =================
if menu == "Caesar Cipher":
    st.header("Caesar Cipher")

    text = st.text_area("Enter Text")
    shift = st.slider("Shift Key", 1, 25, 3)
    mode = st.radio("Mode", ["Encrypt", "Decrypt"])

    def caesar(text, shift, encrypt=True):
        result = ""
        for char in text:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                s = shift if encrypt else -shift
                result += chr((ord(char) - base + s) % 26 + base)
            else:
                result += char
        return result

    if st.button("Process"):
        st.success(caesar(text, shift, mode == "Encrypt"))

# ================= VIGENERE =================
elif menu == "Vigenère Cipher":
    st.header("Vigenère Cipher")

    text = st.text_area("Enter Text")
    key = st.text_input("Enter Key").upper()
    mode = st.radio("Mode", ["Encrypt", "Decrypt"])

    def vigenere(text, key, encrypt=True):
        result = ""
        key_index = 0
        for char in text.upper():
            if char.isalpha():
                k = ord(key[key_index % len(key)]) - 65
                k = k if encrypt else -k
                result += chr((ord(char) - 65 + k) % 26 + 65)
                key_index += 1
            else:
                result += char
        return result

    if st.button("Process"):
        if key:
            st.success(vigenere(text, key, mode == "Encrypt"))
        else:
            st.error("Key required")

# ================= AES =================
elif menu == "AES":
    st.header("AES Encryption & Decryption")

    text = st.text_area("Enter Text")
    mode = st.radio("Mode", ["Encrypt", "Decrypt"])

    key_input = st.text_input("Secret Key (Base64)")

    if st.button("Process"):
        if mode == "Encrypt":
            key = get_random_bytes(16)
            cipher = AES.new(key, AES.MODE_EAX)
            ciphertext, tag = cipher.encrypt_and_digest(text.encode())
            result = base64.b64encode(cipher.nonce + ciphertext).decode()

            st.success("Encrypted Text:")
            st.code(result)
            st.info("Save this key:")
            st.code(base64.b64encode(key).decode())

        else:
            try:
                key = base64.b64decode(key_input)
                data = base64.b64decode(text)
                nonce = data[:16]
                ciphertext = data[16:]
                cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
                plaintext = cipher.decrypt(ciphertext).decode()
                st.success("Decrypted Text:")
                st.code(plaintext)
            except:
                st.error("Invalid key or ciphertext")

# ================= RSA =================
elif menu == "RSA":
    st.header("RSA Encryption & Decryption")

    text = st.text_area("Enter Text")
    mode = st.radio("Mode", ["Encrypt", "Decrypt"])

    if "rsa_key" not in st.session_state:
        st.session_state.rsa_key = RSA.generate(2048)

    key = st.session_state.rsa_key
    public_key = key.publickey()

    if st.button("Process"):
        if mode == "Encrypt":
            cipher = PKCS1_OAEP.new(public_key)
            encrypted = cipher.encrypt(text.encode())
            st.success("Encrypted Text:")
            st.code(base64.b64encode(encrypted).decode())

        else:
            try:
                cipher = PKCS1_OAEP.new(key)
                decrypted = cipher.decrypt(base64.b64decode(text)).decode()
                st.success("Decrypted Text:")
                st.code(decrypted)
            except:
                st.error("Invalid ciphertext")

# ================= HASH =================
elif menu == "SHA-256 Hash":
    st.header("SHA-256 Hash (One-Way)")

    text = st.text_area("Enter Text")

    if st.button("Generate Hash"):
        st.success(hashlib.sha256(text.encode()).hexdigest())
        st.info("⚠ Hashing is one-way (No decryption possible)")
