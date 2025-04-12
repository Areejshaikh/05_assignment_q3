import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Generate a Key
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# Store Data
store_data = {}
failed_attempts = 0

# Function to hash passkey
def hash_passkey(passkey):
    return hashlib.sha224(passkey.encode()).hexdigest()

# Function to encrypt data
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Function to decrypt data
def decrypt_data(encrypted_text, passkey):
    global failed_attempts
    hashed_passkey = hash_passkey(passkey)

    for key, value in store_data.items():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
            failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()

    failed_attempts += 1
    return None

# Streamlit UI
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
page = st.sidebar.selectbox("Navigation", menu)
mainHeading = st.title("🔒 Secure Data Encryption System")

if page == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to securely store and retrieve data using unique passkeys.")

elif page == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data)
            store_data[encrypted_text] = {"encrypted_text": encrypted_text, "passkey": hashed_passkey}
            st.success("✅ Data Stored Securely!")
            st.code(encrypted_text)
        else:
            st.error("❌ Both fields are required!")

elif page == "Retrieve Data":
    st.subheader("📂 Retrieve Your Data")
    encrypted_text = st.text_area("Enter Encrypted Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            decrypted_text = decrypt_data(encrypted_text, passkey)

            if decrypted_text:
                st.success(f"✅ Decrypted Data: {decrypted_text}")
            else:
                st.error(f"❌ Incorrect Passkey! Attempts remaining: {3 - failed_attempts}")

                if failed_attempts >= 3:
                    st.warning("🔒 Too many failed attempts! Redirecting to Login Page.")
                    st.session_state.page = "Login"
                    st.experimental_rerun()
        else:
            st.error("⚠️ Both fields are required!")

elif page == "Login":
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":
            failed_attempts = 0
            st.success("✅ Reauthorized successfully! Redirecting to Retrieve Data...")
            st.session_state.page = "Retrieve Data"
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect password!")
   

