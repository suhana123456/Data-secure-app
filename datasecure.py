import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Generate a consistent encryption key
if "fernet_key" not in st.session_state:
    st.session_state.fernet_key = Fernet.generate_key()

cipher = Fernet(st.session_state.fernet_key)

# Initialize session state variables
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "login_required" not in st.session_state:
    st.session_state.login_required = False
if "last_encrypted" not in st.session_state:
    st.session_state.last_encrypted = ""

# Function to hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt data
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Decrypt data with passkey validation
def decrypt_data(encrypted_text, passkey):
    entry = st.session_state.stored_data.get(encrypted_text)
    if entry and entry["passkey"] == hash_passkey(passkey):
        st.session_state.failed_attempts = 0
        return cipher.decrypt(encrypted_text.encode()).decode()
    else:
        st.session_state.failed_attempts += 1
        if st.session_state.failed_attempts >= 3:
            st.session_state.login_required = True
        return None

# UI
st.set_page_config(page_title="Secure App", page_icon="🔐")
st.title("🔐 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigate", menu)

# Home Page
if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write("Encrypt and decrypt data securely.")

# Store Data
elif choice == "Store Data":
    st.subheader("📥 Store Data")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Store"):
        if user_data and passkey:
            encrypted = encrypt_data(user_data)
            st.session_state.stored_data[encrypted] = {
                "passkey": hash_passkey(passkey)
            }
            st.session_state.last_encrypted = encrypted
            st.success("✅ Data stored!")
            st.code(encrypted, language="text")
        else:
            st.error("Please enter both fields.")

# Retrieve Data
elif choice == "Retrieve Data":
    if st.session_state.login_required:
        st.warning("🔒 Too many failed attempts. Login again.")
    else:
        st.subheader("🔍 Retrieve Data")
        default_encrypted = st.session_state.get("last_encrypted", "")
        encrypted_text = st.text_area("Enter Encrypted Text:", value=default_encrypted)
        passkey = st.text_input("Enter Passkey:", type="password")

        if st.button("Decrypt"):
            if encrypted_text and passkey:
                decrypted = decrypt_data(encrypted_text, passkey)
                if decrypted:
                    st.success("✅ Success!")
                    st.text_area("Decrypted Data:", value=decrypted, height=150)
                else:
                    attempts_left = 3 - st.session_state.failed_attempts
                    st.error(f"❌ Incorrect passkey. Attempts left: {attempts_left}")
            else:
                st.error("Fill both fields.")

# Login Page
elif choice == "Login":
    st.subheader("🔑 Reauthorization")
    master_pass = st.text_input("Master Password:", type="password")

    if st.button("Login"):
        if master_pass == "admin123":
            st.session_state.failed_attempts = 0
            st.session_state.login_required = False
            st.success("✅ Reauthorized! Try retrieving again.")
        else:
            st.error("❌ Incorrect master password.")