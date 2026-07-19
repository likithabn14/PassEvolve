import streamlit as st
import sqlite3
import pandas as pd
from zxcvbn import zxcvbn
from rapidfuzz import fuzz
from cryptography.fernet import Fernet
import datetime
import re

st.set_page_config(page_title="PassEvolve", layout="wide")

# --- 1. CRYPTOGRAPHY SETUP ---
# In a real startup, this key is hidden in a .env file. 
if "fernet_key" not in st.session_state:
    st.session_state.fernet_key = Fernet.generate_key()
cipher_suite = Fernet(st.session_state.fernet_key)

def encrypt_pwd(pwd):
    return cipher_suite.encrypt(pwd.encode()).decode()

def decrypt_pwd(encrypted_pwd):
    return cipher_suite.decrypt(encrypted_pwd.encode()).decode()

# --- 2. DATABASE SETUP ---
def init_db():
    conn = sqlite3.connect("passevolve.db")
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY)''')
    c.execute('''CREATE TABLE IF NOT EXISTS history 
                 (username TEXT, encrypted_pwd TEXT, score INTEGER, timestamp TEXT)''')
    conn.commit()
    conn.close()

init_db()

# --- 3. THE ALGORITHMIC BRAIN ---
def check_password_habits(new_pwd, username):
    conn = sqlite3.connect("passevolve.db")
    c = conn.cursor()
    c.execute("SELECT encrypted_pwd, score FROM history WHERE username=? ORDER BY timestamp ASC", (username,))
    records = c.fetchall()
    conn.close()

    # Zxcvbn analyzes entropy, dictionary words, and keyboard smashes
    z_result = zxcvbn(new_pwd, user_inputs=[username])
    score = z_result['score']
    feedback = z_result['feedback']['warning'] or "Strong composition."
    
    max_similarity = 0
    history_trend = []
    
    # Decrypt and compare with history
    if records:
        for enc_pwd, old_score in records:
            old_pwd = decrypt_pwd(enc_pwd)
            sim = fuzz.ratio(new_pwd, old_pwd)
            if sim > max_similarity:
                max_similarity = sim
            history_trend.append(old_score)
            
    # Habit Analysis Logic
    habit_warnings = []
    if max_similarity > 85:
        habit_warnings.append(f"⚠️ {max_similarity:.1f}% similar to a past password. You are likely just changing a number or letter.")
    
    if username.lower() in new_pwd.lower():
        habit_warnings.append("⚠️ Contains your personal username.")
        
    if re.search(r'(.)\1{3,}', new_pwd):
        habit_warnings.append("⚠️ Repeated character patterns detected.")

    if len(history_trend) >= 2:
        if score > history_trend[-1]:
            habit_warnings.append("✅ Your password habits are improving!")
        elif score < history_trend[-1]:
            habit_warnings.append("📉 Your password security is trending downward compared to your last update.")

    return score, feedback, max_similarity, habit_warnings

# --- 4. STREAMLIT UI ---
st.title("🛡️ PassEvolve: Behavioral Security Analyzer")
st.markdown("Stop creating predictable passwords before hackers can predict them.")

# Sidebar Login
with st.sidebar:
    st.header("User Portal")
    username_input = st.text_input("Enter Username to Login/Register")
    if st.button("Access Portal") and username_input:
        st.session_state.username = username_input
        conn = sqlite3.connect("passevolve.db")
        c = conn.cursor()
        c.execute("INSERT OR IGNORE INTO users (username) VALUES (?)", (username_input,))
        conn.commit()
        conn.close()
        st.success(f"Logged in as {username_input}")

# Main Dashboard
if "username" in st.session_state:
    st.subheader(f"Welcome, {st.session_state.username}")
    
    new_password = st.text_input("Create New Password", type="password")
    
    if st.button("Analyze & Save Password") and new_password:
        score, feedback, max_sim, habits = check_password_habits(new_password, st.session_state.username)
        
        # Save to DB
        enc_pwd = encrypt_pwd(new_password)
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = sqlite3.connect("passevolve.db")
        c = conn.cursor()
        c.execute("INSERT INTO history (username, encrypted_pwd, score, timestamp) VALUES (?, ?, ?, ?)", 
                  (st.session_state.username, enc_pwd, score, timestamp))
        conn.commit()
        conn.close()

        # Display Metrics
        st.divider()
        st.subheader("Security Telemetry")
        col1, col2, col3 = st.columns(3)
        
        # Mapping zxcvbn score (0-4) to percentage
        entropy_pct = (score / 4) * 100 
        
        col1.metric("Entropy Score", f"{entropy_pct:.0f}%")
        col2.metric("Similarity Risk", f"{max_sim:.1f}%", delta=f"{max_sim:.1f}%" if max_sim > 80 else "-OK", delta_color="inverse")
        col3.metric("Dictionary Risk", "High" if score < 2 else "Low")
        
        st.info(f"**Engine Feedback:** {feedback}")
        
        # Display Habit Analyzer
        st.subheader("🧠 Password Habit Analyzer")
        for warning in habits:
            st.markdown(f"**{warning}**")

    # Display Timeline
    st.divider()
    st.subheader("Your Password Timeline")
    conn = sqlite3.connect("passevolve.db")
    df = pd.read_sql_query("SELECT timestamp, score FROM history WHERE username=?", conn, params=(st.session_state.username,))
    conn.close()
    
    if not df.empty:
        # Mask the passwords for timeline display, just show scores
        df['Strength'] = df['score'].map({0: '❌ Weak', 1: '❌ Weak', 2: '⚠️ Fair', 3: '✅ Strong', 4: '🌟 Excellent'})
        df = df[['timestamp', 'Strength']]
        st.dataframe(df, use_container_width=True)
else:
    st.warning("Please enter a username in the sidebar to begin tracking your password habits.")