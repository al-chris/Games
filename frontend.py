# frontend.py

import streamlit as st
import requests
import uuid

API_URL = "http://127.0.0.1:8000"

# Session State for authentication
if 'token' not in st.session_state:
    st.session_state['token'] = None
if 'user_id' not in st.session_state:
    st.session_state['user_id'] = None

# Helper functions
def register(username, password):
    response = requests.post(f"{API_URL}/register", params={"username": username, "password": password})
    if response.status_code == 200:
        st.success("Registered successfully. Please log in.")
    else:
        st.error(response.json().get("detail", "Registration failed"))

def login(username, password):
    response = requests.post(f"{API_URL}/token", data={"username": username, "password": password})
    if response.status_code == 200:
        st.session_state['token'] = response.json()['access_token']
        st.success("Logged in successfully")
    else:
        st.error(response.json().get("detail", "Login failed"))

def create_temp_user():
    response = requests.post(f"{API_URL}/create_temp_user")
    if response.status_code == 200:
        st.session_state['user_id'] = response.json()['user_id']
        st.success("Created temporary user")
    else:
        st.error("Failed to create temporary user")

def search(query):
    response = requests.get(f"{API_URL}/search", params={"query": query})
    if response.status_code == 200:
        return response.json()
    else:
        return {"users": [], "sessions": []}

def create_session(game_type, mode):
    headers = {"Authorization": f"Bearer {st.session_state['token']}"}
    data = {"game_type": game_type, "mode": mode}
    response = requests.post(f"{API_URL}/create_session", json=data, headers=headers)
    if response.status_code == 200:
        st.success(f"Session created with ID: {response.json()['session_id']}")
    else:
        st.error("Failed to create session")

def join_session(session_id):
    headers = {"Authorization": f"Bearer {st.session_state['token']}"}
    data = {"session_id": session_id}
    response = requests.post(f"{API_URL}/join_session", json=data, headers=headers)
    if response.status_code == 200:
        st.success("Joined session successfully")
    else:
        st.error("Failed to join session")

# UI Components
def auth_ui():
    st.sidebar.title("Authentication")
    auth_option = st.sidebar.selectbox("Choose Option", ["Login", "Register", "Continue as Guest"])
    
    if auth_option == "Register":
        username = st.sidebar.text_input("Username")
        password = st.sidebar.text_input("Password", type="password")
        if st.sidebar.button("Register"):
            register(username, password)
    elif auth_option == "Login":
        username = st.sidebar.text_input("Username")
        password = st.sidebar.text_input("Password", type="password")
        if st.sidebar.button("Login"):
            login(username, password)
    elif auth_option == "Continue as Guest":
        if st.sidebar.button("Continue as Guest"):
            create_temp_user()

def main():
    st.title("Multiplayer Gaming Platform")

    auth_ui()

    if st.session_state['token'] or st.session_state['user_id']:
        st.sidebar.write("Logged in")
        # Game Selection
        game = st.selectbox("Choose a Game", ["Word/Sentence/Paragraph Completion", "20 Questions"])
        
        if game == "Word/Sentence/Paragraph Completion":
            st.header("Completion Game")
            mode = st.selectbox("Select Mode", ["word", "sentence", "paragraph"])
            if st.button("Create Session"):
                create_session("completion", mode)
            
            session_id = st.text_input("Enter Session ID to Join")
            if st.button("Join Session"):
                join_session(session_id)
            
            # Game Play
            if st.button("Load Session"):
                headers = {"Authorization": f"Bearer {st.session_state['token']}"} if st.session_state['token'] else {}
                response = requests.get(f"{API_URL}/get_completion_state", params={"session_id": session_id}, headers=headers)
                if response.status_code == 200:
                    state = response.json()
                    story = " ".join([step['content'] for step in state['story']])
                    st.write("**Current Story:**")
                    st.write(story)
                    new_content = st.text_input("Your contribution:")
                    if st.button("Submit"):
                        headers = {"Authorization": f"Bearer {st.session_state['token']}"} if st.session_state['token'] else {}
                        data = {"session_id": session_id, "content": new_content}
                        resp = requests.post(f"{API_URL}/completion_step", json=data, headers=headers)
                        if resp.status_code == 200:
                            st.success("Submitted successfully")
                        else:
                            st.error("Failed to submit")
                else:
                    st.error("Failed to load session")
        
        elif game == "20 Questions":
            st.header("20 Questions Game")
            mode = st.selectbox("Select Mode", ["general", "personal"])
            if st.button("Create Session"):
                create_session("questions", mode)
            
            session_id = st.text_input("Enter Session ID to Join")
            if st.button("Join Session"):
                join_session(session_id)
            
            # Game Play
            if st.button("Load Session"):
                headers = {"Authorization": f"Bearer {st.session_state['token']}"} if st.session_state['token'] else {}
                response = requests.get(f"{API_URL}/get_questions_state", params={"session_id": session_id}, headers=headers)
                if response.status_code == 200:
                    state = response.json()
                    st.write("**Questions:**")
                    for q in state['questions']:
                        st.write(q)
                    answer = st.text_input("Your Answer:")
                    if st.button("Submit Answer"):
                        data = {"session_id": session_id, "question": state['questions'][-1], "answer": answer}
                        resp = requests.post(f"{API_URL}/questions_step", json=data, headers=headers)
                        if resp.status_code == 200:
                            st.success("Answer submitted")
                        else:
                            st.error("Failed to submit answer")
                else:
                    st.error("Failed to load session")
    else:
        st.write("Please authenticate to continue.")

if __name__ == "__main__":
    main()
