import streamlit as st
import pandas as pd
import streamlit_authenticator as stauth
from streamlit_option_menu import option_menu
import bcrypt
import yaml
from yaml.loader import SafeLoader
import requests
from requests.auth import HTTPBasicAuth
import os
import base64


def load_users():
    users = pd.read_csv('codes.csv')
    return users

users_df = load_users()


GITHUB_USERNAME = 'Toine17'
GITHUB_TOKEN = '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'
REPO_NAME = 'essai'
FILE_PATH = 'codes.csv'
BRANCH = 'main'

url = f'https://api.github.com/repos/{GITHUB_USERNAME}/{REPO_NAME}/contents/{FILE_PATH}'

def encode_file_content(file_path):
    with open(file_path, 'rb') as file:
        return base64.b64encode(file.read()).decode('utf-8')
    
def update_github_file(file_path, commit_message, content):
    response = requests.get(url, auth=HTTPBasicAuth(GITHUB_USERNAME, GITHUB_TOKEN))
    file_info = response.json()

    sha = file_info.get('sha') if response.status_code == 200 else None

    update_data = {
        'message': commit_message,
        'content': content,
        'branch': BRANCH
    }

    if sha:
        update_data['sha'] = sha  # If file exists, include SHA to overwrite it

    # Send the PUT request to update the file
    update_response = requests.put(url, json=update_data, auth=HTTPBasicAuth(GITHUB_USERNAME, GITHUB_TOKEN))
    
    return update_response

def save_user(new_user):
    """Sauvegarde un nouvel utilisateur dans le fichier CSV."""
    users_df = load_users()
    users_df = pd.concat([users_df, pd.DataFrame([new_user])], ignore_index=True)
    users_df.to_csv('codes.csv', index=False)

    file_content = encode_file_content('codes.csv')  # Read and encode the file
    commit_message = "Updating codes.csv with new user"
    update_response = update_github_file('codes.csv', commit_message, file_content)

def hash_password(password):
    """Hache le mot de passe avec bcrypt."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()

if 'registration_status' not in st.session_state:
    st.session_state.registration_status = None


credentials = {
    "usernames": {
        row["name"]: {
            "name": row["name"],
            "password": row["password"],  # Déjà haché
            "email" : row["email"],
            "failed_login_attempts" : row["failed_login_attempts"],
            "role": row["role"]
        }
        for _, row in users_df.iterrows()}}

config = {"credentials": credentials, "cookie": {"expiry_days": 1}}


authenticator = stauth.Authenticate(
    config["credentials"], # Les données des comptes
    "cookie name", # Le nom du cookie, un str quelconque
    "cookie key", # La clé du cookie, un str quelconque
    30, # Le nombre de jours avant que le cookie expire 
)


authenticator.login()
if st.session_state["authentication_status"]:
 
  with st.sidebar:
    authenticator.logout("Déconnexion")
    st.write(f"Bienvenue, {st.session_state['name']}")
    selection = option_menu(
            menu_title=None,
            options = ["Accueil", "Mon équipe"]
        )
    
  if selection == 'Accueil':
    st.title("Bienvenue sur ma page")
    st.write("Ca c'est moi :point_down: Professeur Hubert Farnsworth")
    st.image("prof.png")
  elif selection == 'Mon équipe':

        st.title("Bienvenue sur la page des personnages de futurama")
        col1, col2, col3 = st.columns(3)
        with col1 :
            st.header("Leela")
            st.image("leela-1.png")
        with col2 :
            st.header("Bender")
            st.image("bender.png")
        with col3 :  
            st.header("Fry") 
            st.image("fry.png")







######################################################################################################################

    

#if st.button("Inscription"):
with st.form("register_form"):
        new_name = st.text_input("Nom d'utilisateur")
        new_password = st.text_input("Mot de passe", type="password")

        new_user = {
                        "name": new_name,
                        "password": hash_password(new_password),
                        "email": "new_email",
                        "failed_login_attempts": 0,
                        "role": "user"
                    }
    
        if st.form_submit_button("Ajouter"):
            if new_name and new_password:
                save_user(new_user)
                st.session_state.registration_status = "Utilisateur ajouté avec succès."
            else : 
                 st.session_state.registration_status = "Tous les champs doivent être remplis correctement."

if st.session_state.registration_status:
        st.success(st.session_state.registration_status)

            
##########################################################################################################################

# Si l'utilisateur n'est pas authentifié
elif st.session_state.get("authentication_status") is False:
    st.error("L'username ou le mot de passe est incorrect")
elif st.session_state.get("authentication_status") is None:
    st.warning('Les champs username et mot de passe doivent être remplis')
    