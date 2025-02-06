import streamlit as st
import pandas as pd
import streamlit_authenticator as stauth
from streamlit_option_menu import option_menu
import bcrypt
import requests
from requests.auth import HTTPBasicAuth
import base64

# Charger les utilisateurs depuis le fichier CSV
def load_users():
    users = pd.read_csv('codes.csv')
    return users

users_df = load_users()

# Configuration pour GitHub
GITHUB_USERNAME = 'Toine17'
GITHUB_TOKEN = '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'
REPO_NAME = 'essai'
FILE_PATH = 'codes.csv'
BRANCH = 'main'
url = f'https://api.github.com/repos/{GITHUB_USERNAME}/{REPO_NAME}/contents/{FILE_PATH}'

# Encodage du contenu du fichier
def encode_file_content(file_path):
    with open(file_path, 'rb') as file:
        return base64.b64encode(file.read()).decode('utf-8')

# Mise à jour du fichier sur GitHub
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
        update_data['sha'] = sha  # Si le fichier existe, on inclut le SHA pour le remplacer

    # Mise à jour du fichier sur GitHub
    update_response = requests.put(url, json=update_data, auth=HTTPBasicAuth(GITHUB_USERNAME, GITHUB_TOKEN))
    return update_response

# Sauvegarder un utilisateur dans le CSV et GitHub
def save_user(new_user):
    users_df = load_users()
    users_df = pd.concat([users_df, pd.DataFrame([new_user])], ignore_index=True)
    users_df.to_csv('codes.csv', index=False)

    # Encoder et télécharger le fichier sur GitHub
    file_content = encode_file_content('codes.csv')
    commit_message = "Ajout d'un utilisateur"
    update_response = update_github_file('codes.csv', commit_message, file_content)

# Hachage du mot de passe
def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()

# Session state pour afficher l'état de l'inscription
if 'registration_status' not in st.session_state:
    st.session_state.registration_status = None

# Authentification
credentials = {
    "usernames": {
        row["name"]: {
            "name": row["name"],
            "password": row["password"],  # Déjà haché
            "email" : row["email"],
            "failed_login_attempts" : row["failed_login_attempts"],
            "role": row["role"]
        }
        for _, row in users_df.iterrows()}
}

config = {"credentials": credentials, "cookie": {"expiry_days": 1}}

authenticator = stauth.Authenticate(
    config["credentials"],  # Les données des comptes
    "cookie name",  # Le nom du cookie
    "cookie key",  # La clé du cookie
    30,  # Le nombre de jours avant que le cookie expire
)

with st.sidebar.form("register_form"):
    st.subheader("Inscription")
    new_name = st.text_input("Nom d'utilisateur")
    new_password = st.text_input("Mot de passe", type="password")

        
    
    if st.form_submit_button("Ajouter"):
            if new_name and new_password:
                new_user = {
                        "name": new_name,
                        "password": hash_password(new_password),
                        "email": "new_email",
                        "failed_login_attempts": 0,
                        "role": "user"
                    }
                save_user(new_user)
                st.session_state.registration_status = "Utilisateur ajouté avec succès."
            else : 
                 st.session_state.registration_status = "Tous les champs doivent être remplis correctement."

    if st.session_state.registration_status:
        st.success(st.session_state.registration_status)

authenticator.login()

# Si l'utilisateur est authentifié
if st.session_state["authentication_status"]:
    with st.sidebar:
        authenticator.logout("Déconnexion")
        st.write(f"Bienvenue, {st.session_state['name']}")
        selection = option_menu(
            menu_title=None,
            options=["Accueil", "Mon équipe"]
        )

    if selection == 'Accueil':
        st.title("Bienvenue sur ma page")
        st.write("Ca c'est moi :point_down: Professeur Hubert Farnsworth")
        st.image("prof.png")
    elif selection == 'Mon équipe':
        st.title("Bienvenue sur la page des personnages de Futurama")
        col1, col2, col3 = st.columns(3)
        with col1:
            st.header("Leela")
            st.image("leela-1.png")
        with col2:
            st.header("Bender")
            st.image("bender.png")
        with col3:
            st.header("Fry")
            st.image("fry.png")

# Si l'utilisateur n'est pas authentifié
elif st.session_state.get("authentication_status") is False:
    st.error("L'username ou le mot de passe est incorrect")
elif st.session_state.get("authentication_status") is None:
    st.warning('Les champs username et mot de passe doivent être remplis')

# Formulaire d'inscription dans la barre latérale

            
##########################################################################################################################


    