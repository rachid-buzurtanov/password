import re
import hashlib

def password_check(password):
    if re.search(r'\d', password) and re.search('[A-Z]', password) and re.search('[a-z]', password) and re.search('[!@#$%^&*(),.?":{}|<>]', password) and len(password) >= 8:
        return True
    else:
        return False

def get_password():
    password = input("Choisissez un mot de passe : ")
    
    if password_check(password):
        # Hash du mot de passe avec SHA-256
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        print("Mot de passe valide !")
        print("Mot de passe haché (SHA-256) :", hashed_password)
    else:
        print("Le mot de passe doit contenir au moins 8 caractères, une lettre majuscule, une lettre minuscule et un chiffre.")
        get_password()

get_password()
