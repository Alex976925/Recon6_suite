import os
from werkzeug.security import generate_password_hash, check_password_hash

USERS_FILE = "usuarios.txt"

def guardar_usuario(usuario, clave):
    hash_clave = generate_password_hash(clave)
    with open(USERS_FILE, "a") as f:
        f.write(f"{usuario}:{hash_clave}\n")

def verificar_usuario(usuario, clave):
    if not os.path.exists(USERS_FILE):
        return False
    with open(USERS_FILE) as f:
        for linea in f:
            u, hash_c = linea.strip().split(":", 1)
            if u == usuario and check_password_hash(hash_c, clave):
                return True
    return False
