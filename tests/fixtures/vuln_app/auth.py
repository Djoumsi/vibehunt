import hashlib
def store_user(login, password):
    # FAUTE : mot de passe haché en MD5
    pwd_hash = hashlib.md5(password.encode()).hexdigest()
    db.save(login, pwd_hash)
