import hashlib
import bcrypt

# Liste des noms des algorithmes de hachage disponibles dans la bibliothèque hashlib
hash_names = [
    "md5", "sha1", "sha224", "sha256", "sha384", "sha512",
    "blake2b", "blake2s", "sha3_224", "sha3_256", "sha3_384",
    "sha3_512", "shake_128", "shake_256"
]

# Demande à l'utilisateur d'entrer un hash
hash_string = input("Entrez le hash : ")

# Vérifie le type de hash en essayant chaque algorithme de hachage disponible
for name in hash_names:
    try:
        hash_bytes = bytes.fromhex(hash_string)
        h = hashlib.new(name, hash_bytes)
        h.hexdigest()
        print("Le hash est un hash", name.upper())
        break
    except:
        pass
else:
    # Vérifie si le hash est un hash bcrypt
    try:
        bcrypt.checkpw(b"password", hash_string.encode())
        print("Le hash est un hash Bcrypt")
    except:
        print("Le hash n'est pas reconnu")
