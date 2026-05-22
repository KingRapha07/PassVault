#  PassVault — Gestionnaire de mots de passe web

Application web sécurisée pour stocker et gérer ses mots de passe, avec chiffrement AES-256.

##  Fonctionnalités

-  **Chiffrement AES-256** (Fernet) — chaque mot de passe est chiffré avant d'être stocké
-  **Mot de passe maître** — dérivé via PBKDF2-SHA256 (480 000 itérations)
-  **Révélation à la demande** — les mots de passe restent masqués par défaut
-  **Copie en un clic** — copier un mot de passe sans l'afficher
-  **Générateur** — génère des mots de passe forts aléatoires
-  **Catégories** — organiser par type (travail, réseaux sociaux, banque...)
-  **Recherche** — filtrer par site, identifiant ou catégorie
-  **SQLite** — base de données locale, aucune donnée envoyée sur internet

##  Installation

```bash
git clone https://github.com/<pseudo>/passvault.git
cd passvault
pip install -r requirements.txt
python app.py
```

Ouvre ton navigateur sur : **http://127.0.0.1:5000**

## Technologies

| Outil | Rôle |
|-------|------|
| Python 3.10+ | Langage principal |
| Flask | Framework web |
| SQLite3 | Base de données embarquée |
| cryptography (Fernet) | Chiffrement AES-256 |
| PBKDF2-SHA256 | Dérivation du mot de passe maître |
| HTML/CSS + JS | Interface utilisateur |

##  Sécurité

- Les mots de passe ne sont **jamais stockés en clair** dans la base de données
- Le mot de passe maître n'est **jamais stocké** — seulement son hash PBKDF2
- La clé de chiffrement est **dérivée à la volée** depuis le mot de passe maître
- Le sel cryptographique est unique et généré aléatoirement à la création

