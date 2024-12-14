# Blog Minimaliste

Un blog personnel minimaliste avec interface d'administration, développé avec Flask.

## Caractéristiques

- Design minimaliste noir sur blanc
- Publication d'articles en Markdown
- Navigation par tags
- Interface d'administration sécurisée
- Gestion simple des articles (création, modification, suppression)

## Installation

1. Cloner le repository
2. Créer un environnement virtuel :
   ```bash
   python -m venv venv
   source venv/bin/activate  # Sur Unix
   ```
3. Installer les dépendances :
   ```bash
   pip install -r requirements.txt
   ```
4. Configurer les variables d'environnement dans `.env`
5. Initialiser la base de données :
   ```bash
   flask db upgrade
   ```
6. Lancer l'application :
   ```bash
   flask run
   ```

## Structure du Projet

- `app.py` : Application principale Flask
- `models.py` : Modèles de données SQLAlchemy
- `forms.py` : Formulaires WTForms
- `templates/` : Templates HTML
- `static/` : Fichiers statiques (CSS, JS)
