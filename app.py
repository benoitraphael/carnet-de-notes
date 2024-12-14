from flask import Flask, render_template, flash, redirect, url_for, request, session
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
from models import db, User, Notebook, Post, Tag
from datetime import datetime, timedelta
from functools import wraps
import secrets
import os
import markdown
from markupsafe import Markup

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'dev-key-12345')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///./blog.db')
if app.config['SQLALCHEMY_DATABASE_URI'].startswith('postgres://'):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['DEBUG'] = os.environ.get('FLASK_ENV') != 'production'
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_TIME_LIMIT'] = None

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Veuillez vous connecter pour accéder à cette page.'
login_manager.login_message_category = 'error'

def markdown_filter(text):
    return Markup(markdown.markdown(text))

app.jinja_env.filters['markdown'] = markdown_filter

csrf = CSRFProtect()
csrf.init_app(app)
db.init_app(app)

def init_db():
    """Initialise la base de données avec les tables nécessaires"""
    with app.app_context():
        # Créer les tables si elles n'existent pas
        db.create_all()
        
        # Vérifier si l'admin existe déjà
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            # Créer un compte admin par défaut
            admin = User(
                username='admin',
                email='admin@example.com',
                password_hash=generate_password_hash('admin'),
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()

            # Créer un carnet pour l'admin avec un slug unique
            notebook = Notebook(
                title="Notes",
                baseline="Mon carnet de notes",
                slug="notes-admin",
                user_id=admin.id
            )
            db.session.add(notebook)
            db.session.commit()

# Initialiser la base de données au démarrage seulement si elle n'existe pas
if not os.path.exists('blog.db'):
    init_db()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    if current_user.is_authenticated:
        try:
            notebook = Notebook.query.filter_by(user_id=current_user.id).first()
            if not notebook:  # Si l'utilisateur n'a pas de carnet, on en crée un
                # Créer un slug unique basé sur le nom d'utilisateur
                slug = f"notes-{current_user.username}"
                notebook = Notebook(
                    title="Notes",  # Utiliser title au lieu de name
                    baseline="Mon carnet de notes",  # Ajouter une baseline par défaut
                    slug=slug,
                    user_id=current_user.id  # Utiliser user_id au lieu de user
                )
                db.session.add(notebook)
                db.session.commit()
            
            posts = Post.query.filter_by(notebook_id=notebook.id).order_by(Post.created_at.desc()).all()
            return render_template('authenticated.html', posts=posts)
        except Exception as e:
            app.logger.error(f"Erreur lors de l'accès à la page d'accueil : {str(e)}")
            flash("Une erreur s'est produite. Veuillez réessayer.", "error")
            return render_template('authenticated.html', posts=[])
    
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        
        # Vérifier si l'utilisateur existe déjà
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Ce nom d\'utilisateur est déjà pris')
            return redirect(url_for('register'))
        
        # Créer un nouvel utilisateur
        # Pour le développement : le premier utilisateur sera admin
        is_admin = User.query.count() == 0  # Si c'est le premier utilisateur
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            is_admin=is_admin
        )
        
        db.session.add(user)
        db.session.commit()
        
        if is_admin:
            flash('Compte administrateur créé avec succès !')
        else:
            flash('Compte créé avec succès !')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Si déjà connecté, rediriger vers l'accueil
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    # Si ce n'est pas une requête POST, afficher le formulaire
    if request.method != 'POST':
        return render_template('login.html')

    # Récupérer les données du formulaire
    username = request.form.get('username')
    password = request.form.get('password')

    # Vérifier que les champs sont remplis
    if not username or not password:
        flash('Veuillez remplir tous les champs.', 'error')
        return render_template('login.html')

    try:
        # Chercher l'utilisateur
        user = User.query.filter_by(username=username).first()
        if not user:
            flash('Nom d\'utilisateur ou mot de passe incorrect.', 'error')
            return render_template('login.html')

        # Vérifier le mot de passe
        if not check_password_hash(user.password_hash, password):
            flash('Nom d\'utilisateur ou mot de passe incorrect.', 'error')
            return render_template('login.html')

        # Connecter l'utilisateur
        login_user(user)
        return redirect(url_for('index'))

    except Exception as e:
        app.logger.error(f'Erreur de connexion: {str(e)}')
        flash('Une erreur technique s\'est produite.', 'error')
        return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Générer un token unique
            token = secrets.token_urlsafe(32)
            user.reset_token = token
            user.reset_token_expiry = datetime.utcnow() + timedelta(hours=24)
            db.session.commit()
            
            # Créer le lien cliquable
            reset_link = url_for('reset_password', token=token, _external=True)
            flash(f'Cliquez sur ce lien pour réinitialiser votre mot de passe : <a href="{reset_link}">{reset_link}</a>')
            return redirect(url_for('login'))
        
        flash('Aucun compte trouvé avec cet email')
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()
    
    if not user or user.reset_token_expiry < datetime.utcnow():
        flash('Le lien de réinitialisation est invalide ou a expiré')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        user.password_hash = generate_password_hash(password)
        user.reset_token = None
        user.reset_token_expiry = None
        db.session.commit()
        
        flash('Votre mot de passe a été réinitialisé avec succès')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html')

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Accès refusé. Cette page est réservée aux administrateurs.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    users = User.query.all()
    return render_template('admin_users.html', users=users)

@app.route('/notes/new', methods=['GET', 'POST'])
@login_required
def new_note():
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        tags = request.form.get('tags', '').split(',')
        tags = [tag.strip() for tag in tags if tag.strip()]  # Nettoyer les tags

        # Créer un nouveau carnet s'il n'existe pas
        notebook = Notebook.query.filter_by(user_id=current_user.id, title="Notes").first()
        if not notebook:
            notebook = Notebook(
                title="Notes",
                baseline="Mon carnet de notes",
                slug="notes",
                user_id=current_user.id
            )
            db.session.add(notebook)
            db.session.commit()

        # Créer la note
        post = Post(
            title=title,
            content=content,
            notebook_id=notebook.id
        )
        db.session.add(post)

        # Ajouter les tags
        for tag_name in tags:
            tag = Tag.query.filter_by(name=tag_name, notebook_id=notebook.id).first()
            if not tag:
                tag = Tag(name=tag_name, notebook_id=notebook.id)
                db.session.add(tag)
            post.tags.append(tag)

        db.session.commit()
        flash('Note créée avec succès!')
        return redirect(url_for('index'))

    # Passer un dictionnaire vide pour simuler un nouveau post
    return render_template('post_form.html', post=None)

@app.route('/notes/<int:note_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_note(note_id):
    post = Post.query.get_or_404(note_id)
    notebook = Notebook.query.get_or_404(post.notebook_id)
    
    # Vérifier que l'utilisateur est propriétaire de la note
    if notebook.user_id != current_user.id:
        flash('Vous n\'avez pas le droit de modifier cette note')
        return redirect(url_for('index'))

    if request.method == 'POST':
        post.title = request.form.get('title')
        post.content = request.form.get('content')
        post.updated_at = datetime.utcnow()
        
        # Mettre à jour les tags
        post.tags.clear()
        tags = request.form.get('tags', '').split(',')
        tags = [tag.strip() for tag in tags if tag.strip()]
        
        for tag_name in tags:
            tag = Tag.query.filter_by(name=tag_name, notebook_id=notebook.id).first()
            if not tag:
                tag = Tag(name=tag_name, notebook_id=notebook.id)
                db.session.add(tag)
            post.tags.append(tag)

        db.session.commit()
        flash('Note modifiée avec succès!')
        return redirect(url_for('index'))

    tags = ', '.join(tag.name for tag in post.tags)
    return render_template('post_form.html', post=post, tags=tags)

@app.route('/notes/<int:note_id>/delete', methods=['POST'])
@login_required
def delete_note(note_id):
    post = Post.query.get_or_404(note_id)
    notebook = Notebook.query.get_or_404(post.notebook_id)
    
    if notebook.user_id != current_user.id:
        flash('Vous n\'avez pas le droit de supprimer cette note')
        return redirect(url_for('index'))

    db.session.delete(post)
    db.session.commit()
    flash('Note supprimée avec succès!')
    return redirect(url_for('index'))

@app.route('/post/<int:post_id>')
@login_required
def view_post(post_id):
    post = Post.query.get_or_404(post_id)
    notebook = Notebook.query.get(post.notebook_id)
    
    # Vérifier que l'utilisateur a accès à cette note
    if notebook.user_id != current_user.id and not current_user.is_admin:
        flash('Vous n\'avez pas accès à cette note.')
        return redirect(url_for('index'))
        
    return render_template('post.html', post=post)

@app.route('/tags')
@login_required
def tags():
    # Récupérer le carnet de l'utilisateur
    notebook = Notebook.query.filter_by(user_id=current_user.id).first()
    if notebook:
        # Récupérer tous les tags du carnet
        tags = Tag.query.filter_by(notebook_id=notebook.id).all()
        
        # Compter le nombre de notes pour chaque tag
        tag_counts = {}
        for tag in tags:
            tag_counts[tag] = len(tag.posts)
            
        return render_template('tags.html', tags=tags, tag_counts=tag_counts)
    return render_template('tags.html', tags=[], tag_counts={})

@app.route('/tag/<tag_name>')
@login_required
def tag(tag_name):
    # Récupérer le tag du carnet de l'utilisateur
    tag = Tag.query.filter_by(
        name=tag_name, 
        notebook_id=Notebook.query.filter_by(user_id=current_user.id).first().id
    ).first_or_404()
    
    # Filtrer les posts qui ont ce tag
    posts = Post.query\
        .join(Post.tags)\
        .join(Post.notebook)\
        .filter(
            Tag.id == tag.id,
            Notebook.user_id == current_user.id
        )\
        .order_by(Post.created_at.desc())\
        .all()
    
    return render_template('tag.html', tag=tag, posts=posts)

if __name__ == '__main__':
    app.run(debug=True)
else:
    with app.app_context():
        db.create_all()