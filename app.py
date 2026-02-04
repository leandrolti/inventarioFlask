import os
from flask import Flask, abort, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import func # Adicione isso no topo do arquivo
# 2. Decorador para restringir acesso por função
from functools import wraps
from flask_migrate import Migrate  # Adicione este import


app = Flask(__name__)
app.config['SECRET_KEY'] = 'chave-secreta-facil'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# --- MODELOS DO BANCO DE DADOS ---

# 1. Atualize o modelo User
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), default='Viewer') # 'Admin', 'Analista', 'Viewer'

def role_required(roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if current_user.role not in roles:
                abort(403) # Proibido
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# 1. No Modelo Ativo, adicione a coluna quantidade
class Ativo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    num_serie = db.Column(db.String(100))  # <-- NOVO CAMPO
    tombamento = db.Column(db.String(50), default="Não há tombamento") # Novo campo
    localizacao = db.Column(db.String(200)) # Novo campo
    categoria = db.Column(db.String(50))
    status = db.Column(db.String(50))
    quantidade = db.Column(db.Integer, default=1)
    descricao = db.Column(db.String(200))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# --- ROTAS ---

@app.route('/')
@login_required
def dashboard():
    # Usamos func.sum para somar a coluna quantidade de cada categoria
    def contar(cat):
        resultado = db.session.query(func.sum(Ativo.quantidade)).filter_by(categoria=cat).scalar()
        return resultado if resultado else 0

    contagem = {
        'total': db.session.query(func.sum(Ativo.quantidade)).scalar() or 0,
        'hardware': contar('Hardware'),
        'software': contar('Software'),
        'redes': contar('Redes'),
        'robotica': contar('Robótica')
    }
    return render_template('dashboard.html', dados=contagem)


# Rota para o Admin gerenciar usuários
@app.route('/usuarios', methods=['GET', 'POST'])
@login_required
@role_required(['Admin'])
def gerenciar_usuarios():
    if request.method == 'POST':
        novo_user = User(
            username=request.form['username'],
            password=generate_password_hash(request.form['password']),
            role=request.form['role']
        )
        db.session.add(novo_user)
        db.session.commit()
        flash('Novo usuário cadastrado!')

    lista_usuarios = User.query.all()
    return render_template('usuarios.html', usuarios=lista_usuarios)


# Rota de Perfil (Analista e Admin podem editar seu próprio perfil)
@app.route('/perfil', methods=['GET', 'POST'])
@login_required
def perfil():
    if request.method == 'POST':
        current_user.username = request.form['username']
        if request.form['password']:
            current_user.password = generate_password_hash(request.form['password'])
        db.session.commit()
        flash('Perfil atualizado!')
    return render_template('perfil.html')

# 2. Na rota /ativos, capture a quantidade vinda do formulário
@app.route('/ativos', methods=['GET', 'POST'])
@login_required
def ativos():
    if request.method == 'POST':
        # Lógica para o valor padrão do tombamento
        tomb = request.form['tombamento'].strip()
        if not tomb:
            tomb = "Não há tombamento"

        novo = Ativo(
            nome=request.form['nome'],
            num_serie=request.form['num_serie'],
            tombamento=tomb,
            localizacao=request.form['localizacao'],
            categoria=request.form['categoria'],
            status=request.form['status'],
            quantidade=int(request.form['quantidade']),
            descricao=request.form['descricao']
        )
        db.session.add(novo)
        db.session.commit()
        return redirect(url_for('ativos'))

    todos_ativos = Ativo.query.all()
    return render_template('ativos.html', ativos=todos_ativos)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Usuário ou senha incorretos!')
    return render_template('login.html')


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


# Rota para Deletar
@app.route('/deletar/<int:id>')
@login_required
def deletar_ativo(id):
    ativo = Ativo.query.get_or_404(id)
    nome_removido = ativo.nome # Guarda o nome para a mensagem
    db.session.delete(ativo)
    db.session.commit()
    flash(f'O ativo "{nome_removido}" foi excluído permanentemente.')
    return redirect(url_for('ativos'))


# Rota para Editar (Exibir formulário e Salvar)
@app.route('/editar/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_ativo(id):
    ativo = Ativo.query.get_or_404(id)
    if request.method == 'POST':
        ativo.nome = request.form['nome']
        ativo.num_serie = request.form['num_serie']  # <-- ATUALIZA AQUI
        ativo.tombamento = request.form['tombamento'] or "Não há tombamento"
        ativo.localizacao = request.form['localizacao']
        ativo.categoria = request.form['categoria']
        ativo.quantidade = int(request.form['quantidade'])
        ativo.status = request.form['status']
        ativo.descricao = request.form['descricao']

        db.session.commit()
        flash('Ativo atualizado com sucesso!')
        return redirect(url_for('ativos'))

    return render_template('editar_ativo.html', ativo=ativo)


# Rota para deletar usuário
@app.route('/deletar_usuario/<int:id>')
@login_required
@role_required(['Admin'])
def deletar_usuario(id):
    if id == current_user.id:
        flash('Você não pode deletar sua própria conta!')
        return redirect(url_for('gerenciar_usuarios'))

    user = User.query.get_or_404(id)
    db.session.delete(user)
    db.session.commit()
    flash(f'Usuário {user.username} removido!')
    return redirect(url_for('gerenciar_usuarios'))


# Rota para editar usuário
@app.route('/editar_usuario/<int:id>', methods=['GET', 'POST'])
@login_required
@role_required(['Admin'])
def editar_usuario(id):
    user = User.query.get_or_404(id)
    if request.method == 'POST':
        user.username = request.form['username']
        user.role = request.form['role']
        if request.form['password']:
            user.password = generate_password_hash(request.form['password'])

        db.session.commit()
        flash('Usuário atualizado com sucesso!')
        return redirect(url_for('gerenciar_usuarios'))

    return render_template('editar_usuario.html', user=user)


# --- INICIALIZAÇÃO ---
if __name__ == '__main__':
    with app.app_context():
        # 1. Cria o arquivo de banco de dados e as tabelas se não existirem
        db.create_all()

        # 2. Verifica se o admin já existe dentro do contexto da aplicação
        admin_atual = User.query.filter_by(username='admin').first()

        if not admin_atual:
            print("Criando usuário administrador padrão...")
            hashed_pw = generate_password_hash('admin123')
            user_admin = User(
                username='admin',
                password=hashed_pw,
                role='Admin'
            )
            db.session.add(user_admin)
            db.session.commit()
            print("Admin criado com sucesso!")

    # 3. Roda o servidor (fora do bloco with)
    app.run(debug=True)
