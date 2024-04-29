from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import os
import secrets
from werkzeug.utils import secure_filename
import base64
from datetime import datetime
import random
import string
from flask_mail import Message, Mail
from config import email,senha
from werkzeug.security import generate_password_hash, check_password_hash
from flask_bcrypt import Bcrypt


app = Flask(__name__)
app.secret_key = 'site_pega_visao'  # Chave secreta para o uso do session
bcrypt = Bcrypt(app)

# Configuração do Flask-Mail para o Gmail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = email
app.config['MAIL_PASSWORD'] = senha

mail = Mail(app)
senha_hasheada = bcrypt.generate_password_hash(senha).decode('utf-8')

def create_connection():
    conn = sqlite3.connect('pegavisao.db')
    return conn

# Função para converter a string em float
def str_to_float(value):
    try:
        return float(value)
    except ValueError:
        return 0.0  # Ou qualquer valor padrão que você queira

#FUNÇÕES
# Função para verificar se um e-mail já está em uso
def email_existe(email):
    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM usuarios WHERE email = ?', (email,))
    usuario = cursor.fetchone()

    conn.close()

    return usuario is not None

def enviar_email_senha(email, token):
    # URL para a página de redefinição de senha
    reset_url = url_for('redefinir_senha', token=token, _external=True)

    # Corpo do email com o link de redefinição de senha
    msg = Message('Redefinição de Senha', sender='your-email@example.com', recipients=[email])
    msg.body = f"Olá,\n\nRecebemos uma solicitação para redefinir a senha da sua conta. Para concluir esse processo, " \
               f"por favor clique no link abaixo ou cole-o em seu navegador:\n\n{reset_url}\n\nSe você não solicitou " \
               f"essa alteração, por favor ignore este email.\n\nAtenciosamente,\Equipe de Suporte"

    mail.send(msg)

# Função para obter usuário por nome de usuário
def obter_usuario_por_nome(nome_usuario):
    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM usuarios WHERE nome = ?', (nome_usuario,))
    usuario = cursor.fetchone()

    conn.close()

    return usuario


# Função para atualizar a senha no banco de dados
def atualizar_senha(email, nova_senha):
    conn = create_connection()
    cursor = conn.cursor()

    # Atualizar a senha do usuário no banco de dados
    cursor.execute('UPDATE usuarios SET senha = ? WHERE email = ?', (nova_senha, email))

    conn.commit()
    conn.close()

#Função de formatar as opções 
def formatar_funcao(funcao):
    # Remover caracteres especiais e converter para minúsculas
    funcao_formatada = funcao.lower().replace("ç", "c").replace("ã", "a").replace("õ", "o").replace(" ", "_")
    return funcao_formatada

def obter_usuario_por_email(email):
    with sqlite3.connect('pegavisao.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM usuarios WHERE email = ?', (email,))
        usuario = cursor.fetchone()
        if usuario:
            return {'id': usuario[0], 'nome': usuario[1], 'email': usuario[4], 'senha': usuario[3]}
        else:
            return None
        
# Função para salvar o token de redefinição de senha no banco de dados
def salvar_token(nome_usuario, token):
    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute('INSERT INTO tokens (user_id, token) VALUES (?, ?)', (nome_usuario, token))

    conn.commit()
    conn.close()

# Função para verificar se o token é válido e obter o usuário associado a ele
def obter_usuario_por_token(token):
    conn = sqlite3.connect('pegavisao.db')
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM tokens WHERE token = ? AND used = 0', (token,))
    token_salvo = cursor.fetchone()

    if token_salvo:
        user_id = token_salvo[1]
        print(f"ID do usuário encontrado: {user_id}")  # Adicione essa linha para depuração
        cursor.execute('SELECT * FROM usuarios WHERE id = ?', (user_id,))
        usuario = cursor.fetchone()

        conn.close()

        return usuario
    else:
        conn.close()
        return None

@app.route("/", methods=["GET", "POST"])
@app.route("/home", methods=["GET", "POST"])
def home():
    tipos = ["Filme", "Serie"]  # Lista de opções para o tipo
    user_function = get_user_function()
    user_logged_in = 'user_id' in session
    user_name = session.get('user_name', '')  # Obtém o nome do usuário da sessão

    if user_function == 'admin':  # Verifica se o usuário é administrador
        if request.method == "POST":
            tipo = request.form["tipo"]
            titulo = request.form["titulo"]
            ano = request.form["ano"]
            dia_assistido = request.form["dia_assistido"]
            avaliacao = request.form["avaliacao"]
            opiniao = request.form["opiniao"]
            capa = request.files["capa"]  # Obtém o arquivo da capa

            # Salvar a capa no banco de dados
            if capa.filename != '':
                capa_base64 = base64.b64encode(capa.read()).decode('utf-8')
            else:
                flash('Selecione um arquivo de imagem para a capa.', 'error')
                return redirect(url_for('home'))

            # Inserir os dados do filme ou série no banco de dados
            with create_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO filmesseries (tipo, titulo, ano, dia_assistido, avaliacao, opiniao, capa)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (tipo, titulo, ano, dia_assistido, avaliacao, opiniao, capa_base64))
                conn.commit()

            flash('Filme ou série adicionado com sucesso!', 'success')
            return redirect(url_for('home'))
        
    
    # Recupera os dados dos filmes ou séries do banco de dados
    with create_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM filmesseries WHERE tipo = "Filme" ORDER BY id DESC LIMIT 6')
        fimes_recentes = cursor.fetchall()
    
    with create_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM filmesseries WHERE tipo = "Serie" ORDER BY id DESC LIMIT 6')
        series_recentes = cursor.fetchall()


    with sqlite3.connect('pegavisao.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT email FROM usuarios')
        usuario_email = [row[0] for row in cursor.fetchall()]
                         

    return render_template('pagina_inicial.html', user_function=user_function, user_logged_in=user_logged_in, user_name=user_name, usuario_email=usuario_email, tipos=tipos, fimes_recentes=fimes_recentes, series_recentes=series_recentes, str_to_float=str_to_float)

@app.route("/remover_filme/<int:filme_id>", methods=["POST"])
def remover_filme(filme_id):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM filmesseries WHERE id = ?', (filme_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('home'))

def get_user_function():
    if 'user_id' in session:
        user_id = session['user_id']
        with create_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT nome, funcao FROM usuarios WHERE id = ?', (user_id,))
            user_data = cursor.fetchone()
            if user_data:
                user_name, user_function = user_data
                return user_function

    return 'visitante'

@app.route("/cadastro", methods=["GET", "POST"])
def cadastro():
    # Defina os valores padrão para os campos
    nome = ''
    email = ''
    # Permitir que apenas visitantes acessem a página de cadastro
    if get_user_function() != 'visitante':
        return redirect(url_for('home'))

    funcoes = ["comentarista", "admin"]  # Defina os tipos de função disponíveis
    if request.method == "POST":
        nome = request.form["nome"].lower()
        email = request.form["email"].lower()
        senha = request.form["senha"]
        funcao = request.form["funcao"]

        # Verificar se o email já está cadastrado
        conn = create_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM usuarios WHERE email = ?', (email,))
        existing_user = cursor.fetchone()
        conn.close()

        if existing_user:
            flash('Email já cadastrado. Por favor, escolha outro email.', 'error')
            return render_template('cadastro.html', funcoes=funcoes, nome=nome, email=email)
        if len(senha) < 8 or not any(char.isalpha() for char in senha) or not any(char.isdigit() for char in senha):
            flash('A senha deve ter pelo menos 8 caracteres, incluindo letras e números.', 'error')
            return render_template('cadastro.html', funcoes=funcoes, nome=nome, email=email)
        else:

             # Hash da senha antes de armazenar no banco de dados
            senha_hash = bcrypt.generate_password_hash(senha).decode('utf-8')
            # Inserir o novo usuário apenas se o email não estiver cadastrado e a senha for válida
            conn = create_connection()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO usuarios (email, nome, funcao, senha)
                VALUES (?,?, ?, ?)
            ''', (email,nome, funcao, senha_hash))
            conn.commit()
            conn.close()

            flash('Cadastro realizado com sucesso!', 'success')
            return render_template('pagina_inicial.html')

    # Se houver um erro, devolva os valores dos campos de formulário
    return render_template('cadastro.html', funcoes=funcoes, nome=nome, email=email)

@app.route('/autenticar', methods=['POST'])
def autenticar():
    message = ''
    if request.method == "POST":
        email = request.form["email"].lower()
        senha = request.form["senha"]
        conn = create_connection()
        cursor = conn.cursor()
        # Buscar usuário pelo nome de usuário
        cursor.execute('SELECT * FROM usuarios WHERE email = ?', (email,))
        user = cursor.fetchone()
        conn.close()

        if user and bcrypt.check_password_hash(user[3], senha):
            session['user_id'] = user[0]  # Armazenar o ID do usuário na sessão
            session['user_name'] = user[1]  # Armazena o nome do usuário na sessão
            session['user_function'] = user[2]  # Armazena a função do usuário na sessão
            return redirect(url_for('home'))
        else:
            message = 'Email ou senha incorretos. Tente novamente.'
            return redirect(url_for('home', message=message))

    return render_template('pagina_inicial.html', message=message)

@app.route("/logout", methods=["POST"])
def logout():
    # Remover o ID do usuário da sessão ao fazer logout
    session.pop('user_id', None)
    return redirect(url_for('home'))

# Rota para redefinir a senha
@app.route('/esqueci_minha_senha', methods=['GET', 'POST'])
def esqueci_minha_senha():
    if request.method == 'POST':
        email = request.form['email']

        # Verificar se o e-mail existe na base de dados
        usuario = obter_usuario_por_email(email)

        if usuario:
            # Gerar um token seguro
            token = secrets.token_urlsafe(32)

            # Salvar o token no banco de dados
            salvar_token(usuario['id'], token)
            
            # Enviar e-mail com o token
            enviar_email_senha(usuario['email'], token)

            mensagem = "Uma nova senha foi enviada para o seu email."

            return render_template("pagina_inicial.html")
        else:
            mensagem = "Email não encontrado."

        return render_template("esqueci_minha_senha.html", mensagem=mensagem)

    return render_template("esqueci_minha_senha.html")

# Rota para redefinir a senha após a confirmação
@app.route('/redefinir_senha/<token>', methods=['GET', 'POST'])
def redefinir_senha(token):
    # Verificar se o token é válido
    usuario = obter_usuario_por_token(token)

    if usuario is None:
        flash('Token inválido ou expirado. Por favor, solicite um novo token.')
        return redirect(url_for('esqueci_minha_senha'))

    if request.method == 'POST':
        nova_senha = request.form['nova_senha']
        confirmar_senha = request.form['confirmar_senha']

        if nova_senha != confirmar_senha:
            flash('As senhas digitadas não coincidem. Por favor, tente novamente.')
            return render_template('redefinir_senha.html', token=token)

        # Hash da nova senha antes de atualizar no banco de dados
        nova_senha_hash = bcrypt.generate_password_hash(nova_senha).decode('utf-8')

        # Atualizar a senha do usuário no banco de dados
        atualizar_senha(usuario[4], nova_senha_hash)

        flash('Senha redefinida com sucesso. Você já pode fazer login com sua nova senha.')
        return redirect(url_for('home'))

    return render_template('redefinir_senha.html', token=token)

@app.route("/filmes")
def filmes():
    user_function = get_user_function()
    user_logged_in = 'user_id' in session
    user_name = session.get('user_name', '') 
    with create_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM filmesseries ORDER BY id DESC')
        filmes_series = cursor.fetchall()

    cursor.execute('''
        SELECT * FROM filmesseries
        WHERE tipo = 'Filme'
        ORDER BY CAST(avaliacao AS REAL) DESC
    ''')
    filmes_mais_avaliados = cursor.fetchall()

    return render_template('filmes.html',  filmes_series=filmes_series,user_function=user_function,filmes_mais_avaliados=filmes_mais_avaliados, str_to_float=str_to_float, user_logged_in=user_logged_in, user_name=user_name)

@app.route("/series")
def series():
    user_function = get_user_function()
    user_logged_in = 'user_id' in session
    user_name = session.get('user_name', '')
    with create_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM filmesseries ORDER BY id DESC')
        filmes_series = cursor.fetchall() 

    cursor.execute('''
        SELECT * FROM filmesseries
        WHERE tipo = 'Serie'
        ORDER BY CAST(avaliacao AS REAL) DESC
    ''')
    filmes_mais_avaliados = cursor.fetchall()


    return render_template('series.html',  filmes_series=filmes_series, filmes_mais_avaliados=filmes_mais_avaliados, user_function=user_function, str_to_float=str_to_float, user_logged_in=user_logged_in, user_name=user_name)

@app.route("/remover_comentario/<int:comentario_id>", methods=["POST"])
def remover_comentario(comentario_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    user_function = get_user_function()

    with create_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT usuario_id FROM comentarios WHERE id = ?', (comentario_id,))
        comentario = cursor.fetchone()

        # Verifica se o usuário é o dono do comentário ou um admin
        if comentario and (user_function == 'admin' or comentario[0] == user_id):
            cursor.execute('DELETE FROM comentarios WHERE id = ?', (comentario_id,))
            conn.commit()
            flash('Comentário removido com sucesso.', 'success')
        else:
            flash('Você não tem permissão para remover este comentário.', 'danger')

    return redirect(url_for('detalhes', filme_id=request.form['filme_id']))

@app.route("/adicionar_comentario/<int:filme_id>", methods=["POST"])
def adicionar_comentario(filme_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    comentario = request.form['comentario']
    data_comentario = int(datetime.now().timestamp())  # Timestamp UNIX atual

    with create_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT nome FROM usuarios WHERE id = ?', (user_id,))
        nome_usuario = cursor.fetchone()[0]  # Obtém o nome do usuário
        cursor.execute('INSERT INTO comentarios (filme_id, usuario_id, nome_usuario, comentario, data_comentario) VALUES (?, ?, ?, ?, ?)', (filme_id, user_id, nome_usuario, comentario, data_comentario))
        conn.commit()

    return redirect(url_for('detalhes', filme_id=filme_id))

@app.route("/detalhes/<int:filme_id>", methods=["GET", "POST"])
def detalhes(filme_id):
    with create_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM filmesseries WHERE id = ?', (filme_id,))
        filme_serie = cursor.fetchone()

        cursor.execute('''
            SELECT comentarios.*, usuarios.nome as nome_usuario
            FROM comentarios
            INNER JOIN usuarios ON comentarios.usuario_id = usuarios.id
            WHERE comentarios.filme_id = ?
            ORDER BY comentarios.data_comentario DESC
        ''', (filme_id,))
        comentarios = cursor.fetchall()

    tipos = ["Filme", "Serie"]
    user_logged_in = 'user_id' in session
    user_name = session.get('user_name', '')
    user_function = get_user_function()

    if not filme_serie:
        return "Filme ou série não encontrado."

    if request.method == "POST":
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user_id = session['user_id']
        comentario = request.form['comentario']

        with create_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT nome FROM usuarios WHERE id = ?', (user_id,))
            nome_usuario = cursor.fetchone()[0]  # Obtém o nome do usuário
            cursor.execute('INSERT INTO comentarios (filme_id, usuario_id, nome_usuario, comentario) VALUES (?, ?, ?, ?)', (filme_id, user_id, nome_usuario, comentario))
            conn.commit()
        return redirect(url_for('detalhes', filme_id=filme_id))

    return render_template('detalhes_filme.html', filme_serie=filme_serie, user_function=user_function, str_to_float=str_to_float, user_logged_in=user_logged_in, user_name=user_name, tipos=tipos, comentarios=comentarios)

@app.route("/pesquisar", methods=["GET"])
def pesquisar():
    termo_pesquisa = request.args.get('termo_pesquisa', '')

    print(termo_pesquisa)

    resultados = []  # Inicializa resultados como uma lista vazia

    if termo_pesquisa:
        with create_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM filmesseries WHERE titulo LIKE ?', ('%' + termo_pesquisa + '%',))
            resultados = cursor.fetchall()

    user_logged_in = 'user_id' in session
    user_name = session.get('user_name', '')
    user_function = get_user_function()

    return render_template('resultado_pesquisa.html', resultados=resultados, str_to_float=str_to_float, termo_pesquisa=termo_pesquisa, user_logged_in=user_logged_in, user_name=user_name, user_function=user_function)


if __name__ == '__main__':
    # Criar tabela de usuários se não existir
        conn = sqlite3.connect('pegavisao.db')
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT NOT NULL,
                funcao TEXT NOT NULL,
                senha TEXT NOT NULL,
                email TEXT NOT NULL
            );
        ''')
            # Criar tabela de tokens de redefinição de senha se não existir
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT NOT NULL,
                used INTEGER DEFAULT 0,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES usuarios(id)
            );
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS filmesseries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tipo TEXT NOT NULL,
                titulo TEXT NOT NULL,
                ano TEXT NOT NULL,
                dia_assistido TEXT NOT NULL,
                avaliacao INTEGER NOT NULL,
                opiniao TEXT NOT NULL,
                capa TEXT NOT NULL,
                comentarios TEXT DEFAULT 'Nenhum comentário disponível.'
            );
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS comentarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT, --0
                filme_id INTEGER NOT NULL, --1
                usuario_id INTEGER NOT NULL, --2
                nome_usuario TEXT, --3
                comentario TEXT NOT NULL, --4
                data_comentario TEXT,  --5 
                FOREIGN KEY(filme_id) REFERENCES filmesseries(id), --6
                FOREIGN KEY(usuario_id) REFERENCES usuarios(id) --7
            );
        ''')

        conn.commit()
        conn.close()

        app.run(debug=True)