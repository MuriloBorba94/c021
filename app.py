from flask import Flask, render_template_string, request, redirect, url_for, session, jsonify, render_template, send_file
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import pandas as pd
import io

app = Flask(__name__)
import os
app.secret_key = os.getenv('SECRET_KEY', 'sua_chave_secreta_aqui')

# Inicializa o banco de dados
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        fivem_id TEXT UNIQUE NOT NULL,
        family TEXT NOT NULL,
        password TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS solicitacoes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        client_name TEXT NOT NULL,
        fivem_id TEXT NOT NULL,
        amount REAL NOT NULL,
        created_at TEXT NOT NULL,
        status TEXT DEFAULT 'Pendente',
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_id INTEGER,
        request_id INTEGER,
        action TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (admin_id) REFERENCES users(id),
        FOREIGN KEY (request_id) REFERENCES solicitacoes(id)
    )''')
    # Cria um admin padrão (nome: Admin, fivem_id: admin, family: N/A, senha: admin123)
    try:
        c.execute('INSERT INTO users (name, fivem_id, family, password, is_admin) VALUES (?, ?, ?, ?, ?)',
                 ('Admin', 'admin', 'N/A', generate_password_hash('admin123'), 1))
        conn.commit()
    except sqlite3.IntegrityError:
        pass  # Admin já existe
    conn.close()

# Rota para a raiz (redireciona para login)
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('home'))
    return redirect(url_for('login'))

# Rota para login
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        fivem_id = request.form['fivem_id']
        password = request.form['password']
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT id, password, is_admin FROM users WHERE fivem_id = ?', (fivem_id,))
        user = c.fetchone()
        conn.close()
        if user and check_password_hash(user[1], password):
            session['user_id'] = user[0]
            session['is_admin'] = user[2]
            return redirect(url_for('home'))
        error = 'ID do FiveM ou senha inválidos.'
    return render_template('login.html', error=error)

# Rota para logout
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('is_admin', None)
    return redirect(url_for('login'))

# Rota para cadastro de usuário comum
@app.route('/cadastro_comum', methods=['GET', 'POST'])
def cadastro_comum():
    error = None
    if request.method == 'POST':
        name = request.form['name']
        fivem_id = request.form['fivem_id']
        family = request.form['family']
        password = request.form['password']
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        try:
            c.execute('INSERT INTO users (name, fivem_id, family, password, is_admin) VALUES (?, ?, ?, ?, ?)',
                     (name, fivem_id, family, generate_password_hash(password), 0))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            conn.close()
            error = 'ID do FiveM já existe.'
    return render_template('cadastro_comum.html', error=error)

# Rota para cadastro de administrador
@app.route('/template/cadastro', methods=['GET', 'POST'])
def cadastro():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login'))
    error = None
    if request.method == 'POST':
        name = request.form['name']
        password = request.form['password']
        fivem_id = f'admin_{datetime.now().strftime("%Y%m%d%H%M%S")}'
        family = 'N/A'
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        try:
            c.execute('INSERT INTO users (name, fivem_id, family, password, is_admin) VALUES (?, ?, ?, ?, ?)',
                     (name, fivem_id, family, generate_password_hash(password), 1))
            conn.commit()
            conn.close()
            return redirect(url_for('home'))
        except sqlite3.IntegrityError:
            conn.close()
            error = 'Erro ao cadastrar administrador.'
    return render_template('cadastro_usuario.html', error=error)

# Rota para registrar solicitações
@app.route('/register', methods=['POST'])
def register():
    if 'user_id' not in session:
        return jsonify({'error': 'Não autenticado'}), 401
    client_name = request.form['client_name']
    fivem_id = request.form['fivem_id']
    amount = float(request.form['amount'])
    created_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('INSERT INTO solicitacoes (user_id, client_name, fivem_id, amount, created_at, status) VALUES (?, ?, ?, ?, ?, ?)',
             (session['user_id'], client_name, fivem_id, amount, created_at, 'Pendente'))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Solicitação registrada com sucesso'})

# Rota para visualizar solicitações
@app.route('/template/requests')
def requests():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login'))
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT s.client_name, s.fivem_id, u.family, s.amount, s.created_at, s.status, s.id FROM solicitacoes s JOIN users u ON s.user_id = u.id')
    solicitacoes = c.fetchall()
    conn.close()
    return render_template('requests.html', requests=solicitacoes, is_admin=session.get('is_admin', 0))

# Rota para exportar solicitações para Excel
@app.route('/export_excel')
def export_excel():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login'))
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT s.client_name, s.fivem_id, u.family, s.amount, s.created_at, s.status FROM solicitacoes s JOIN users u ON s.user_id = u.id')
    solicitacoes = c.fetchall()
    conn.close()
    
    # Criar DataFrame com pandas
    df = pd.DataFrame(solicitacoes, columns=['Nome', 'ID FiveM', 'Família', 'Valor (GTA$)', 'Data', 'Status'])
    
    # Criar buffer para o arquivo Excel
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Solicitações')
    
    # Configurar resposta para download
    output.seek(0)
    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        download_name=f'solicitacoes_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xlsx',
        as_attachment=True
    )

# Rota para concluir solicitações
@app.route('/complete/<int:request_id>', methods=['POST'])
def complete_request(request_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Acesso negado'}), 403
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('UPDATE solicitacoes SET status = ? WHERE id = ?', ('Concluído', request_id))
    c.execute('INSERT INTO logs (admin_id, request_id, action, created_at) VALUES (?, ?, ?, ?)',
             (session['user_id'], request_id, 'Concluído', datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Solicitação concluída com sucesso'})

# Rota para excluir solicitações
@app.route('/delete/<int:request_id>', methods=['POST'])
def delete_request(request_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Acesso negado'}), 403
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('UPDATE solicitacoes SET status = ? WHERE id = ?', ('Excluído', request_id))
    c.execute('INSERT INTO logs (admin_id, request_id, action, created_at) VALUES (?, ?, ?, ?)',
             (session['user_id'], request_id, 'Excluído', datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Solicitação excluída com sucesso'})

# Rota para template Home
@app.route('/home')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('index.html', is_admin=session.get('is_admin', 0))

# Rota para template Home (via menu expansivo)
@app.route('/template/home')
def template_home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('home'))

# Inicializa o banco
init_db()

if __name__ == '__main__':
    app.run(debug=True)
