# python -u api.py
from flask import Flask, jsonify, request, send_from_directory, abort
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import os

app = Flask(__name__)

# Configuração do JWT
app.config['JWT_SECRET_KEY'] = 'sua_chave_secreta'  # Altere para uma chave secreta forte
jwt = JWTManager(app)

# Diretório onde os arquivos estão localizados
DIRETORIO_ARQUIVOS = os.path.join(os.getcwd(), 'meus_arquivos')

# Endpoint para gerar token
@app.route('/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({"msg": "Formato de solicitação inválido"}), 400

    username = request.json.get('username', None)
    password = request.json.get('password', None)

    # Validação de credenciais (substitua pela lógica de autenticação real)
    if username != 'usuario' or password != 'senha':
        return jsonify({"msg": "Credenciais inválidas"}), 401

    # Cria o token de acesso
    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token), 200

# Endpoint protegido que requer um token válidos
@app.route('/download/<filename>')
@jwt_required()
def download_file(filename):
    try:
        print(f"Usuário autenticado está solicitando o download do arquivo: {filename}")

        # Caminho completo para o arquivo
        caminho_completo = os.path.join(DIRETORIO_ARQUIVOS, filename)
        print(f"Caminho completo do arquivo: {caminho_completo}")

        # Normaliza o caminho do arquivo
        caminho_completo = os.path.normpath(caminho_completo)

        # Verifica se o caminho está dentro do diretório permitido
        if not caminho_completo.startswith(DIRETORIO_ARQUIVOS):
            print("Tentativa de acesso a caminho inválido.")
            abort(400, "Caminho inválido.")

        # Verifica se o arquivo existe
        if not os.path.isfile(caminho_completo):
            print("Arquivo não encontrado.")
            abort(404, "Arquivo não encontrado.")

        print(f"Arquivo encontrado. Enviando {filename} para download.")
        return send_from_directory(DIRETORIO_ARQUIVOS, filename, as_attachment=True)
    except Exception as e:
        print(f"Ocorreu um erro: {e}")
        abort(500, f"Ocorreu um erro: {e}")

if __name__ == '__main__':
    app.run(port=5000)
