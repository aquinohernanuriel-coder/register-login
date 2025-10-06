from flask import Flask, send_from_directory, request, jsonify
import os

app = Flask(__name__, static_folder='.', static_url_path='')

# Ruta principal: sirve tu index.html
@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')

# Ejemplo de endpoint para registro
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    # Aquí podrías guardar en base de datos o archivo
    print(f"Usuario registrado: {username}")
    return jsonify({"message": "Usuario registrado con éxito"}), 201

# Ejemplo de endpoint para login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    # Aquí validarías usuario/contraseña
    print(f"Intento de login: {username}")
    return jsonify({"message": "Login exitoso"}), 200

# Puerto dinámico para Render
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
