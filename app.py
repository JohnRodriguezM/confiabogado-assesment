from flask import Flask, request, jsonify
import datetime
from functools import wraps
import jwt

app = Flask(__name__)
app.config['SECRET_KEY'] = 'mi_secreto'  # Clave secreta para firmar el token JWT

# Array de usuarios con sus contraseñas
USUARIOS = {
    'jairo': 'c12345',
    'usuario2': 'contraseña2'
}

# Función para verificar si un número es primo
def es_primo(numero):
    if numero < 2:
        return False
    for i in range(2, int(numero ** 0.5) + 1):
        if numero % i == 0:
            return False
    return True

# Función para convertir una fecha a texto en español
def fecha_a_texto(fecha):
    meses = {
        1: "enero", 2: "febrero", 3: "marzo", 4: "abril", 5: "mayo", 6: "junio",
        7: "julio", 8: "agosto", 9: "septiembre", 10: "octubre", 11: "noviembre", 12: "diciembre"
    }
    dia = fecha.day
    mes = meses[fecha.month]
    año = fecha.year
    return f"{dia} de {mes} del {año}"

# Función para generar un token JWT

def generar_token(usuario):
    expiracion = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    token = jwt.encode({'usuario': usuario, 'exp': expiracion}, app.config['SECRET_KEY'])
    return token

# Decorador para la autenticación con JWT
def autenticar(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')

        if not token or not token.startswith('Bearer '):
            return jsonify({"error": "Formato de token inválido"}), 401

        token = token.split(" ")[1]

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            usuario_actual = data['usuario']
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token JWT expirado"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Token JWT inválido"}), 401

        return f(usuario_actual, *args, **kwargs)

    return decorated_function

# Ruta para autenticar y generar un token JWT
@app.route('/login', methods=['POST'])
def login():
    
    usuario = request.json.get('usuario')
    contraseña = request.json.get('contraseña')

    if usuario not in USUARIOS or USUARIOS[usuario] != contraseña:
        return jsonify({"error": "Usuario o contraseña incorrectos"}), 401

    token = generar_token(usuario)
    return jsonify({"token": token})

# Ruta para verificar si un número es primo
@app.route('/es_primo', methods=['POST'])
@autenticar
def verificar_primo(usuario_actual):
    data = request.get_json()
    numero = data.get('numero')
    if numero is None or not isinstance(numero, int):
        return jsonify({"error": "Se requiere un parámetro 'numero' entero"}), 400
    
    primo = es_primo(numero)
    return jsonify({"es_primo": primo})

# Ruta para convertir una fecha a texto en español
@app.route('/fecha_a_texto', methods=['POST'])
@autenticar
def convertir_fecha(usuario_actual):
    data = request.get_json()
    fecha_str = data.get('fecha')
    if not fecha_str:
        return jsonify({"error": "Se requiere un parámetro 'fecha'"}), 400
    
    try:
        fecha = datetime.datetime.strptime(fecha_str, '%Y-%m-%d')
    except ValueError:
        return jsonify({"error": "Formato de fecha inválido. Debe ser 'yyyy-mm-dd'"}), 400
    
    fecha_texto = fecha_a_texto(fecha)
    return jsonify({"fecha_texto": fecha_texto})

if __name__ == '__main__':
    app.run(debug=True)
