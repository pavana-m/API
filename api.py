from flask import Flask, request, jsonify, render_template
from flask_mysqldb import MySQL
import os
import datetime
import jwt
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
from werkzeug.utils import secure_filename
 
app = Flask(__name__)

#setting up connection to mysql database
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'Ganesha@9342'
app.config['MYSQL_HOST'] = '127.0.0.1'
app.config['MYSQL_DB'] = 'apple'
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024
types = ['jpg', 'png', 'gif']


mysql = MySQL(app)

def permitted_document(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in types
 
#home page for the app
@app.route('/')
def home():
    return render_template('home.html')

app.config['SECRET_KEY'] = '123456' 

# Simulated user database (for demonstration purposes)
users = {'pavithra': '123456'}

classes = {
    "software architecture" : "123",
    "machine learning" : "234"
}

folder = 'static/photos'

app.config['UPLOAD'] = os.path.join(app.root_path, folder)

# Error handling
@app.errorhandler(400)
def bad_request(e):
    return jsonify({'error': 'Bad request'}), 400

@app.errorhandler(401)
def unauthorized(e):
    return jsonify({'error': 'Unauthorized'}), 401

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not Found'}), 404

@app.errorhandler(500)
def internal_server_error(e):
    return jsonify({'error': 'Internal Server Error'}), 500

# Login endpoint
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']

    if username in users and users[username] == password:
        # Create a JWT token with a short expiration time (for demonstration purposes)
        expiration = datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
        # print("token is", expiration)
        token = jwt.encode({'username': username, 'exp': expiration}, app.config['SECRET_KEY'], algorithm='HS256')
        print("token is",token)
        return jsonify({'access_token': token}), 200
    else:
        return unauthorized('Invalid credentials')

# Protected endpoint (requires a valid JWT token)
@app.route('/protected', methods=['GET'])
def protected():
    token = request.headers.get('Authorization')
    if not token:
        return unauthorized('Token is missing')

    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        current_user = payload['username']
        return jsonify({'message': 'You have access to this protected resource, {}'.format(current_user)}), 200
    except ExpiredSignatureError:
        return unauthorized('Token has expired')
    except InvalidTokenError:
        return unauthorized('Invalid token')
    except Exception as e:
        return internal_server_error(str(e))
    
@app.route('/upload', methods=['POST'])
def upload_photo():
    
    file = request.files['file']
    filename = secure_filename(file.filename)
    print(permitted_document(file.filename))
    if file and permitted_document(file.filename):
        file.save(os.path.join(app.config['UPLOAD'], file.filename))
        return jsonify({"message": "Photo uploaded successfully"}), 200
    else:
        return jsonify({"message": "Photo could not be uploaded"}), 404 

@app.route('/public_route', methods=['GET'])
def public_route():
    return classes


@app.route('/add_user', methods=['POST'])
def index():
            username = request.args.get('username')
            password = request.args.get('password')

            # Check if the username is already in use
            cur = mysql.connection.cursor()
            cur.execute("SELECT * FROM users WHERE username= %s", [username])
            user = cur.fetchone()
            cur.close()
            if user:
                return jsonify({"message": "User already exists"}), 400 
            else:
                cur = mysql.connection.cursor()
                cur.execute("INSERT INTO users (username, password) VALUES (%s, %s)", [username, password])
                mysql.connection.commit()
                cur.close()
                return jsonify("User created!"), 200 


@app.route('/update_user', methods=['PUT'])
def update_user():
            username = request.args.get('username')
            password = request.args.get('password')

            # Check if the username is already in use
            cur = mysql.connection.cursor()
            cur.execute("SELECT * FROM users WHERE username= %s", [username])
            user = cur.fetchone()
            cur.close()
            if user:
                cur = mysql.connection.cursor()
                cur.execute("INSERT INTO users (username, password) VALUES (%s, %s)", [username, password])
                mysql.connection.commit()
                cur.close()
                return jsonify("User password updated!"), 200 
            else:
                return jsonify("User does not exist!"), 404 
            
@app.route('/delete_user', methods=['DELETE'])
def delete_user():
            username = request.args.get('username')

            # Check if the username is already in use
            cur = mysql.connection.cursor()
            cur.execute("SELECT * FROM users WHERE username= %s", [username])
            user = cur.fetchone()
            cur.close()
            if user:
                cur = mysql.connection.cursor()
                cur.execute("DELETE FROM users WHERE username= %s", [username])
                mysql.connection.commit()
                cur.close()
                return jsonify("User deleted!"), 200 
            else:
                return jsonify("User does not exist to be deleted!"), 404 
            
@app.route('/all_user', methods=['GET'])
def alll_user():

            # Check if the username is already in use
            cur = mysql.connection.cursor()
            cur.execute("SELECT * FROM users")
            user = cur.fetchall()
            print(user)
            cur.close()
            return jsonify(user), 200 
            
# @app.route('/all_user', methods=['GET'])
# def all_user():
#     cur = mysql.connection.cursor()
#     cur.execute("SELECT username from users")
#     usernames = [row[0] for row in cur.fetchall()]
#     print(users)
#     cur.close()
#     return users, 200

if __name__ == '__main__':
    app.run(debug=True)
