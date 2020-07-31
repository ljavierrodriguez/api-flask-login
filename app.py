import os, datetime 
from werkzeug.utils import secure_filename
from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_script import Manager
from flask_migrate import Migrate, MigrateCommand 
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required
from models import db, User, Certificatw
from libs.utils import allowed_file

UPLOAD_FOLDER = "static"
ALLOWED_EXTENSIONS_IMGS = {'png', 'jpg', 'jpeg', 'gif'}
ALLOWED_EXTENSIONS_FILES = {'pdf', 'png', 'jpg', 'jpeg'}

app = Flask(__name__)
app.url_map.strict_slashes = False
app.config['DEBUG'] = True
app.config['ENV'] = 'development'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['JWT_SECRET_KEY'] = 'secret-key'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


db.init_app(app)
Migrate(app, db)
CORS(app)
jwt = JWTManager(app)
bcrypt = Bcrypt(app)
manager = Manager(app)
manager.add_command("db", MigrateCommand) # init migrate and upgrade

@app.route("/")
def main():
    return render_template('index.html')

@app.route("/register", methods=['POST'])
def register():
    email = request.json.get("email", None)
    password = request.json.get("password", None)

    if not email:
        return jsonify({"msg": "Email is required"}), 400
    if not password:
        return jsonify({"msg": "Password is required"}), 400

    user = User.query.filter_by(email=email).first()
    
    if user:
         return jsonify({"msg": "Email already exists"}), 400

    
    user = User()
    user.name = request.json.get("name", "")
    user.email = email
    user.password = bcrypt.generate_password_hash(password)
    user.active = request.json.get("active", False)

    user.save()

    return jsonify({"success": "Register successfully!, please Log In"}), 200

@app.route("/login", methods=['POST'])
def login():
    email = request.json.get("email", None)
    password = request.json.get("password", None)

    if not email:
        return jsonify({"msg": "Email is required"}), 400
    if not password:
        return jsonify({"msg": "Password is required"}), 400

    user = User.query.filter_by(email=email, active=True).first()
    
    if not user:
         return jsonify({"msg": "email/password are incorrects"}), 400

    if not bcrypt.check_password_hash(user.password, password):
        return jsonify({"msg": "email/password are incorrects"}), 400

    expires = datetime.timedelta(days=3)

    data = {
        "access_token": create_access_token(identity=user.email, expires_delta=expires),
        "user": user.serialize()
    }

    return jsonify({"success": "Log In succesfully!", "data": data}), 200

@app.route("/update-profile", methods=['POST'])
@jwt_required
def update_profile():
    if 'avatar' not in request.files:
        return jsonify({"msg": "Avatar is required"}), 400
            
    file = request.files['avatar']
    # name = request.form.get("name")
    # if user does not select file, browser also
    # submit an empty part without filename
    if file.filename == '':
        return jsonify({"msg": "Not Selected File"}), 400

    if file and allowed_file(file.filename, ALLOWED_EXTENSIONS_IMGS):

        email = get_jwt_identity()
        user = User.query.filter_by(email=email).first()

        filename = secure_filename(file.filename)
        filename = "user_" + str(user.id) + "_" + filename
        file.save(os.path.join(app.config['UPLOAD_FOLDER']+"/images", filename))

        user.avatar = filename
        user.update()

        return jsonify({"success": "Profile updated successfully!", "user": user.serialize()}), 200
        #return redirect(url_for('uploaded_file', filename=filename))

    return jsonify({"msg": "Image not allowed!"}), 400


@app.route('/images-profile/<filename>')
def image_profile(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER']+"/images",
                               filename)

if __name__ == "__main__":
    manager.run()