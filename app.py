
from flask import request, Flask,jsonify
from pymongo.mongo_client import MongoClient
from bson.objectid import ObjectId
from bson import json_util
from google.oauth2 import id_token
from google.auth.transport import requests
from flask_bcrypt import Bcrypt
import jwt
import datetime
uri = "mongodb+srv://se1212312121:se1212312121@cluster0.kjvosuu.mongodb.net/"

# Create a new client and connect to the server
client = MongoClient(uri)

app = Flask(__name__)
keyforlogin = "1212312121"
bcrypt = Bcrypt(app)
db = client["vivart"]
customer = db["customer"]
post = db["post"]

clientId = "1007059418552-8qgb0riokmg3t0t993ecjodnglvm0bj2.apps.googleusercontent.com"

@app.route("/", methods=["GET"])
def test():
    return("lfkpowkoefk")

@app.route("/signup/email/google", methods=["POST"])
def signup_google():
    data = request.get_json()
    token = data.get("credential")
    if token :
        decoded_data = id_token.verify_oauth2_token(token, requests.Request(), clientId)
        find = customer.find_one({"email": decoded_data["email"]})
        if not find :
            return jsonify(decoded_data), 200
    elif "email" in data:
        find = customer.find_one({"email": data["email"]})
        if not find :
            return jsonify({"email" : data["email"]}), 200
    return {"message" : "fail"}, 400

@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json()
    find = customer.find_one({"username": data["username"]})
    if not find :
        if "password" in data :
            data["password"]=bcrypt.generate_password_hash(data["password"]).decode('utf-8')
        customer.insert_one(data)
        payload = {
        "username": data['username'],
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=6)  
        }
        token = jwt.encode(payload, keyforlogin, algorithm="HS256")
        return jsonify(token), 200
    return {"message" : "fail"}, 400

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    token = data.get("credential")
    if token :
        decoded_data = id_token.verify_oauth2_token(token, requests.Request(), clientId)
        find = customer.find_one({"email": decoded_data["email"]})
        if find :
            payload = {
            "username": find['username'],
            "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=6)  
            }
            token = jwt.encode(payload, keyforlogin, algorithm="HS256")
            return jsonify(token), 201
    elif "username" in data:
        find = customer.find_one({"username": data["username"]})
        if find:
            if bcrypt.check_password_hash(find["password"], data["password"]):
                payload = {
                "username": find['username'],
                "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=6)  
                }
                token = jwt.encode(payload, keyforlogin, algorithm="HS256")
                return jsonify(token), 201
    return {"message": "login fail"}, 401

@app.route("/post", methods=["POST"])
def postdata():
    data = request.get_json()
    post.insert_one(data)
    return {"message": "upload successful"}, 200


@app.route('/post/<string:_id>', methods=['GET'])
def getpost(_id):
    object_id = ObjectId(_id)  # แปลง _id เป็น ObjectId
    data = post.find_one({"_id": object_id})  # ค้นหาจาก MongoDB
    if data:
        data['_id'] = str(data['_id'])  # แปลง ObjectId เป็น string เพื่อให้ JSON ใช้ได้
        return jsonify(data)
    else:
        return jsonify({"error": "Data not found"}), 404
    
@app.route('/post', methods=['GET'])
def getallpost():
    data = list(post.find())  # ดึงข้อมูลทั้งหมดจาก MongoDB
    if data:
        # แปลง ObjectId เป็น string ในทุก document
        for item in data:
            item['_id'] = str(item['_id'])  # แปลง ObjectId เป็น string
        return jsonify(data)
    else:
        return jsonify({"error": "Data not found"}), 404
    

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)