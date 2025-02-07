
from flask import request, Flask,jsonify
from pymongo.mongo_client import MongoClient
from bson.objectid import ObjectId
from bson import json_util
from google.oauth2 import id_token
from google.auth.transport import requests
from flask_bcrypt import Bcrypt
from flask_cors import CORS
import jwt
import datetime
uri = "mongodb+srv://se1212312121:se1212312121@cluster0.kjvosuu.mongodb.net/"

# Create a new client and connect to the server
client = MongoClient(uri)

app = Flask(__name__)
CORS(app) 
keyforlogin = "1212312121"
bcrypt = Bcrypt(app)
db = client["vivart"]
customer = db["customer"]
post = db["post"]
cart = db["cart"]

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
    try:
        object_id = ObjectId(_id)  # แปลง _id เป็น ObjectId
    except:
        return jsonify({"error": "Invalid ID format"}), 400
    
    # อัปเดต visit +1
    result = post.find_one_and_update( 
        {"_id": object_id}, 
        {"$inc": {"visit": 1}}, 
        return_document=True  # ให้คืนค่าหลังอัปเดต
    ) 

    if result:
        result['_id'] = str(result['_id'])  # แปลง ObjectId เป็น string เพื่อ JSON ใช้งานได้
        return jsonify(result)
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
    

@app.route('/cart/<string:_id>', methods=['GET'])
def getcart(_id):
    object_id = ObjectId(_id)
    data = cart.find({"_id_customer": object_id})  # หาโดยใช้ _id_customer
    results = []
    for item in data:
        item['_id'] = str(item['_id'])  
        item['_id_customer'] = str(item['_id_customer'])  
        results.append(item)
    if results:
        return jsonify(results)
    else:
        return jsonify({"error": "Data not found"}), 404

@app.route("/cart", methods=["POST"])
def add_to_cart():
    data = request.get_json()
    cart.insert_one(data)
    return {"message": "upload successful"}, 200

@app.route("/cart/<string:_id>", methods=["DELETE"])
def delete_cart(_id):
    try:
        object_id = ObjectId(_id)  # แปลง _id ให้เป็น ObjectId
    except:
        return jsonify({"error": "Invalid ID format"}), 400

    result = cart.delete_one({"_id": object_id})  # ลบข้อมูลที่มี _id ตรงกัน
    if result.deleted_count > 0:
        return jsonify({"message": "Delete successful"}), 200
    else:
        return jsonify({"error": "Data not found"}), 404

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)