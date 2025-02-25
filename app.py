from flask import request, Flask,jsonify
from pymongo import MongoClient, ReturnDocument
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
follow = db["follow"]

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
        follow.insert_one({
            "username":data["username"],
            "followers": [],
            "following": []
        })
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
    
@app.route('/status', methods=['POST'])
def getstatus():
    data = request.get_json()
    decoded = jwt.decode(data["token"], keyforlogin, algorithms=["HS256"])
    find = customer.find_one({"username": decoded["username"]})
    if find:
        find['_id'] = str(find['_id'])  
        return jsonify(find),200
    else:
        return jsonify({"error": "Data not found"}), 404
    
@app.route('/update/like/<string:_id>', methods=["PUT"])
def updatelike(_id):
    object_id = ObjectId(_id)  
    user = request.get_json()
    find = post.find_one({"_id": object_id}) 
    if find:
        post.update_one({"_id": object_id}, {"$addToSet": {"like": user}}, upsert=True)
        return jsonify({"message": "successful"}), 200
    return jsonify({"message": "fail"}), 400

@app.route('/cart/<string:_id_customer>', methods=['GET'])
def getcart(_id_customer):
    object_id = ObjectId(_id_customer)
    data = cart.find({"_id_customer": object_id})
    results = []
    for item in data:
        item['_id'] = str(item['_id'])
        item['_id_customer'] = str(item['_id_customer'])
        if '_id_post' in item:
            item['_id_post'] = str(item['_id_post'])
        results.append(item)
    if results:
        return jsonify(results)
    else:
        return jsonify({"error": "Data not found"}), 404

@app.route('/cart/<string:_id_customer>/<string:_id_post>', methods=['PUT'])
def update_cart(_id_customer, _id_post):
    object_id_customer = ObjectId(_id_customer)
    object_id = ObjectId(_id_post)
    data = request.get_json()
    new_quantity = data.get("quantity", 1)
    
    if new_quantity <= 0:
        cart.delete_one({"_id_post": object_id, "_id_customer": object_id_customer})
        return jsonify({"message": "item removed"}), 200

    updated_item = cart.find_one_and_update(
        {"_id_post": object_id, "_id_customer": object_id_customer},
        {"$set": {"quantity": new_quantity}},
        return_document=True
    )

    if updated_item:
        return jsonify({"message": "successful"}), 200
    else:
        return jsonify({"error": "Data not found"}), 404

@app.route('/cart/<string:_id_customer>/<string:_id_post>', methods=['DELETE'])
def delete_cart_item(_id_customer, _id_post):
    object_id_customer = ObjectId(_id_customer)
    object_id = ObjectId(_id_post)
    result = cart.delete_one({"_id_post": object_id, "_id_customer": object_id_customer})

    if result.deleted_count > 0:
        return jsonify({"message": "Delete successful"}), 200
    else:
        return jsonify({"error": "Data not found"}), 404

@app.route('/cart', methods=['POST'])
def add_to_cart():
    data = request.get_json()
    try:
        data['_id_post'] = ObjectId(data['_id_post'])
        data['_id_customer'] = ObjectId(data['_id_customer'])
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    existing_item = cart.find_one({"_id_post": data['_id_post'], "_id_customer": data['_id_customer']})
    if existing_item:
        new_quantity = existing_item['quantity'] + data['quantity']
        cart.update_one(
            {"_id_post": data['_id_post'], "_id_customer": data['_id_customer']},
            {"$set": {"quantity": new_quantity}}
        )
        return jsonify({"message": "Quantity updated"}), 200
    else:
        cart.insert_one(data)
        return jsonify({"message": "Item added to cart"}), 200


@app.route('/delete/like/<string:_id>', methods=['DELETE'])
def deletelike(_id):
    object_id = ObjectId(_id)  
    user = request.get_json()
    find = post.find_one({"_id": object_id})  
    if find:
        post.update_one({"_id": object_id}, {"$pull": {"like": user}}, upsert=True)
        return jsonify({"message": "successful"}), 200
    return jsonify({"message": "fail"}), 400

@app.route("/editprofile", methods=["PUT"])
def profile_update():
    data = request.json
    username = data.get("username")

    if not username:
        return jsonify({"error": "Username is required"}), 400

    update_fields = {}
    if "user_bio" in data:
        update_fields["user_bio"] = data["user_bio"]
    if "profile_pic" in data:
        update_fields["img"] = data["profile_pic"]  # Ensure profile_pic is valid

    if not update_fields:
        return jsonify({"error": "No fields to update"}), 400

    updated_user = customer.find_one_and_update(
        {"username": username},
        {"$set": update_fields},
        return_document=ReturnDocument.AFTER
    )

    if updated_user:
        # Convert ObjectId to string for JSON serialization
        updated_user["_id"] = str(updated_user["_id"])
        return jsonify(updated_user), 200
    else:
        return jsonify({"error": "User not found"}), 404


@app.route("/profile/info/<username>", methods=["GET"])
def get_profile_info(username):
    data = customer.find_one({"username": username})
    
    if data:
        data["_id"] = str(data["_id"])  # Convert ObjectId to string
        data.pop("password", None)  # Remove password if it exists
        data.pop("id_number",None)
        data.pop("contact",None)
        data.pop("email",None)
        return jsonify(data), 200
    else:
        return jsonify({"error": "Profile not found"}), 404


#GET POST BY username
@app.route("/profile/posts/<username>", methods=["GET"])
def get_profile_post(username):
    data = list(post.find({"$or": [{"username": username}, {"artist": username}]}))

    if data:
        for doc in data:
            doc["_id"] = str(doc["_id"])  # Convert ObjectId to string

    
    return jsonify(data), 200


@app.route("/profile/follow/<username>" , methods=["GET"])
def get_profile_follow(username):
    data = follow.find_one({"username": username})
    if data:
        data["_id"] = str(data["_id"])  # Convert ObjectId to string
        return jsonify(data), 200
    else:
        return jsonify({"error": "Profile not found"}), 404

@app.route("/follow", methods=["POST"])
def follow_user():
    follow_info = request.get_json()
    user_login = follow_info.get("user_login")  # The user who wants to follow
    this_user = follow_info.get("this_user")  # The user being followed
    img = follow_info.get("img")  # Optional: image URL

    if not user_login or not this_user:
        return jsonify({"message": "Invalid input"}), 400

    # Check if both users exist in the 'follow' collection
    follower = follow.find_one({"username": user_login})
    following = follow.find_one({"username": this_user})

    if not (follower and following):
        return jsonify({"message": "User not found"}), 404

    # Add 'this_user' to 'user_login's following list
    follow.update_one(
        {"username": user_login},
        {"$addToSet": {"followings": {"username": this_user, "img": img}}}
    )

    # Add 'user_login' to 'this_user's followers list
    follow.update_one(
        {"username": this_user},
        {"$addToSet": {"followers": {"username": user_login, "img": img}}}
    )

    return jsonify({"message": f"{user_login} is now following {this_user}"}), 200


@app.route("/unfollow", methods=["PUT"])
def unfollow_user():
    follow_info = request.get_json()
    user_login = follow_info.get("user_login")  # The user who wants to unfollow
    this_user = follow_info.get("this_user")  # The user being unfollowed

    if not user_login or not this_user:
        return jsonify({"message": "Invalid input"}), 400

    # Check if both users exist in the 'follow' collection
    follower = follow.find_one({"username": user_login})
    following = follow.find_one({"username": this_user})

    if not (follower and following):
        return jsonify({"message": "User not found"}), 404

    # Remove 'this_user' from 'user_login's following list
    follow.update_one(
        {"username": user_login},
        {"$pull": {"followings": {"username": this_user}}}
    )

    # Remove 'user_login' from 'this_user's followers list
    follow.update_one(
        {"username": this_user},
        {"$pull": {"followers": {"username": user_login}}}
    )

    return jsonify({"message": f"{user_login} has unfollowed {this_user}"}), 200

# Fill tracking number   
@app.route("/edit/<id>", methods=["PUT"])
def edit_tracking(id):
    data = request.json
    if "tracking_number" not in data:
        return jsonify({"error": "Missing tracking number"}), 400
    
    filltracking.update_one({"_id": ObjectId(id)}, {"$set": {"tracking_number": data["tracking_number"]}})
    return jsonify({"message": "Tracking number updated"})

@app.route("/get_tracking", methods=["POST"])
def get_tracking():
    data = request.json
    if "username" not in data:
        return jsonify({"error": "Missing username"}), 400
    
    tracking_data = list(filltracking.find({"username": data["username"]}, {"_id": 1, "tracking_number": 1}))
    for item in tracking_data:
        item["id"] = str(item.pop("_id"))
    
    return jsonify(tracking_data)

@app.route("/submit", methods=["POST"])
def submit_tracking():
    data = request.json
    print("🔍 Received Data:", data)  # ตรวจสอบค่าที่รับมา

    if "username" not in data or "tracking_number" not in data:
        print("🚨 Missing required fields:", data)
        return jsonify({"error": "Missing required fields"}), 400

    tracking_entry = {
        "username": data["username"],
        "tracking_number": data["tracking_number"]
    }
    
    try:
        inserted_id = filltracking.insert_one(tracking_entry).inserted_id
        print("✅ Inserted ID:", inserted_id)
        return jsonify({"message": "Tracking number submitted", "id": str(inserted_id)})
    except Exception as e:
        print("🚨 Database Error:", str(e))
        return jsonify({"error": "Database error"}), 500

    
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)