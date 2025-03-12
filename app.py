from flask import request, Flask,jsonify
from pymongo import MongoClient, ReturnDocument
from bson.objectid import ObjectId
from bson import json_util
from google.oauth2 import id_token
from google.auth.transport import requests
from flask_bcrypt import Bcrypt
from flask_cors import CORS
import jwt
from datetime import datetime, timedelta, timezone
import requests as req
import base64
import io
from azure.storage.blob import BlobServiceClient
from email.message import EmailMessage
import random
import smtplib
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
report = db["report"]
filltracking = db["filltracking"]
address = db["address"]
historysellbuy = db["history"]
comment = db["comment"]
notificate = db["notificate"]
bank = db["bank"]
payout = db["payout"]
bid = db["bid"]
otppassword = db["otp"]

clientId = "1007059418552-8qgb0riokmg3t0t993ecjodnglvm0bj2.apps.googleusercontent.com"
AZURE_STORAGE_CONNECTION_STRING = ""
CONTAINER_NAME = "images"
blob_service_client = BlobServiceClient.from_connection_string(AZURE_STORAGE_CONNECTION_STRING)


#Function อัพรูปลง Azure แล้ว return ค่าเป็น link ของรูปนั้น
def upload_images_to_azure(base64_strings, name):
    if not base64_strings:
        return None, "No image data provided"

    blob_urls = []
    for i, base64_string in enumerate(base64_strings):
        try:
            if "," in base64_string:
                base64_string = base64_string.split(",")[1]  # ลบ prefix "data:image/png;base64,"
            
            image_data = base64.b64decode(base64_string)  # แปลง Base64 เป็นไบนารี
            blob_name = f"{name}_{i}.png"  # ตั้งชื่อไฟล์ให้แต่ละรูป

            blob_client = blob_service_client.get_blob_client(container=CONTAINER_NAME, blob=blob_name)
            blob_client.upload_blob(io.BytesIO(image_data), overwrite=True)
            
            blob_urls.append(blob_client.url)  # เก็บ URL ของไฟล์ที่อัปโหลด
        except Exception as e:
            return None, f"Failed to upload image {i}: {str(e)}"
    
    return blob_urls, None

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
    if not find:
        if "password" in data:
            data["password"] = bcrypt.generate_password_hash(data["password"]).decode('utf-8')
        
        base64_strings = data.get("img", [])
        blob_urls, error = upload_images_to_azure(base64_strings, data.get('username'))
        if error:
            return jsonify({"error": error}), 400
        
        data["img"] = blob_urls  # แทนที่ Base64 ด้วย URL
        customer.insert_one(data)
        
        payload = {
            "username": data['username'],
            "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=6)  
        }
        token = jwt.encode(payload, keyforlogin, algorithm="HS256")
        return jsonify(token), 200

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    token = data.get("credential")
    if token:
        decoded_data = id_token.verify_oauth2_token(token, requests.Request(), clientId)
        find = customer.find_one({"email": decoded_data["email"]})
        if find:
            payload = {
                "username": find['username'],
                "exp": datetime.now(timezone.utc) + timedelta(hours=6)  
            }
            token = jwt.encode(payload, keyforlogin, algorithm="HS256")
            return jsonify(token), 201
    elif "username" in data:
        find = customer.find_one({"username": data["username"]})
        if find:
            if bcrypt.check_password_hash(find["password"], data["password"]):
                payload = {
                    "username": find['username'],
                    "exp": datetime.now(timezone.utc) + timedelta(hours=6)  
                }
                token = jwt.encode(payload, keyforlogin, algorithm="HS256")
                return jsonify(token), 201
    return {"message": "login fail"}, 401

@app.route("/post", methods=["POST"])
def postdata():
    data = request.get_json()
    base64_strings = data.get("img", [])
    if isinstance(data.get("originalimg"), list) and data["originalimg"]:
        base64_strings_originalimg = data["originalimg"]
        blob_urls, error = upload_images_to_azure(base64_strings_originalimg, f"{data.get('name', 'unknown')}_originalimg")

        if error:
            print(f"Error uploading images: {error}")  # หรือใช้ logging
            data["originalimg"] = []
        else:
            data["originalimg"] = blob_urls
    blob_urls, error = upload_images_to_azure(base64_strings, data.get('name'))
    
    if error:
        return jsonify({"error": error}), 400
    
    data["img"] = blob_urls  # แทนที่ Base64 ด้วย URL
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

@app.route('/post/<string:_id>', methods=['DELETE'])
def delete_post(_id):
    try:
        object_id = ObjectId(_id)  # แปลง _id เป็น ObjectId
    except:
        return jsonify({"error": "Invalid ID format"}), 400
    
    # ลบโพสต์จาก MongoDB
    result = post.delete_one({"_id": object_id})
    
    if result.deleted_count == 1:
        return jsonify({"message": "Post deleted successfully"}), 200
    else:
        return jsonify({"error": "Post not found"}), 404
    
@app.route('/product', methods=['POST'])
def getallproduct():
    data = request.get_json()
    find = list(post.find({"artist": data["artist"],"typepost": "ordinary"}))  
    if find:
        for item in find:
            item['_id'] = str(item['_id'])  
        return jsonify(find)
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
    object_id = _id_customer
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
    object_id_customer = _id_customer
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
    object_id_customer = _id_customer
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
        data['_id_customer'] = data['_id_customer']
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
    
    if "profile_pic" in data and data["profile_pic"]:
        blob_urls, error = upload_images_to_azure(data["profile_pic"], username)
        if error:
            return jsonify({"error": error}), 400
        update_fields["img"] = blob_urls  # Store uploaded image URLs
    
    if not update_fields:
        return jsonify({"error": "No fields to update"}), 400
    
    updated_user = customer.find_one_and_update(
        {"username": username},
        {"$set": update_fields},
        return_document=ReturnDocument.AFTER
    )
    
    if updated_user:
        updated_user["_id"] = str(updated_user["_id"])  # Convert ObjectId to string
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
    data = list(post.find({"$or": [{"own": username}, {"artist": username}]}))

    for doc in data:
        doc["_id"] = str(doc["_id"])  # Convert ObjectId to string

    return jsonify(data), 200  # Will return [] if no data exists


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
    img = follow_info.get("img")  # Optional image URL

    if not user_login or not this_user:
        return jsonify({"message": "Invalid input"}), 400

    # Ensure both users exist in the 'follow' collection
    for user in [user_login, this_user]:
        if not follow.find_one({"username": user}):
            follow.insert_one({
                "username": user,
                "followers": [],
                "following": []
            })

    # Add 'this_user' to 'user_login's following list
    follow.update_one(
        {"username": user_login},
        {"$addToSet": {"following": {"username": this_user, "img": img}}}
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
#report management
# Helper to convert ObjectId to string
def serialize_report(report):
    return {
        '_id': str(report['_id']),
        'postid' : report.get('postid'),
        'name': report.get('name', 'Unnamed Report'),
        'description': report.get('description', ''),
        'date': report.get('date', ''),
        'artist' : report.get('artist')
    }

# 📥 GET all reports
@app.route('/api/reports', methods=['GET'])
def get_reports():
    reports = list(report.find()) 
    if reports:
        for doc in reports:
            doc["_id"] = str(doc["_id"])  # Convert ObjectId to string
    return jsonify([serialize_report(report) for report in reports]), 200

# 📥 GET a single report by ID
@app.route('/api/reports/<report_id>', methods=['GET'])
def get_report(report_id):
    report = report.find_one({'_id': ObjectId(report_id)}) 
    if report:
        return jsonify(serialize_report(report)), 200
    return jsonify({'message': 'Report not found'}), 404

# 📤 POST a new report (for testing purposes)
@app.route('/api/reports', methods=['POST'])
def create_report():
    data = request.json

    result = report.insert_one(data) 
    return jsonify({'message': 'Report created', 'id': str(result.inserted_id)}), 201

@app.route('/post/<string:_id>', methods=['PUT'])
def update_post(_id):
    try:
        object_id = ObjectId(_id)  # Convert the _id to ObjectId
    except:
        return jsonify({"error": "Invalid ID format"}), 400
    
    data = request.get_json()

    # Optional: Add validation for required fields
    if not data.get('name') or not data.get('description'):
        return jsonify({"error": "Missing required fields (name, description)"}), 400

    # Update the post
    result = post.find_one_and_update(
        {"_id": object_id},
        {"$set": data},
        return_document=True  # Return the document after the update
    )

    if result:
        result['_id'] = str(result['_id'])  # Convert ObjectId to string for JSON response
        return jsonify(result)
    else:
        return jsonify({"error": "Data not found"}), 404
    
@app.route('/address', methods=['POST'])
def add_address():
    data = request.get_json()
    address.insert_one(data)
    return {"message": "upload successful"}, 200

@app.route('/get_address', methods=['POST'])
def get_address():
    data = request.get_json()
    token = jwt.decode(data["token"], keyforlogin, algorithms="HS256")
    find = list(address.find({"username": token["username"]}))
    for item in find:
        item['_id'] = str(item['_id']) 
    return jsonify(find), 200


@app.route('/delete_address', methods=['DELETE'])
def delete_address():
    data = request.get_json()
    token = jwt.decode(data["token"], keyforlogin, algorithms="HS256")
    object_id = ObjectId(data["_id"])   
    address.delete_one({"username": token["username"], "_id": object_id})

    return {"message": "delete successful"}, 200

@app.route('/edit_address', methods=['PUT'])
def edit_address():
    data = request.get_json()
    token = jwt.decode(data["token"], keyforlogin, algorithms="HS256")
    object_id = ObjectId(data["_id"])   
    address.update_one({"username": token["username"], "_id": object_id},{"$set" : data["data"]})

    return {"message": "update successful"}, 200

@app.route('/amount', methods=['POST'])
def amount():
    data = request.get_json()
    
    if data["typepost"] == "uniq" :
        object_id = ObjectId(data["_id"])   
        find = post.find_one({"_id": object_id})
        if find["status"] == "open" :
            post.update_one({"_id": object_id},{"$set":{"status": "close","payment":data["payment"]}})
            return {"message": "successful"}, 200
    elif data["typepost"] == "ordinary" :
        object_id = ObjectId(data["_id"])   
        find = post.find_one({"_id": object_id})
        if int(find["amount"]) >= data["quantity"] :
            post.update_one({"_id": object_id},{"$set":{"amount": int(find["amount"])-int(data["quantity"]),"payment":data["payment"]}})
            return {"message": "successful"}, 200
    return {"message": "fail successful"}, 400

@app.route('/amount', methods=['PUT'])
def put_amount():
    data = request.get_json()
    
    if data["typepost"] == "uniq" :
        object_id = ObjectId(data["_id"])   
        find = post.find_one({"_id": object_id})
        if find["status"] == "close" and find["payment"] == "waiting" :
            post.update_one({"_id": object_id},{ "$set": {"status": "open"},"$unset": {"payment": ""}})
            return {"message": "successful"}, 200
    elif data["typepost"] == "ordinary" :
        object_id = ObjectId(data["_id"])   
        find = post.find_one({"_id": object_id})
        if int(find["amount"]) >= data["quantity"] and find["payment"]:
            post.update_one({"_id": object_id},{"$set":{"amount": int(find["amount"])+int(data["quantity"])},"$unset": {"payment": ""}})
            return {"message": "successful"}, 200
    return {"message": "fail"}, 400



@app.route('/proxy', methods=['POST'])
def proxy():
    # รับ URL ที่ส่งมาจาก frontend
    data = request.get_json()
    url = data["url"]
    
    try:
        # ส่งคำขอไปยัง URL ที่ได้รับจาก frontend
        response = req.get(url)
        
        # ส่งผลลัพธ์จาก API ภายนอกกลับไปยัง frontend
        return jsonify(response.json()), response.status_code
    except req.exceptions.RequestException as e:
        return jsonify({"error": str(e)}), 500
    
@app.route('/success', methods=['POST'])
def success():
    data = request.get_json()
    
    if data["typepost"] == "uniq" :
        object_id = ObjectId(data["_id"])   
        find = post.find_one({"_id": object_id})
        if find["status"] == "close" :
            post.update_one({"_id": object_id},{"$set":{"payment":data["payment"],"own":data["username"]}})
            return {"message": "successful"}, 200
    elif data["typepost"] == "ordinary" :
        object_id = ObjectId(data["_id"])   
        find = post.find_one({"_id": object_id})
        post.update_one({"_id": object_id},{"$unset":{"payment":data["payment"]}})
        return {"message": "successful"}, 200
    return {"message": "fail"}, 400

@app.route("/comment/<string:post_id>", methods=["POST"])
def post_comment(post_id):
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data received"})
        new_comment = {
            "post_id": post_id,
            "name": data.get("name"),
            "comment": data.get("comment"),
            "img": data.get("img")
        }
        result = comment.insert_one(new_comment)
        return jsonify({"message": "Comment added", "comment_id": str(result.inserted_id)}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route("/comment/<string:post_id>", methods=["GET"])
def get_comment(post_id):
    try:
        
        find = list(comment.find({"post_id": post_id}))
        if find :
            for item in find:
                item['_id'] = str(item['_id'])

            return jsonify(find),200
        return jsonify({"message": "Comment fail"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/get_user_images", methods=["POST"])
def get_user_images():
    data = request.json  # Expecting a list of dictionaries
    usernames = [entry["username"] for entry in data]  # Extract usernames
    
    users = customer.find({"username": {"$in": usernames}}, {"username": 1, "img": 1, "_id": 0})
    
    user_images = {user["username"]: user.get("img", "default.png") for user in users}  # Default if no image found
    
    for entry in data:
        entry["img"] = user_images.get(entry["username"], "default.png")  # Attach image to each user
    
    return jsonify(data)

@app.route("/notificate", methods=["POST"])
def post_noti():
    data = request.get_json()
    notificate.insert_one(data)
    return {"message": "upload successful"}, 200

@app.route('/history', methods=['POST'])
def historysellandbuy():
    data = request.get_json()
    historysellbuy.insert_one(data)
    return {"message": "successful"}, 200

@app.route('/history/<string:username>', methods=['GET'])
def get_historysellandbuy(username):
    data = list(historysellbuy.find({"own":username}))
    for item in data :
        item["_id"] = str(item["_id"])
    return jsonify(data), 200

@app.route('/countlike/<string:username>', methods=['GET'])
def countlike(username):
    data = list(post.find({"artist": username}))
    total_likes = 0
    for item in data:
        item["_id"] = str(item["_id"])  
        total_likes += len(item.get("like", []))  
    
    return jsonify({"total_likes": total_likes}), 200

@app.route("/get_uniq_posts", methods=["POST"])
def get_uniq_posts():
    
    data = request.json
    login_user = data.get("loginUser")

    if not login_user:
        return jsonify({"error": "User not logged in"}), 400

        # ค้นหาโพสต์ที่มีเงื่อนไขตามที่กำหนด
    posts = list(post.find(
        {"own": login_user, "typepost": "uniq", "status": "open"}
    ))

        # แปลง _id ให้เป็น string ก่อนส่งกลับ
    for post_item in posts:
        post_item["_id"] = str(post_item["_id"])  # แปลง _id เป็น string

    return jsonify({"posts": posts}), 200


@app.route('/bank/<string:id_user>', methods=['GET'])
def get_bank(id_user):
    find = bank.find_one({"username": id_user})  # ซ่อน _id เพื่อไม่ให้ส่งไป
    if find:
        find["_id"] = str(find["_id"])
        return jsonify(find), 200
    return jsonify({"message": "fail"}), 400

@app.route('/bank', methods=['POST'])
def post_bank():
    data = request.get_json()
    bank.insert_one(data)
    return {"message":"successful"}, 200

@app.route('/payout', methods=['POST'])
def post_payout():
    data = request.get_json()
    payout.insert_one(data)
    return {"message":"successful"}, 200

@app.route('/bid_history/<string:login_user>', methods=['GET'])
def get_bid_history(login_user):
    
    if not login_user:
        return jsonify({"message": "LoginUser parameter is required"}), 400

    try:
        # Query the historymongo collection to find the user's purchase history
        purchases = bid.find({"user": login_user})

        # Use count_documents() instead of count()
        if bid.count_documents({"user": login_user}) == 0:
            return jsonify([]), 200

        # Format the result
        
        purchase_list = []
        for purchase in purchases:
            purchase_details = {
                **purchase,  # คัดลอกข้อมูลเดิมทั้งหมด
                "_id": str(ObjectId()),  # เปลี่ยน _id เป็นค่าใหม่
            }
            purchase_list.append(purchase_details)

        return jsonify(purchase_list)
    
    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500
    
@app.route('/delete_post/<string:post_id>', methods=['DELETE'])
def admin_delete_post(post_id):
    # Convert string post_id to ObjectId for MongoDB query
    try:
        result = post.delete_one({'_id': ObjectId(post_id)})
        if result.deleted_count == 1:
            return jsonify({"message": "Post deleted successfully"}), 200
        else:
            return jsonify({"message": "Post not found"}), 404
    except Exception as e:
        return jsonify({"message": str(e)}), 400
    
@app.route('/paidHistory/<string:id_user>', methods=['GET'])
def get_paid(id_user):
    find = list(historysellbuy.find({"customer": id_user}))
    if find:
        for item in find :
            item["_id"] = str(item["_id"])
        return jsonify(find), 200
    return jsonify({"message": "fail"}), 400


@app.route('/salehistory/<string:id_user>', methods=['GET'])
def get_salehistory(id_user):
    find = list(historysellbuy.find({"own": id_user}))
    if find:
        for item in find :
            item["_id"] = str(item["_id"])
        return jsonify(find), 200
    return jsonify({"message": "fail"}), 400

@app.route('/toshipping/<string:id_user>', methods=['GET'])
def get_ship(id_user):
    find = list(filltracking.find({"customer": id_user}))
    if find:
        for item in find :
            item["_id"] = str(item["_id"])
            item["tracking_number"] = str(item["tracking_number"])
        return jsonify(find), 200
    return jsonify({"message": "fail"}), 400
        
@app.route('/delete_report/<string:report_id>', methods=['DELETE'])
def admin_delete_report(report_id):
    try:
        # Convert string report_id to ObjectId for MongoDB query
        result = report.delete_one({'_id': ObjectId(report_id)})
        
        if result.deleted_count == 1:
            return jsonify({"message": "Report deleted successfully"}), 200
        else:
            return jsonify({"message": "Report not found"}), 404
    except Exception as e:
        return jsonify({"message": str(e)}), 400


@app.route("/bid", methods=["POST"])
def place_bid():
    data = request.json
    post_id = data["_id_post"]
    username = data["user"]
    new_price = int(data["price"])

    # ค้นหาบิดก่อนหน้า
    existing_bid = bid.find_one({"_id_post": post_id, "user": username})

    if existing_bid:
        old_price = existing_bid["price"]
        if new_price > old_price:  # เช็กว่าราคาใหม่ต้องสูงกว่าเก่า
            bid.update_one(
                {"_id_post": post_id, "user": username},
                {"$set": {"price": new_price}}
            )
            return jsonify({"message": "Bid updated successfully!", "price": new_price}), 200
        else:
            return jsonify({"error": "New bid must be greater than your previous bid!"}), 400
    else:
        # เพิ่มบิดใหม่ถ้ายังไม่เคยบิด
        bid_data = {
                    "_id_post": post_id,
                    "user": data["user"],  # ต้องใช้ค่าจาก front-end
                    "artist": data["artist"],
                    "price": new_price,
                    "img_user": data["img_user"],
                    "img_post": data["img_post"]
                }


        bid.insert_one(bid_data)
        return jsonify({"message": "Bid placed successfully!", "price": new_price}), 201
    
@app.route("/bid/<post_id>", methods=["GET"])
def get_bids(post_id):
    # ดึงรายการบิดทั้งหมดของโพสต์นี้
    all_bids = list(bid.find({"_id_post": post_id}, {"_id": 0}))
    return jsonify(all_bids), 200

@app.route("/notificate/<string:username>", methods=["GET"])
def get_notifications(username):
    if not username:
        return jsonify({"error": "Username is required"}), 400
    
    notifications = list(notificate.find({"receiver": username}, {"_id": 0}))  # Exclude _id field
    return jsonify(notifications)

@app.route("/check_bid_end/<string:login_user>", methods=["GET"])
def check_bid_end(login_user):
    purchases = bid.find({"user": login_user})
    bid_list = []
    
    for purchase in purchases:
        # Initialize bid_data
        bid_data = {
            "_id": str(purchase["_id"]),
            "_id_post": purchase["_id_post"],
            "user": purchase["user"],
            "artist": purchase["artist"],
            "price": purchase["price"]
        }
        
        # Find the corresponding post data for the given _id_post
        post_data = post.find_one({"_id": ObjectId(purchase["_id_post"])})
        
        # Check if post_data exists and contains the 'typepost' field
        if post_data and "endbid" in post_data:
            bid_data["endbid"] = post_data["endbid"]
        else:
            bid_data["endbid"] = None
        
        # Append the bid data to the list
        bid_list.append(bid_data)
    
    # Return the list as a JSON response
    return jsonify(bid_list)

def send_otp(email, otp):
    msg = EmailMessage()
    msg.set_content(f"Your OTP is: {otp}")
    msg["Subject"] = "Your OTP Code"
    msg["From"] = "mosphonz3@gmail.com"
    msg["To"] = email
    otppassword.update_one(
        {"email": email},  
        {"$set": {"otp": otp}},  
        upsert=True  
    )
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login("mosphonez3@gmail.com", "lmwjmtqijtpunema")
            server.send_message(msg)
        return True
    except Exception as e:
        print("Error:", e)
        return False

# Route API สำหรับส่ง OTP
@app.route("/send-otp", methods=["POST"])
def send_otp_route():
    data = request.get_json()
    email = data.get("email")
    
    if not email:
        return jsonify({"error": "Email is required"}), 400

    otp = random.randint(100000, 999999)  # สุ่ม OTP 6 หลัก

    if send_otp(email, otp):
        return jsonify({"message": "OTP sent successfully", "otp": otp}), 200
    else:
        return jsonify({"error": "Failed to send OTP"}), 500

@app.route("/get_email/<string:email>", methods=["GET"])
def get_otp(email):
    email = otppassword.find_one({"email": email})
    email["_id"] = str(email["_id"])
    return jsonify(email), 200

@app.route("/change_password/<string:email>", methods=["PUT"])
def change_password(email):
    data = request.get_json()
    password = bcrypt.generate_password_hash(data["password"]).decode('utf-8')
    customer.update_one(
        {"email": email}, 
        {"$set": {"password": password}}  
    )
    otppassword.delete_one({"email": email})
    return jsonify({"message" :"sugsess"}), 200

#Signin admin
VALID_USERNAME = "admin"
VALID_PASSWORD = "password"

@app.route("/signinadmin", methods=["POST"])
def signin():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    
    if username == VALID_USERNAME and password == VALID_PASSWORD:
        return jsonify({"message": "Signin successful", "status": "success"}), 200
    else:
        return jsonify({"message": "Invalid credentials", "status": "error"}), 401


@app.route("/check_bid_end/<string:login_user>", methods=["GET"])
def check_bid_end(login_user):
    purchases = bid.find({"user": login_user})
    bid_list = []
    
    for purchase in purchases:
        # Check if this bid exists in the candidate collection
        candidate_data = candidate.find_one({
            "post_id": purchase["_id_post"],  # Assuming `post_id` exists in the candidate collection
            "user": login_user
        })
        
        if not candidate_data:
            continue  # Skip this bid if not found in the candidate collection

        # Initialize bid_data
        bid_data = {
            "_id": str(purchase["_id"]),
            "_id_post": purchase["_id_post"],
            # "name":purchase["name"],
            "user": purchase["user"],
            "artist": purchase["artist"],
            "price": purchase["price"]
        }
        
        # Find the corresponding post data for the given _id_post
        post_data = post.find_one({"_id": ObjectId(purchase["_id_post"])})
        
        if post_data and "endbid" in post_data:
            bid_data["endbid"] = post_data["endbid"]
        else:
            bid_data["endbid"] = None
        
        # Append only if candidate_data exists
        bid_list.append(bid_data)
    
    # Return the filtered list as a JSON response
    return jsonify(bid_list)

@app.route("/wonbid/adtocart", methods=["POST"])
def WonBID_add_to_cart():
    data = request.json
    post_id = data.get("_id_post")
    loginuser = data.get("_id_customer")
    price = data.get("price")
    if not post_id:
        return jsonify({"error": "post_id is required"}), 400
    
    # Check if post_id exists in the cart
    existing_item = cart.find_one({"_id_post": ObjectId(post_id) , "_id_customer":loginuser})
    post_info = post.find_one({"_id":ObjectId(post_id)})
    if existing_item:
        return jsonify({"message": "post_id already in cart"}), 200
    
    return_data = {
        "_id_post": ObjectId(post_id),
        "_id_customer":loginuser,
        "price":price,
        "img":post_info.get("img"),
        # "name":post_info.get("name"),
        "quantity":1,
        "typepost":post_info.get("typepost"),
        "type":post_info.get("type"),
        "own":post_info.get("own")
    }   
    
    # Insert new post_id if not found
    cart.insert_one(return_data)
    return jsonify({"message": "post_id added to cart"}), 201

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)