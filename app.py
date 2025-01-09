from flask import request, Flask
from pymongo.mongo_client import MongoClient
from flask_cors import CORS
uri = "mongodb+srv://se1212312121:se1212312121@cluster0.kjvosuu.mongodb.net/"

# Create a new client and connect to the server
client = MongoClient(uri)

app = Flask(__name__)
CORS(app)

db = client["vivart"]
customer = db["customer"]

@app.route("/", methods=["GET"])
def test():
    return("lfkpowkoefk")

@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json()
    find = customer.find_one({"username": data["username"]})
    if not find:
        customer.insert_one(data)
        return {"message": "Signup successful"}, 201
    return {"message": "Signup fail"}, 401

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    find = customer.find_one({"username": data["username"], "password": data["password"]})
    if find:
        return {"message": "login successful"}, 201
    return {"message": "login fail"}, 401

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)