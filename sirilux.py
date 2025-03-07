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
import requests
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
historymongo = db["history"]
clientId = "1007059418552-8qgb0riokmg3t0t993ecjodnglvm0bj2.apps.googleusercontent.com"

#bidHistory
@app.route('/purchase_history', methods=['GET'])
def get_purchase_history():
    login_user = request.args.get('LoginUser')  # Get LoginUser from query parameter
    
    if not login_user:
        return jsonify({"message": "LoginUser parameter is required"}), 400

    try:
        # Query the historymongo collection to find the user's purchase history
        purchases = historymongo.find({"LoginUser": login_user})

        # Use count_documents() instead of count()
        if historymongo.count_documents({"LoginUser": login_user}) == 0:
            return jsonify({"message": "No purchase history found for this user."}), 404

        # Format the result
        purchase_list = []
        for purchase in purchases:
            purchase_details = {
                "img": purchase.get("img"),
                "name": purchase.get("name"),
                "price": purchase.get("price"),
                "amount": purchase.get("amount"),
                #"purchase_date": purchase.get("purchase_date")
            }
            purchase_list.append(purchase_details)

        return jsonify(purchase_list)
    
    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
