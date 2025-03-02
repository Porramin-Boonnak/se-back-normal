from flask import Flask, request, jsonify
from pymongo import MongoClient
uri = "mongodb+srv://se1212312121:se1212312121@cluster0.kjvosuu.mongodb.net/"

app = Flask(__name__)

client = MongoClient(uri)
db = client["your_database"]
collection = db["products"]

@app.route("/sell", methods=["POST"])
def sell_product():
    data = request.json
    product_id = data.get("id")
    loginuser = data.get("loginuser")  # รับค่าผู้ใช้งานที่ล็อกอินเข้ามา

    if not product_id or not loginuser:
        return jsonify({"error": "Product ID and login user are required"}), 400

    # ค้นหาสินค้าตาม id และ owner ต้องตรงกับ loginuser
    product = collection.find_one({"id": product_id, "owner": loginuser})

    if not product:
        return jsonify({"error": "Product not found or you don't have permission"}), 403

    # ตรวจสอบว่า type == "post" และต้องไม่ซ้ำ (unique)
    if collection.find_one({"type": "post", "id": product_id}):
        return jsonify({"error": "Product with this type 'post' already exists"}), 409

    # อัปเดตสถานะเป็น "sold"
    result = collection.update_one({"id": product_id}, {"$set": {"status": "sold"}})

    if result.modified_count:
        return jsonify({"message": "Product sold successfully"}), 200
    else:
        return jsonify({"error": "Failed to update product"}), 500

if __name__ == "__main__":
    app.run(debug=True)
