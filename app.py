from flask import Flask, request, jsonify, session, render_template, send_from_directory
from sqlalchemy import create_engine, text
import redis
import json
from flask_cors import CORS
from flask_socketio import SocketIO
import bcrypt
import uuid
import time
import requests
import threading

# Khởi tạo Flask
app = Flask(__name__, template_folder="Templates")
app.secret_key = "supersecretkey"

# Cho phép CORS để gọi API từ frontend
CORS(app, supports_credentials=True)

# Dùng Windows Authentication (nếu không có username/password)
DB_URI = "mssql+pyodbc://@localhost:1433/Products?driver=ODBC+Driver+18+for+SQL+Server&TrustServerCertificate=yes"

# Tạo engine kết nối
engine = create_engine(DB_URI)

# Kết nối Redis
r = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)

# Kết nối Rasa
RASA_URL = "http://localhost:5005/webhooks/rest/webhook"

# Websocket
socketio = SocketIO(app, async_mode="threading", cors_allowed_origins="*")

# Đăng ký user
@app.route('/user/signup', methods=['POST'])
def register():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    email = data.get("email")
    phone = data.get("phone")

    if not username or not password or not email:
        return jsonify({"error": "Missing required fields"}), 400

    if r.exists(f"user:{username}"):
        return jsonify({"error": "Username already exists"}), 400
    
    user_id = r.incr("user_id_counter")

    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    r.hset(f"user:{username}", mapping={
        "user_id": user_id,
        "password": hashed_pw,
        "email": email,
        "phone": phone,
        "role": "user"
    })
    
    # Lưu vào SQL Server
    try:
        with engine.begin() as conn:
            conn.execute(text("""
                INSERT INTO Users (username, password, email, phone)
                VALUES (:username, :password, :email, :phone)
                """), {
                "username": username,
                "password": hashed_pw,
                "email": email,
                "phone": phone
                })
    except Exception as e:
        r.delete(f"user:{username}")
        print("Database error:", str(e))

    return jsonify({"message": "User registered successfully"}), 201

# Đăng nhập user
@app.route('/user/login', methods=['POST'])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    user = r.hgetall(f"user:{username}")
    if not user:
        return jsonify({"error": "User not found"}), 404

    stored_password = user["password"].encode('utf-8')
    if not bcrypt.checkpw(password.encode('utf-8'), stored_password):
        return jsonify({"error": "Invalid password"}), 401
    
    user_id = user["user_id"]

    # Tạo session
    session_id = str(uuid.uuid4())
    r.setex(f"session:{session_id}", 3600, user_id)  # Lưu session trong 1 giờ

    return jsonify({"message": "Login successful", "session_id": session_id, "user_id": user_id}), 200

# Đăng xuất user
@app.route('/user/logout', methods=['POST'])
def logout():
    session_id = request.headers.get("Authorization")
    r.delete(f"session:{session_id}")
    return jsonify({"message": "Logged out successfully"}), 200

# Gửi OTP code
@app.route('/user/send_code', methods=['POST'])
def send_code():
    data = request.json
    method = data.get("method")  # "email" hoặc "phone"
    value = data.get("value")    # Email hoặc số điện thoại

    if not value:
        return jsonify({"error": "Missing value"}), 400

    # Duyệt tất cả users để kiểm tra email hoặc phone có tồn tại không
    user_keys = r.keys("user:*")  # Lấy danh sách tất cả user trong Redis
    user_found = False

    for user_key in user_keys:
        user_data = r.hgetall(user_key)
        if method == "email" and user_data.get("email") == value:
            user_found = True
            break
        elif method == "phone" and user_data.get("phone") == value:
            user_found = True
            break

    if user_found:
        # Gửi mã (Giả lập, thực tế bạn có thể tích hợp email/SMS API)
        reset_code = "4181"  # Thay bằng mã random trong thực tế
        r.setex(f"otp:{value}", 300, reset_code)  # Lưu OTP trong 5 phút

        return jsonify({"message": "A reset code has been sent"}), 200
    else:
        return jsonify({"error": "Invalid email/phone"}), 400

# Đăng nhập admin
@app.route('/admin')
def admin_login():
    return render_template("Admin.html")

# Lấy danh sách tất cả users   
@app.route('/users', methods=['GET'])
def get_all_users():
    user_keys = r.keys("user:*")  # Lấy tất cả key user
    users = []

    for user_key in user_keys:
        user_data = r.hgetall(user_key)
        users.append({
            "role": user_data.get("role", "user"),  
            "username": user_key.split(":")[1],  # Lấy username từ key
            "email": user_data.get("email", ""),
            "phone": user_data.get("phone", "")
        })

    # Sắp xếp theo role trước, sau đó username theo alphabet
    users_sorted = sorted(users, key=lambda x: (x["role"] != "admin", x["username"]))

    return jsonify(users_sorted), 200

# Lấy danh sách tất cả admins
@app.route('/admins', methods=['GET'])
def get_all_admins():
    admin_keys = r.keys("admin:*")  # Lấy tất cả key admin
    admins = []

    for admin_key in admin_keys:
        admin_data = r.hgetall(admin_key)
        admins.append({
            "role": "admin",
            "adminname": admin_key.split(":")[1],
            "email": admin_data.get("email", ""),
            "phone": admin_data.get("phone", ""),
            "password": admin_data.get("password", "")  # Trả về để kiểm tra
        })

    return jsonify(admins), 200

@app.route('/admin/login', methods=['POST'])
def admin_login_post():
    data = request.json
    adminname = data.get("adminname")
    password = data.get("password")

    admin_data = r.hgetall(f"admin:{adminname}")
    if not admin_data:
        return jsonify({"error": "Admin not found"}), 404

    stored_password = admin_data["password"].encode('utf-8')
    if not bcrypt.checkpw(password.encode('utf-8'), stored_password):
        return jsonify({"error": "Invalid password"}), 401

    session_id = str(uuid.uuid4())
    r.setex(f"session:{session_id}", 3600, adminname)

    return jsonify({"message": "Admin login successful", "session_id": session_id}), 200

# Xóa người dùng
@app.route('/admin/delete_user', methods=['DELETE'])
def delete_user():
    session_id = request.headers.get("Authorization")  
    if not session_id or not r.exists(f"session:{session_id}"):
        return jsonify({"error": "Unauthorized"}), 401
    r.expire(f"session:{session_id}", 3600)

    try:
        data = request.get_json()  # Lấy JSON đúng cách
    except Exception as e:
        return jsonify({"error": "Invalid JSON format"}), 400

    username = data.get("username")
    if not username:
        return jsonify({"error": "Missing username"}), 400

    if r.exists(f"user:{username}"):
        r.delete(f"user:{username}")
        r.delete("cached_users")
        return jsonify({"message": "User deleted successfully"}), 200
    else:
        return jsonify({"error": "User not found"}), 404
    
@app.route('/products')
def show_products():
    products = []

    # 1) Lấy ID từ SQL & Redis
    with engine.connect() as conn:
        sql_ids = {row[0] for row in conn.execute(text("SELECT product_id FROM Products"))}
    redis_ids = set(map(int, r.zrange("products:zset", 0, -1, withscores=False)))

    # 2) Tính các ID mới phải load SQL
    new_ids = sql_ids - redis_ids

    # 3) Sync: cache những new_ids
    if new_ids:
        app.logger.info(f"[SYNC] Thêm mới vào cache: {new_ids}")
        with engine.connect() as conn:
            for pid in new_ids:
                row = conn.execute(text(
                    "SELECT name, price, image_path, stock FROM Products WHERE product_id=:pid"
                ), {"pid": pid}).fetchone()
                if not row:
                    continue
                key = f"product_id:{pid}"
                data = {
                    "name": row[0], "price": row[1],
                    "image_path": row[2], "stock": row[3]
                }
                r.hset(key, mapping=data)
                r.expire(key, 600)
                r.zadd("products:zset", {pid: pid})
                r.expire("products:zset", 600)

    # 4) Xóa cache cho ID không còn trong SQL
    remove_ids = redis_ids - sql_ids
    if remove_ids:
        app.logger.info(f"[SYNC] Xóa khỏi cache: {remove_ids}")
        for pid in remove_ids:
            r.delete(f"product_id:{pid}")
            r.zrem("products:zset", pid)

    # 5) Đọc theo thứ tự và log nguồn THẬT của mỗi product
    ordered_ids = r.zrange("products:zset", 0, -1, withscores=False)
    for pid_str in ordered_ids:
        pid = int(pid_str)
        key = f"product_id:{pid}"
        data = r.hgetall(key)

        if pid in new_ids:
            app.logger.info(f"[LOAD SQL ] product_id={pid}")
            source = "sql"
        else:
            app.logger.info(f"[CACHE HIT] product_id={pid}")
            source = "redis"

        products.append({
            "product_id": pid,
            "name":        data["name"],
            "price":       data["price"],
            "image_path":  data["image_path"],
            "stock":       data["stock"],
            "source":      source
        })

    return render_template('Products.html', products=products)

# Thêm sản phẩm vào giỏ hàng
@app.route("/cart/add", methods=["POST"])
def add_to_cart():
    session_id = request.headers.get("Authorization")  

    if not session_id or not r.exists(f"session:{session_id}"):
        return jsonify({"error": "Unauthorized"}), 401

    user_id = r.get(f"session:{session_id}")

    data = request.json
    product_id = data.get("product_id")  
    quantity = int(data.get("quantity", 1))  

    if not user_id or not product_id:
        return jsonify({"error": "No login"}), 401

    cart_key = f"cart:{user_id}"
    current_quantity = r.hget(cart_key, product_id) or 0
    new_quantity = int(current_quantity) + quantity

    r.hset(cart_key, product_id, new_quantity)  # Cập nhật Redis
    r.expire(cart_key, 600)

    # Cập nhật giỏ hàng trong SQL Server
    with engine.connect() as conn:
        conn.execute(text("""
            MERGE INTO Cart AS target
            USING (SELECT :user_id AS user_id, :product_id AS product_id , :quantity AS quantity) AS source
            ON target.user_id = source.user_id AND target.product_id = source.product_id
            WHEN MATCHED THEN
                UPDATE SET target.quantity = source.quantity
            WHEN NOT MATCHED THEN
                INSERT (user_id, product_id, quantity) VALUES (source.user_id, source.product_id, source.quantity);
        """), {"user_id": user_id, "product_id": product_id, "quantity": new_quantity})
        conn.commit()

    return jsonify({"message": "Added to cart", "cart": r.hgetall(cart_key)})

@app.route('/cart/count', methods=['GET'])
def get_cart_count():
    session_id = request.headers.get("Authorization")  # Lấy session_id từ header

    if not session_id or not r.exists(f"session:{session_id}"):
        return jsonify({"error": "Unauthorized"}), 401  # Lỗi nếu không có session hợp lệ

    user_id = r.get(f"session:{session_id}")  # Lấy user_id từ session Redis
    
    # Kiểm tra Redis trước
    redis_key = f"cart:{user_id}"
    cart_data = r.hgetall(redis_key)

    if cart_data:
        total_quantity = sum(int(qty) for qty in cart_data.values())  # Cộng dồn số lượng
    else:
        # Nếu Redis không có, lấy từ SQL Server
        conn = engine.connect()
        result = conn.execute(text("SELECT SUM(Quantity) FROM Cart WHERE user_id = :user_id"), {"user_id": user_id})
        total_quantity = result.scalar() or 0  # Tránh giá trị None
        conn.close()

    return jsonify({"total_quantity": total_quantity})

# Xóa sản phẩm khỏi giỏ hàng
@app.route("/cart/remove", methods=["POST"])
def remove_from_cart():
    session_id = request.headers.get("Authorization")  

    if not session_id or not r.exists(f"session:{session_id}"):
        return jsonify({"error": "Unauthorized"}), 401

    user_id = r.get(f"session:{session_id}")

    data = request.json
    product_id = data.get("product_id")  
    quantity = int(data.get("quantity", 1))
    
    cart_key = f"cart:{user_id}"
    current_quantity = r.hget(cart_key, product_id)
    
    if not current_quantity:
        return jsonify({"error": "The product does not exist in cart"}), 400
    
    new_quantity = int(current_quantity) - quantity
    if new_quantity > 0:
        r.hset(cart_key, product_id, new_quantity)
    else:
        r.hdel(cart_key, product_id)
    
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM cart WHERE user_id = :user_id and product_id = :product_id"), {"user_id": user_id, "product_id": product_id})
    
    return jsonify({"message": "Updated", "cart": r.hgetall(cart_key)})

# Lấy danh sách giỏ hàng
@app.route('/cart', methods=['GET'])
def get_cart():
    session_id = request.headers.get("Authorization")  # Lấy session_id từ header

    if not session_id or not r.exists(f"session:{session_id}"):
        return jsonify({"error": "Unauthorized"}), 401  # Lỗi nếu không có session hợp lệ

    user_id = r.get(f"session:{session_id}")  # Lấy user_id từ session Redis
    
    cart_key = f"cart:{user_id}"

    cart_items = r.hgetall(cart_key)
    items = []

    if cart_items:
        # Nếu Redis có dữ liệu, trả về ngay
        for product_id, quantity in cart_items.items():
            with engine.connect() as conn:
                product = conn.execute(
                    text("SELECT name FROM Products WHERE product_id = :product_id"), 
                    {"product_id": product_id}
                ).fetchone()

            if product:
                items.append({
                    "product_id": product_id,
                    "name": product[0],
                    "quantity": int(quantity)
                })
    else:
        # Nếu Redis không có, lấy toàn bộ giỏ hàng từ SQL Server
        with engine.connect() as conn:
            result = conn.execute(
                text("""
                    SELECT c.product_id, p.name, c.quantity 
                    FROM Cart c 
                    JOIN Products p ON c.product_id = p.product_id 
                    WHERE c.user_id = :user_id
                """), {"user_id": user_id}
            )
            cart_data = result.fetchall()

        if cart_data:
            # Dùng pipeline để cache tất cả sản phẩm vào Redis một lần
            with r.pipeline() as pipe:
                for row in cart_data:
                    items.append({
                        "product_id": row[0],
                        "name": row[1],
                        "quantity": row[2]
                    })
                    pipe.hset(cart_key, row[0], row[2])
                pipe.expire(cart_key, 600)  # Cache 10 phút
                pipe.execute()

    return jsonify({"items": items})

# Xóa toàn bộ giỏ hàng
@app.route("/cart/clear", methods=["POST"])
def clear_cart():
    session_id = request.headers.get("Authorization")  

    if not session_id or not r.exists(f"session:{session_id}"):
        return jsonify({"error": "Unauthorized"}), 401

    user_id = r.get(f"session:{session_id}")
    
    cart_key = f"cart:{user_id}"
    r.delete(cart_key)

    with engine.begin() as conn:
        conn.execute(text("DELETE FROM cart WHERE user_id = :user_id"), {"user_id": user_id})

    return jsonify({"message": "Deleted"})

connected_users = {}  # Lưu user_id -> session_id

@socketio.on("connect")
def handle_connect():
    session_id = request.args.get("session_id")
    if session_id and r.exists(f"session:{session_id}"):
        user_id = r.get(f"session:{session_id}")
        connected_users[user_id] = request.sid  # Lưu SID

@socketio.on("disconnect")
def handle_disconnect():
    # Xóa user khỏi danh sách khi họ thoát
    for user_id, sid in list(connected_users.items()):
        if sid == request.sid:
            del connected_users[user_id]
            break

# Tích hợp Chatbot
@socketio.on("user_message")
def handle_user_message(data):
    session_id = data.get("session_id")
    message = data.get("message", "")

    if not session_id or not r.exists(f"session:{session_id}"):
        return jsonify({"error": "Unauthorized"}), 401

    user_id = r.get(f"session:{session_id}")

    if message:
        redis_data = json.dumps({"user_id": user_id, "message": message}, ensure_ascii=False)
        r.publish("user_message", redis_data)

# Lắng nghe chatbot & tư vấn viên từ Redis
def listen_redis():
    pubsub = r.pubsub()
    pubsub.subscribe(["chatbot_response", "agent_response"])

    for message in pubsub.listen():
        if message["type"] == "message":
            data = json.loads(message["data"])
            user_id = str(data["user_id"])  
            channel = message["channel"]
            response = data["response"]

            if channel == "agent_response":
                # Gửi đến tất cả nếu user_id = "all"
                if user_id == "all":
                    socketio.emit(channel, {"message": response})

            recipient_sid = connected_users.get(user_id)

            if recipient_sid:
                channel = "chatbot_response" if message["channel"] == "chatbot_response" else "agent_response"
                socketio.emit(channel, {"message": response}, room=recipient_sid)

# Gửi tin nhắn từ user đến Rasa
def listen_user_message():
    pubsub = r.pubsub()
    pubsub.subscribe("user_message")

    for message in pubsub.listen():
        if message["type"] == "message":
            data = json.loads(message["data"])
            user_id = data["user_id"]
            user_message = data["message"]

            response = requests.post(RASA_URL, json={"sender": user_id, "message": user_message})
            bot_response = response.json()[0]["text"] if response.json() else "Xin lỗi, tôi không hiểu."

            response_data = {"user_id": user_id, "response": bot_response}
            r.publish("chatbot_response", json.dumps(response_data, ensure_ascii=False))

# Load trang User.html
@app.route("/")
def home():
    return render_template("User.html")

# Chạy ứng dụng Flask
if __name__ == "__main__":
    threading.Thread(target=listen_redis, daemon=True).start()
    threading.Thread(target=listen_user_message, daemon=True).start()

    socketio.run(app, debug=True, host="0.0.0.0", port=5000, use_reloader=False)

# Đo thời gian
"""
@app.route('/products', methods=['GET'])
def get_products():
    # 1️⃣ Bắt đầu đo thời gian Redis
    start_time = time.time()
    
    # Kiểm tra Redis cache
    cached_products = r.get("products")
    
    redis_time = time.time() - start_time  # Thời gian truy xuất Redis
    if cached_products:
        print(f"🟢 Dữ liệu từ Redis cache (Thời gian: {redis_time:.6f} giây)")
        return jsonify({"products": json.loads(cached_products), "redis_time": redis_time, "source": "redis"})

    # 2️⃣ Nếu không có trong Redis, đo thời gian truy vấn SQL Server
    start_time = time.time()
    
    with engine.connect() as conn:
        query = text("SELECT * FROM products")
        result = conn.execute(query)
        products = [dict(row._mapping) for row in result]  # Convert thành danh sách dict
    
    sql_time = time.time() - start_time  # Thời gian truy vấn SQL Server
    print(f"🟠 Dữ liệu từ SQL Server (Thời gian: {sql_time:.6f} giây)")

    if not products:
        return jsonify({"products": None, "message": "Không có sản phẩm nào", "redis_time": redis_time, "sql_time": sql_time})

    # 3️⃣ Lưu vào Redis cache (timeout 5 phút)
    r.setex("products", 300, json.dumps(products))

    return jsonify({"products": products, "redis_time": redis_time, "sql_time": sql_time, "source": "database"})
"""