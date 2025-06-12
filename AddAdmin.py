import bcrypt
import redis

# Kết nối Redis
r = redis.StrictRedis(host='localhost', port=6379, decode_responses=True)

def add_admin(role, adminname, password, email, phone):
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    # Lưu vào Redis với đầy đủ thông tin
    r.hset(f"admin:{adminname}", mapping={
        "password": hashed_password.decode('utf-8'),
        "email": email,
        "phone": phone
    })

    print(f"Admin '{adminname}' đã được thêm thành công!")

# Thêm admin mới
add_admin("admin", "admin1", "password123", "23521022@gm.uit.edu.vn", "0589234181")
add_admin("admin", "admin2", "securePass456", "hothiminhngoc7461@gmail.com", "0374799888")
