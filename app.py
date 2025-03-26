from flask import Flask, render_template, request, jsonify,redirect, session
import sqlite3
import bcrypt
import time
import re
app = Flask(__name__)
app.secret_key = "super_secret_key"

def init_db():
    
    with sqlite3.connect("database.db") as conn:
        cursor=conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, 
                    username TEXT UNIQUE, 
                    password TEXT,
                    failed_attempts INTEGER DEFAULT 0,
                    lockout_time INTEGER DEFAULT 0)''')
        conn.commit()

init_db()

def check_password_strength(password):
    if len(password) < 8 or len(password) == 0 :
        obj={"success":False,"message":"Password must be at least 8 characters long, contain a number and an uppercase letter."}
        return obj
    else:
        if not re.search("[a-z]", password) or not re.search(r"[0-9]",password) or not re.search(r"[!@#$%&*?]",password):
            obj={"success":True,"message":"Weak"}
            return obj
        elif len(password) >= 8 and re.search("[a-z]", password) and re.search(r"[0-9]",password) and re.search(r"[!@#$%&*?]",password):
            obj={"success":True,"message":"Strong","err":False}
            return obj

@app.route("/",methods=["GET","POST"])
def register():
    if request.method == "POST":
        
        username = request.json["username"]
        password = request.json["password"]
       

        passwordStrength=check_password_strength(password)

        if not passwordStrength['success']:
            return jsonify({"message":passwordStrength['message']})

        hashed_password=bcrypt.hashpw(password.encode(),bcrypt.gensalt())
        print(hashed_password)

        with sqlite3.connect("database.db") as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("INSERT INTO users (username, password) VALUES (?,?)", (username, hashed_password))
                conn.commit()
                return jsonify({"strength":passwordStrength['message']})
            except sqlite3.IntegrityError:
                return jsonify({"message":"Username already exists."})
        
        #return redirect("/index")
    return render_template("index.html")

MAX_ATTEMPT=3
LOCKOUT_TIME=60

@app.route("/login", methods=["GET"])  
def login():
    return render_template("login.html") 

@app.route("/signin", methods=["POST"])  
def singin():
    if request.method=="POST":
         username=request.json["username"]
         password=request.json["password"]
        
        
         with sqlite3.connect("database.db") as conn:
             cursor=conn.cursor()
             cursor.execute("SELECT password, failed_attempts, lockout_time FROM users WHERE username=?", (username,))
             user=cursor.fetchone()

        
         if user:
             hashed_password,failed_attempt,lockout_time = user

             if failed_attempt >= MAX_ATTEMPT:
                 if time.time() - lockout_time < LOCKOUT_TIME:
                     return jsonify({"message":"Account locked. try again after 60 minutes."})
                 else:
                     with sqlite3.connect("database.db") as conn:
                         cursor=conn.cursor()
                         cursor.execute("UPDATE users SET failed_attempts=0, lockout_time=0 WHERE username=?",(username,))
                         conn.commit()
        
         if bcrypt.checkpw(password.encode(),hashed_password):
             session["user"]=username
             with sqlite3.connect("database.db") as conn:
                 cursor=conn.cursor()
                 cursor.execute("UPDATE users SET failed_attempts=0 WHERE username=?",(username,))
                 conn.commit()
            #  return redirect("/")
                 return jsonify({"message":"You logged in successfully."})

         else:
             with sqlite3.connect("database.db") as conn:
                 cursor=conn.cursor()
                 failed_attempt += 1
                 if failed_attempt >= MAX_ATTEMPT:
                     cursor.execute("UPDATE users SET failed_attempts=?,lockout_time=? WHERE username=?", (failed_attempt, time.time(), username,))
                     conn.commit()
                     return jsonify({"message":"Your account has been locked due to multiple wrong attempts."}) 
                 else:
                     cursor.execute("UPDATE users SET failed_attempts=? WHERE username=?", (failed_attempt, username,))
                     conn.commit()
                     return jsonify({"message":"Invalid  password"})
    return render_template("login.html") 

@app.route("/logout")
def logout():
    session.pop("user",None)
    return redirect("/login")

if __name__ == "__main__":
    app.run(debug=True,port=8080)