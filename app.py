import sqlite3
import os
from flask import Flask, request, jsonify
import hashlib
import json
import hmac
import base64


app = Flask(__name__)
db_name = "project2.db"
sql_file = "project2.sql"
db_flag = False

def create_db():
   conn = sqlite3.connect(db_name)

   with open(sql_file, 'r') as sql_startup:
      init_db = sql_startup.read()

   cursor = conn.cursor()
   cursor.executescript(init_db)
   conn.commit()
   conn.close()

   global db_flag
   db_flag = True
   return conn

def get_db():
	if not db_flag:
		create_db()
	conn = sqlite3.connect(db_name)
	return conn


def hash_pass(password, salt):
	obj = hashlib.sha256((password+salt).encode())
	return obj.hexdigest()

def valid_pass(password, first_name, last_name, username):
	if len(password) < 8:
		return False
	else:
		upper_c = False
		lower_c = False
		digit = False
		for i in password:
			if i.isupper():
				upper_c = True
			elif i.islower():
				lower_c = True
			elif i.isdigit():
				digit = True
		check = upper_c and lower_c and digit
		
		for word in [first_name, last_name, username]:
			if word.lower() in password.lower():
				return False
			
		return check
	
def generate_jwt(username):
	with open('key.txt', 'r') as file:
		key = file.read().strip()

	header = {"alg": "HS256","typ": "JWT"}
	payload = {"username": username}
	
	header_encoded = base64.urlsafe_b64encode(json.dumps(header).encode('utf-8')).decode('utf-8')
	payload_encoded = base64.urlsafe_b64encode(json.dumps(payload).encode('utf-8')).decode('utf-8')
    
   # Create the message to sign
	message = f"{header_encoded}.{payload_encoded}"
	signature = hmac.new(key.encode('utf-8'),message.encode('utf-8'),hashlib.sha256).hexdigest()
	jwt_token = f"{message}.{signature}"
	
	return jwt_token

def verify_jwt(token):
	try:
		parts = token.split(".")
		if len(parts) !=3:
			return None
		
		header, payload, signature = parts
		with open('key.txt', 'r') as file:
			key = file.read().strip()

		message = f"{header}.{payload}"
		expected_signature = hmac.new(key.encode('utf-8'),message.encode('utf-8'),hashlib.sha256).hexdigest()
		
		if signature != expected_signature:
			return None
		
		decoded_payload = base64.urlsafe_b64decode(payload).decode('utf-8')
		final = json.loads(decoded_payload)
		
        
		return final.get('username')
	
	except:
		return None
				
@app.route('/create_user', methods=['POST'])      
def create_user():
	conn = get_db()
	cursor = conn.cursor()
	
	first_name = request.form.get('first_name')
	last_name = request.form.get('last_name')
	username = request.form.get('username')
	email_address = request.form.get('email_address')
	password = request.form.get('password')
	salt = request.form.get('salt')
	
   # check for existing user
	cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
	if cursor.fetchone():  # if username already exists
		return json.dumps({"status": 2, "pass_hash": "NULL"})
	
	cursor.execute("SELECT email_address FROM users WHERE email_address = ?", (email_address,))
	if cursor.fetchone():  # if email is already in use
		return json.dumps({"status": 3, "pass_hash": "NULL"})
	

   # validate password
	if not valid_pass(password, first_name, last_name, username):
		conn.close()
		return json.dumps({"status": 4, "pass_hash": "NULL"})
	
	pass_hash = hash_pass(password, salt)
	
	
	# add user to db
	user = (first_name, last_name, username, email_address, pass_hash, salt)
	cursor.execute("INSERT INTO users VALUES (?, ?, ?, ?, ?, ?)", user)
	conn.commit()  
	conn.close()
	return json.dumps({"status": 1, "pass_hash": pass_hash})

@app.route('/clear', methods=['GET'])
def clear():
	try:
        # Close any existing connections first
        if os.path.exists(db_name):
            os.remove(db_name)
        
        # Reset the flag so DB gets recreated
        global db_flag
        db_flag = False
        
        # Recreate fresh database
        create_db()
        
        return json.dumps({"status": 1})
    except Exception as e:
        return json.dumps({"status": 2})

@app.route('/login', methods=['POST'])
def login():
	conn = get_db()
	cursor = conn.cursor()

	username = request.form.get('username')
	password= request.form.get('password')
	# if not exist
	cursor.execute("SELECT password_hash, salt FROM users WHERE username=?", (username,))
	user = cursor.fetchone()
	if not user:
		conn.close()
		return json.dumps({"status": 2, "jwt": "NULL"})
	
	stored_hash, stored_salt = user
	current_hash = hash_pass(password, stored_salt)
	# verify if password matches
	if current_hash!=stored_hash:
		conn.close()
		return json.dumps({"status": 2, "jwt": "NULL"})
	
	jwt_token = generate_jwt(username)

	conn.close()
	return json.dumps({"status": 1, "jwt": jwt_token})		

@app.route('/follow', methods=['POST'])
def follow():
	conn = get_db()
	cursor = conn.cursor()

	jwt = request.headers.get('Authorization')
	if not jwt:
        conn.close()
        return json.dumps({"status": 2})  # missing
    
    # verify who is making the request
    user = verify_jwt(jwt)
    if not user:
        conn.close()
        return json.dumps({"status": 2}) # invalid


	target = request.form.get('username')
	if not target or target == user:
        conn.close()
        return json.dumps({"status": 2})
	#if already in folllow list, returns error
	cursor.execute("SELECT follower FROM follow_list WHERE user= ? ", (target,))
	if cursor.fetchone():
		return json.dumps({"status": 2})

	cursor.execute("SELECT * FROM follow_list WHERE user = ? AND follower = ?", (user, target))
    if cursor.fetchone():
        conn.close()
        return json.dumps({"status": 2}) 
	
	cursor.execute("INSERT INTO follow_list (user,follower) VALUES (?, ?)", (user, target))
    conn.commit()
    conn.close()
	return json.dumps({"status": 1})





	
	
