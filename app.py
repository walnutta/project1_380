import sqlite3
import os
from flask import Flask, request, jsonify
import hashlib
import json
import hmac
import base64


app = Flask(__name__)
db_name = "project1.db"
sql_file = "project1.sql"
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
	conn = get_db()
	cursor = conn.cursor()
	cursor.execute("DELETE FROM users")
	cursor.execute("DELETE FROM prev_passwords")  
	conn.commit()
	conn.close()
	return json.dumps({"status": 1})
	
def generate_jwt(username):
	with open('key.txt', 'r') as file:
		key = file.read().strip()

	header = {"alg": "HS256","typ": "JWT"}
	payload = {"username": username,"access": "True"}
	
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
		if final.get('access') != 'True':
			return None
        
		return final.get('username')
	
	except:
		return None
	
@app.route('/view', methods=['POST'])
def view():
	conn = get_db()
	cursor = conn.cursor()

	jwt = request.form.get('jwt')

	username = verify_jwt(jwt)
	if not username:
		return json.dumps({"status": 2, "data": "NULL"})
	
	#get user data
	cursor.execute("SELECT username, email_address, first_name, last_name FROM users WHERE username=?", (username,))
	user = cursor.fetchone()
	
	if not user:
		conn.close()
		return json.dumps({"status": 2, "data": "NULL"})
	
	username, email_address, first_name, last_name = user

	# return user data
	data = {
		"username": username,
		"email_address": email_address,
		"first_name": first_name,
		"last_name": last_name
	}

	conn.close()
	return json.dumps({"status": 1, "data": data})

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

@app.route('/update', methods=['POST'])
def update():
	conn = get_db()
	cursor = conn.cursor()

	jwt = request.form.get('jwt')
	verified_username = verify_jwt(jwt)
	if not verified_username:
		return json.dumps({"status": 3})
	
	username = request.form.get('username')
	new_username = request.form.get('new_username')
	password = request.form.get('password')
	new_password = request.form.get('new_password')
	
	if username and new_username:
		#if username did not exist
		if username != verified_username:
			conn.close()
			return json.dumps({"status":2})
		
		cursor.execute('SELECT username FROM users WHERE username=?', (new_username,))  #if username found -> not unique
		if cursor.fetchone():
			conn.close()
			return json.dumps({"status":2})
		
		cursor.execute("UPDATE users SET username=? WHERE username=?", (new_username, username))
		conn.commit()
		conn.close()
		return json.dumps({"status": 1})
	
	elif password and new_password:
		cursor.execute("SELECT password_hash, salt, first_name, last_name FROM users WHERE username=?", (verified_username,))
		user = cursor.fetchone()
		if not user:
			conn.close()
			return json.dumps({"status": 2, "jwt": "NULL"})
	
		password_hash, salt, first_name, last_name = user
		current = hash_pass(password, salt)

		if current != password_hash:
			conn.close()
			return json.dumps({"status":2})
		
		if not valid_pass(new_password, first_name, last_name, verified_username):
			conn.close()
			return json.dumps({"status": 2})

		new_hash = hash_pass(new_password, salt)

		cursor.execute("SELECT password_hash FROM prev_passwords WHERE username=?", (verified_username,))
		olds = cursor.fetchall()
		for (old,) in olds:
			if old == new_hash:
				conn.close()
				return json.dumps({"status":2})
		
		if new_hash == password_hash:
			conn.close()
			return json.dumps({"status": 2})
	
		cursor.execute("INSERT INTO prev_passwords VALUES (?, ?)", (verified_username, password_hash))
		
		cursor.execute("UPDATE users SET password_hash=? WHERE username=?", (new_hash, verified_username))
		conn.commit()
		conn.close()
		return json.dumps({"status": 1})
	else:
		conn.close()
		return json.dumps({"status":2})


