from flask_login import UserMixin
from db import get_db

import os
from itsdangerous import URLSafeTimedSerializer
login_serializer = URLSafeTimedSerializer(os.environ['SECRET_KEY'])
import psycopg2
        
class User(UserMixin):
    def __init__(self, id_, name, email, profile_pic, email_verified):
        self.id = id_
        self.name = name
        self.email = email
        self.profile_pic = profile_pic
        self.email_verified = email_verified
        self.api_key = None #api_key

    @staticmethod
    def get(user_id):
        conn = get_db()
        cursor = conn.cursor()

        try:
            cursor.execute("""SELECT id, name, email, profile_pic, email_verified, 'api_key' FROM "public".users WHERE id = %s limit 1 """, (user_id,))
            result = cursor.fetchone()
            print("User")
            print(result)
            
            if result is None:
                return None
            
            if result is not None: 
                user = User(
                id_=result[0], name=result[1], email=result[2], profile_pic=result[3], email_verified=result[4])
                
                return user
            else: 
                return None
            
        except (Exception, psycopg2.DatabaseError) as error:
            print("Error in User Get" ) 
            print(error)
            return None

    @staticmethod
    def by_email(email):
        db = get_db()
        cursor = db.cursor()
        print(cursor)
        print("Cursor")
        cursor.execute(
            "SELECT * FROM users WHERE email = %s limit 1", (email,)
        )
        result = cursor.fetchone()
        
        if not user:
            print("returning None")
            return None

        user = User(
            id_=result[0], name=result[1], email=result[2], profile_pic=result[3], email_verified=result[4]
        )
        
        return user

    @staticmethod
    def create(id_, name, email, profile_pic, email_verified):
        db = get_db()
        cursor = db.cursor()
        
        if User.get(id_) is None:
            cursor.execute(
                "INSERT INTO users (id, name, email, profile_pic, email_verified, api_key) "
                "VALUES (%s, %s, %s, %s, %s, %s)"
                "ON CONFLICT (id) "
                " DO UPDATE SET "
                "name = EXCLUDED.name, "
                "email = EXCLUDED.email,"
                "email_verified = EXCLUDED.email_verified",
                (id_, name, email, profile_pic, str(email_verified), "api_key"),
            )
            db.commit()
            
        if User.get(id_) is not None:
            cursor.execute(
                "INSERT INTO users (id, name, email, profile_pic, email_verified, api_key) "
                "VALUES (%s, %s, %s, %s, %s, %s)"
                "ON CONFLICT (id) "
                " DO UPDATE SET "
                "email_verified = EXCLUDED.email_verified",
                (id_, name, email, profile_pic, str(email_verified), "api_key"),
            )
            db.commit()
            #cursor.close()

    @staticmethod
    def logout(id_):
        print(id_)
        db = get_db()
        cursor = db.cursor()
        user = User.get(id_)
        
        if User.get(id_) is not None:
            cursor.execute(
                "INSERT INTO users (id, name, email, profile_pic, email_verified, api_key) "
                "VALUES (%s, %s, %s, %s, %s, %s)"
                "ON CONFLICT (id) "
                " DO UPDATE SET "
                "email_verified = EXCLUDED.email_verified ",
                (id_, user.name, user.email, user.profile_pic, 'False', user.api_key),
            )
            db.commit()

    @staticmethod
    def login(id_):
        print(id_)
        db = get_db()
        cursor = db.cursor()
        user = User.get(id_)
        
        if User.get(id_) is not None:
            cursor.execute(
                "INSERT INTO users (id, name, email, profile_pic, email_verified, api_key) "
                "VALUES (%s, %s, %s, %s, %s, %s)"
                "ON CONFLICT (id) "
                " DO UPDATE SET "
                "email_verified = EXCLUDED.email_verified ",
                (id_, user.name, user.email, user.profile_pic, 'True', user.api_key),
            )
            db.commit()
    
    def get_auth_token(self):
        data = [self.id, self.name]
        return login_serializer.dumps(data)

