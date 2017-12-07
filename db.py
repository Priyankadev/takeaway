from pymongo import MongoClient
from flask import jsonify
import traceback
import json
import datetime
from bson import ObjectId


class Mdb:

    def __init__(self):
        conn_str = 'mongodb://tuser:tpass@ds133136.mlab.com:33136/' \
                   'takeaway'
        client = MongoClient(conn_str)
        self.db = client['takeaway']
        print("[Mdb] connected to database :: ", self.db)

############################################################################
#                                                                          #
#                              USER PANEL                                  #
#                                                                          #
############################################################################

    def check_email(self, email):
        return self.db.user.find({'email': email}).count() > 0


############################################################################
#                                                                          #
#                       REGISTRATION USRE IN DATABASE                      #
#                                                                          #
############################################################################
    def add_user(self, name, email, pw_hash, age, phone, address, gender):
        try:
            rec = {
                'name': name,
                'email': email,
                'password': pw_hash,
                'age': age,
                'phone': phone,
                'address': address,
                'gender': gender
            }
            self.db.user.insert(rec)

        except Exception as exp:
            print("add_user() :: Got exception: %s", exp)
            print(traceback.format_exc())

############################################################################
#                                                                          #
#        CHECK EMAIL EXIST OR NOT IN DATABASE BEFORE LOGIN CANDIDATE       #
#                                                                          #
############################################################################
    def user_exists(self, email):
        return self.db.user.find({'email': email}).count() > 0

############################################################################
#                                                                          #
#                   MATCH PASSWORD AND EMAIL THEN LOGIN                    #
#                                                                          #
############################################################################
    def get_password(self, email):
        result = self.db.user.find({'email': email})
        name = ''
        password = ''
        if result:
            for data in result:
                name = data['name']
                password = data['password']
                print('password in db class', password)
        return password

############################################################################
#                                                                          #
#                GET NAME AND EMAILID VIA EMAIL ADDRESS                    #
#                                                                          #
############################################################################
    def get_name(self, email):
        result = self.db.user.find({'email': email})
        name = ''
        email = ''
        phone = ''
        address = ''
        if result:
            for data in result:
                name = data['name']
                email = data['email']
                phone = data['phone']
                address = data['address']
        return name


#############################################
#                                           #
#         GET USER ID BY SESSION            #
#                                           #
#############################################
    def get_user_id_by_session(self, email):
        result = self.db.user.find({'email': email})
        id = ''
        if result:
            for data in result:
                id = data['_id']
        return id

############################################################################
#                                                                          #
#                       REGISTRATION USRE IN DATABASE                      #
#                                                                          #
############################################################################
    def ad_post(self, email, title, category, description, name, phone, city):
        try:
            rec = {
                'email': email,
                'title': title,
                'category': category,
                'description': description,
                'name': name,
                'phone': phone,
                'city': city
            }
            self.db.post.insert(rec)

        except Exception as exp:
            print("ad_post() :: Got exception: %s", exp)
            print(traceback.format_exc())


    def check_category(self, category):
        return self.db.category.find({'category': category}).count() > 0



#############################################
#                                           #
#         GET ADMIN ID BY SESSION           #
#                                           #
#############################################
    def get_admin_id_by_session(self, email):
        result = self.db.admin.find({'email': email})
        id = ''
        if result:
            for data in result:
                id = data['_id']
        return id

############################################################################
#                                                                          #
#                        CANDIDATE SESSION INFORMATION                     #
#                                                                          #
############################################################################
    def save_login_info(self, user_email, mac, ip, user_agent, type):
        LOGIN_TYPE = 'User Login'
        try:
            ts = datetime.datetime.today().strftime("%a %b %d %X  %Y ")

            rec = {
                'user_id': user_email,
                'mac': mac,
                'ip': ip,
                'user_agent': user_agent,
                'user_type': type,
                'timestamp': ts
            }

            self.db.user_session.insert(rec)
        except Exception as exp:
            print("save_login_info() :: Got exception: %s", exp)
            print(traceback.format_exc())

############################################################################
#                                                                          #
#                      ADD ADMIN IN DATABASE BY HARD CODE                  #
#                                                                          #
############################################################################
    def add_admin(self, email, password):
        try:
            rec = {
                'email': email,
                'password': password
            }
            self.db.admin.insert(rec)
        except Exception as exp:
            print("add_admin() :: Got exception: %s", exp)
            print(traceback.format_exc())

############################################################################
#                                                                          #
#       CHECK EMAIL EXIST OR NOT IN DATABASE BEFORE LOGIN CANDIDATE        #
#                                                                          #
############################################################################
    def admin_exists(self, email, password):

        return self.db.admin.find({'email': email, 'password': password}).\
                   count() > 0

    def save_category(self, category1, category2, category3, category4):
        try:
            rec = {

                'category' : [
                    {'category1': category1},
                    {'category2': category2},
                    {'category3': category3},
                    {'category4': category4},
                    ]
            }

            self.db.category.insert(rec)
        except Exception as exp:
            print("add_admin() :: Got exception: %s", exp)
            print(traceback.format_exc())
############################################################################
#                                                                          #
#                              MAIN                                        #
#                                                                          #
############################################################################
if __name__ == "__main__":
    mdb = Mdb()
    mdb.add_admin('john@gmail.com', '123')
