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
#                       REGITRATION CANDIDATE IN DATABASE                  #
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
            print("add_candidate() :: Got exception: %s", exp)
            print(traceback.format_exc())
############################################################################
#                                                                          #
#                              MAIN                                        #
#                                                                          #
############################################################################
if __name__ == "__main__":
    mdb = Mdb()
    # mdb.add_admin('john@gmail.com', '123')
