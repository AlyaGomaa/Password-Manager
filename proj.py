import mysql.connector
from mysql.connector import errorcode
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto import Random
from getpass import getpass

# sudo mysql -p

# hardcoded_pw = "lolo" #for now
# _key =  hardcoded_pw + ((16-len(hardcoded_pw)) * '=')
# BS = 16

DB_NAME = "password_manager"
TABLES = {
    "User": "CREATE TABLE User (id MEDIUMINT NOT NULL AUTO_INCREMENT, username VARCHAR(1000) NOT NULL UNIQUE, master_password VARCHAR(50) NOT NULL, PRIMARY KEY (id))", \
    "Data": "CREATE TABLE Passwords (id MEDIUMINT NOT NULL AUTO_INCREMENT, user_id MEDIUMINT, username VARCHAR(1000) NOT NULL, password VARCHAR(1000) NOT NULL, url VARCHAR(1000) NOT NULL ,PRIMARY KEY (id) )"
    }


class PasswordManager():
    def __init__(self):
        # self.username = username
        # self.master_key = master_key
        connection = mysql.connector.connect(
            host="localhost",
            user="root",
            password="gbhgbhgbh"
            # database="password_manager" #name of the database
        )
        self.connection = connection
        self.cursor = connection.cursor()

        try:
            self.cursor.execute(f"USE {DB_NAME}")

        except mysql.connector.Error as err:
            print(f"Database {DB_NAME} does not exists.")

            try:
                self.create_database()
                self.cursor.execute(f"USE {DB_NAME}")

            except  mysql.connector.Error as err:
                print(f"Coudnt create db: {err}")
            try:
                self.create_tables()
            except  mysql.connector.Error as err:
                print(f"couldn't create tables {err}")

    def create_database(self):
        sql = f"CREATE DATABASE {DB_NAME} DEFAULT CHARACTER SET 'utf8'"
        self.cursor.execute(sql)

    def create_tables(self):
        for table in TABLES:
            sql = TABLES[table]
            self.cursor.execute(sql)

    def register(self):

        username = input("Username: ")
        master_key = input("Master Key: ")
        master_key = hashlib.md5(master_key.encode()).hexdigest()
        sql = f"INSERT INTO User (username,master_password) VALUES ('{username}' , '{master_key}')"

        try:
            self.cursor.execute(sql)
            print("User Created Successfully")
        except mysql.connector.Error as err:
            print(f"{err}")

    def sign_in(self):

        username = input("Username: ")
        master_key = input("Master Key: ")
        md5_of_master_pw = hashlib.md5(master_key.encode()).hexdigest()

        sql =f"SELECT EXISTS(SELECT 1 FROM User WHERE master_password = '{md5_of_master_pw}' AND username='{username}' )"
        try:
            self.cursor.execute(sql)
            user_exists = mycursor.fetchone()
            if user_exists:
                print("successful login")
            else:
                print("msh successful login")

        except mysql.connector.Error as err:
            print("Can't sign in")


class AESCipher:
    def __init__(self, key):
        self.key = pad(key)
        self.BS = 16

    def pad(raw):
        return raw + (self.BS - len(raw) % self.BS) * chr(self.BS - len(raw) % self.BS)

    def encrypt(self, raw):
        raw = pad(raw)  # pad
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(enc[16:])
        decrypted = decrypted[:-ord(decrypted[len(decrypted) - 1:])]  # unpad
        return decrypted.decode("utf-8")


class User:

    def __init__(self, username, master_key):
        self.username = username
        self.master_key = master_key
        self.id = NoneType



        # maybe obtain a cursor everytime you need one?
        # global mycursor 
        # mycursor = connection.cursor()
        # return mycursor
        # print(f"db: {db} , self.db: {self.db}")

    def exists(self):
        mycursor = self.cursor

        sql = f"SELECT user FROM mysql.user WHERE user='{username}'"
        mycursor.execute(sql)
        user_exists = mycursor.fetchone()
        return True if user_exists else False

    def register(self):
        # start mn henaa INSERT INTO animals (id,name) VALUES(0,'groundhog')
        sql = f"INSERT INTO User (Username,Master_Password) VALUES({self.username} , {self.password})"

        # # create a new user in the database
        # sql = f"CREATE USER '{username}'@'localhost' IDENTIFIED BY '{master_key}'"
        # mycursor.execute(sql)

        # # create a new table named after him
        # tablename=username.upper()
        # sql = f"CREATE TABLE {tablename} (username VARCHAR(1000) NOT NULL, password VARCHAR(1000) NOT NULL, url VARCHAR(1000) NOT NULL)"
        # mycursor.execute(sql)

        # #grant him all priveledges only on his table
        # sql = f"GRANT ALL PRIVILEGES ON passsword_manager.tablename TO '{username}'@'localhost'"
        # mycursor.execute(sql)
        # # sign the user in
        # self.sign_in()


# create table User (id MEDIUMINT NOT NULL AUTO_INCREMENT, Username VARCHAR(1000) NOT NULL, Master_Password VARCHAR(50) NOT NULL, PRIMARY KEY (id))


def is_url_present(url):
    sql = f"SELECT * FROM PM WHERE url='{url}'"
    mycursor.execute(sql)
    # gets the number of rows affected by the command executed
    entry = mycursor.fetchone()
    return False if entry == None else True


def get_db():
    sql = "SELECT username, password, url FROM PM"
    mycursor.execute(sql)
    return mycursor


def print_db():
    mycursor = get_db()
    print(" Username\t\tPassword\t\t\t\tUrl\t\t")
    for (username, password, url) in mycursor:
        entry = f"| {username} | {password} | {url} |"
        print(" " + "-" * (len(entry) - 2))
        print(entry)

    print(" " + "-" * (len(entry) - 2))


def _insert(username, pw, url):
    """Inserts the entry if it doesn't exist and edits the existing entry if it does. """
    if is_url_present(url):
        _update("username", username, url)
        _update("password", pw, url)

    else:
        aes = AESCipher(_key)
        encrypted_pw = aes.encrypt(pw)
        sql = "INSERT INTO PM (username, password,url) VALUES (%s, %s , %s)"
        val = [
            (username, encrypted_pw, url)
        ]

        mycursor.executemany(sql, val)

        db.commit()

        print(mycursor.rowcount, "was inserted.")


def _update(field, new_data, url):
    if field == 'password':
        aes = AESCipher(_key)
        new_data = aes.encrypt(new_data)

    sql = "UPDATE PM SET " + field + "= %s WHERE url=%s"
    val = [
        (new_data, url)
    ]

    mycursor.executemany(sql, val)
    db.commit()
    print(f"{field} edited.")


def _delete(url):
    sql = f"DELETE FROM PM WHERE url='{url}'"
    mycursor.execute(sql)
    db.commit()
    print("Deleted.")


def export_passwords():
    f = open("passwords.csv", "w")
    f.write('name,url,username,password\n')
    mycursor = get_db()
    aes = AESCipher(_key)
    for (username, password, url) in mycursor:
        decrypted_password = aes.decrypt(password)
        f.write(f"{url},{username},{decrypted_password}\n")
    f.close()
    print("Passwords exported to current directory.")


def import_passwords(_file):
    f = open(_file, 'r')
    credentials = f.read()

    for line in credentials.splitlines()[
                1:]:  # we don't need the first line of a csv file it's always url , username , password
        url, username, password = line.split(',')
        _insert(username, password, url)
    f.close()
    print("Passwords successfully imported.")
    print_db()


def config(usr):
    """make config file to determine if the user is already registered"""
    try:
        f = open("/home/password_manager.config", 'w+')
        f.write(usr + "\n")  # append the name of every registered user to the file
        f.close()
    except FileNotFoundError:  # first use
        f = open("/home/password_manager.config", 'w')

def get_choice():
    print("Welcome to Password Manager.")
    choice = int(input("1. Login \n2. Create New User\n>> "))
    return choice

if __name__ == "__main__":
    pw = PasswordManager()
    while True:
        choice = get_choice()
        if choice == 1:
            pw.sign_in()

        elif choice == 2:
            pw.register()

    # current_user = User(username,master_key) # create an instance of the User class
    # if current_user.exists() :
    #     print("yuppyyyy")
    #     current_user.sign_in()

    # else:
    #     print("gonna sign you in baby")
    #     current_user.register()
    #     _insert("sara'susername" ,"sara'spw" , "sara'surl")

    # mycursor = current_user.connection.cursor()
    # print_db()

    # db = mysql.connector.connect(
    # host="localhost",
    # user="root",
    # password="gbhgbhgbh",
    # database="password_manager"
    # )

# register User
# use master key
# 3dli el interface shwya
