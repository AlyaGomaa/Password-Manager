import base64
import hashlib
import mysql.connector
from Crypto import Random
from Crypto.Cipher import AES

# sudo mysql -p

# hardcoded_pw = "lolo" #for now
# _key =  hardcoded_pw + ((16-len(hardcoded_pw)) * '=')
# BS = 16
# ctrl shift - collapse all
# ctrl alt left restore last position
# alt shift l reformat
DB_NAME = "pm"
TABLES = {
    "User": "CREATE TABLE User (id MEDIUMINT NOT NULL AUTO_INCREMENT, username VARCHAR(1000) NOT NULL UNIQUE, master_password VARCHAR(50) NOT NULL, PRIMARY KEY (id))", \
    "Data": "CREATE TABLE Passwords (id MEDIUMINT NOT NULL AUTO_INCREMENT, user_id MEDIUMINT, username VARCHAR(1000) NOT NULL, password VARCHAR(1000) NOT NULL, url VARCHAR(1000) NOT NULL ,PRIMARY KEY (id) )"
}


class User:

    def __init__(self, username, master_key):
        self.username = username
        self.master_key = master_key



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
        self.current_user = None

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
            self.connection.commit()
            cur_user = User(username, master_key)
            self.current_user = cur_user

            print("User Created Successfully")

        except mysql.connector.Error as err:
            print(f"{err}")

    def sign_in(self):

        username = input("Username: ")
        master_key = input("Master Key: ")
        md5_of_master_pw = hashlib.md5(master_key.encode()).hexdigest()

        sql = f"SELECT * FROM User WHERE master_password = '{md5_of_master_pw}' AND username='{username}'"
        try:
            self.cursor.execute(sql)
            user_exists = self.cursor.fetchall()  # returns array of tuples

            if len(user_exists) == 1:
                cur_user = User(username, master_key)
                self.current_user = cur_user

                print("Successful login")
            else:
                print("Incorrect Username or Password")

        except mysql.connector.Error as err:
            print("Can't sign in")

    def is_url_present(self,url):
        sql = f"SELECT * FROM Passwords WHERE url='{url}'"
        self.cursor.execute(sql)
        # gets the number of rows affected by the command executed
        entry = self.cursor.fetchone()
        return False if entry == None else True

    def insert_row(self,username, pw, url):
        """Inserts the entry if it doesn't exist and edits the existing entry if it does. """
        if self.is_url_present(url):
            _update("username", username, url)
            _update("password", pw, url)

        else:
            aes = AESCipher(self.current_user.master_key)
            encrypted_pw = aes.encrypt(pw)
            sql = f"INSERT INTO Passwords (username, password ,url) VALUES ('{username}', '{encrypted_pw}' , '{url}')"

            self.cursor.execute(sql)
            self.connection.commit()
            print(self.cursor.rowcount, "was inserted.")

    def handle_insert(self):
        username = input("Username: ")
        password = input("Password: ")
        url = input("Url: ")
        self.insert_row(username,password,url)


    def _update(self,field, new_data, url):
        if field == 'password':
            aes = AESCipher(self.current_user.master_key)
            new_data = aes.encrypt(new_data)

        sql = "UPDATE Passwords SET {field} ='{new_data}' WHERE url='{url}'"


        self.cursor.execute(sql)
        self.connection.commit()
        print(f"{field} edited.")

    def _delete(self,url):
        sql = f"DELETE FROM PM WHERE url='{url}'"
        self.cursor.execute(sql)
        self.connection.commit()
        print("Deleted.")


class AESCipher:
    def __init__(self, key):
        self.key = pad(key)
        self.BS = 16

    def pad(self,raw):
        return raw + (self.BS - len(raw) % self.BS) * chr(self.BS - len(raw) % self.BS)

    def encrypt(self, raw):
        raw = self.pad(raw)  # pad
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


def get_db():
    sql = "SELECT username, password, url FROM PM"
    self.cursor.execute(sql)
    return self.cursor


def print_db():
    self.cursor = get_db()
    print(" Username\t\tPassword\t\t\t\tUrl\t\t")
    for (username, password, url) in self.cursor:
        entry = f"| {username} | {password} | {url} |"
        print(" " + "-" * (len(entry) - 2))
        print(entry)

    print(" " + "-" * (len(entry) - 2))



def export_passwords():
    f = open("passwords.csv", "w")
    f.write('name,url,username,password\n')
    self.cursor = get_db()
    aes = AESCipher(_key)
    for (username, password, url) in self.cursor:
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


def main_menu():
    print("Welcome to Password Manager.")
    choice = int(input("1. Login \n2. Create New User\n>> "))
    return choice


def user_interaction(current_user):
    if not current_user:
        print("Error retrieving user information")
        return -1
    print(f"\t\tYou're logged in as {current_user.username}")
    choice = int(input("1. Insert\n2. Update\n3.Delete\n>>>"))
    return choice


if __name__ == "__main__":

    password_manager = PasswordManager()
    operations = {1: password_manager.insert_row,
                  2: password_manager.update_row,
                  3: password_manager.delete_row
                  }
    while True:
        choice = main_menu()

        if choice == 1:
            password_manager.sign_in()

        elif choice == 2:
            password_manager.register()

        if password_manager.current_user:

            while True:
                choice = user_interaction(password_manager.current_user)
                if choice == -1: break
                if choice in operations:
                    operations[choice]()

                else:
                    continue

    # current_user = User(username,master_key) # create an instance of the User class
    # if current_user.exists() :
    #     print("yuppyyyy")
    #     current_user.sign_in()

    # else:
    #     print("gonna sign you in baby")
    #     current_user.register()
    #     _insert("sara'susername" ,"sara'spw" , "sara'surl")

    # self.cursor = current_user.connection.cursor()
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
