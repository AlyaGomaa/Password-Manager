import base64
import hashlib
import mysql.connector
from Crypto import Random
from Crypto.Cipher import AES


DB_NAME = "password_manager"

TABLES = {
    "User": "CREATE TABLE Users (id MEDIUMINT NOT NULL AUTO_INCREMENT, username VARCHAR(1000) NOT NULL UNIQUE, master_password VARCHAR(50) NOT NULL, PRIMARY KEY (id))", \
    "Data": "CREATE TABLE Passwords (id MEDIUMINT NOT NULL AUTO_INCREMENT, user_id MEDIUMINT, username VARCHAR(1000) NOT NULL, password VARCHAR(1000) NOT NULL, url VARCHAR(1000) NOT NULL ,PRIMARY KEY (id) )"
}


class User:

    def __init__(self, username, master_key,id):
        self.username = username
        self.id = id
        self.master_key = master_key


class PasswordManager():
    def __init__(self):

        
        PASSWORD = input("Enter MYSQL root password: ")

        connection = mysql.connector.connect(
            host="localhost",
            user="root",
            password=PASSWORD

        )

        self.connection = connection
        self.cursor = connection.cursor()
        self.current_user = None

        
        try:
            self.cursor.execute(f"USE {DB_NAME}")
            
            
        except mysql.connector.Error as err:

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
        self.key = hashlib.md5(master_key.encode()).hexdigest()
        sql = f"INSERT INTO Users (username,master_password) VALUES ('{username}' , '{self.key}')"

        get_user_id = f"select * from Users where username='{username}'"
        try:
            self.cursor.execute(sql)
            self.connection.commit()
            self.cursor.execute(get_user_id)
            user_id = self.cursor.fetchone()[0]  # returns a row

            cur_user = User(username, self.key , user_id)
            self.current_user = cur_user
            print("User Created Successfully")

        except mysql.connector.Error as err:
            print(f"{err}")

    def sign_in(self):

        username = input("Username: ")
        master_key = input("Master Key: ")
        md5_of_master_pw = hashlib.md5(master_key.encode()).hexdigest()
        self.key = md5_of_master_pw
        sql = f"SELECT * FROM Users WHERE master_password = '{md5_of_master_pw}' AND username='{username}'"
        get_user_id = f"select * from Users where username='{username}'"
        try:
            self.cursor.execute(sql)
            user_exists = self.cursor.fetchall()  # returns array of tuples

            if len(user_exists) == 1:

                self.cursor.execute(get_user_id)
                user_id = self.cursor.fetchone()[0]  # returns a tuple , we only need the 1st element

                cur_user = User(username, self.key , user_id)
                self.current_user = cur_user
                print("Successful login")
            else:
                print("Incorrect Username or Password")

        except mysql.connector.Error as err:
            print("Can't sign in")

    def is_url_present(self, url):
        sql = f"SELECT * FROM Passwords WHERE url='{url}'"
        try:
            self.cursor.execute(sql)

            # gets the number of rows affected by the command executed
            entry = self.cursor.fetchone()
            return False if entry == None else True
        except mysql.connector.Error as err:
            print("Unknown error")

    def insert_row(self, username, pw, url):
        """Inserts the entry if it doesn't exist and edits the existing entry if it does. """
        
        if self.is_url_present(url):
            self.update_row("username", username, url)
            self.update_row("password", pw, url)


        else:

            aes = AESCipher(self.current_user.master_key)
            encrypted_pw = aes.encrypt(pw)
            sql = f"INSERT INTO Passwords (user_id,username, password ,url) VALUES ('{self.current_user.id}','{username}', '{encrypted_pw}' , '{url}')"
            self.cursor.execute(sql)
            self.connection.commit()
            print(self.cursor.rowcount, "was inserted.")
    def delete_row(self, url):
        try:
            sql = f"DELETE FROM Passwords WHERE url='{url}' AND user_id='{self.current_user.id}'"
            self.cursor.execute(sql)
            self.connection.commit()
            print("Row deleted.")

        except  mysql.connector.Error as err:
            print(err)


    def handle_input(self, choice):
        if choice == "insert" or choice=="update":
            username = input("Username: ")
            password = input("Password: ")
            url = input("Url: ")
            if choice == "insert":
                self.insert_row(username, password, url)

            else :

                self.update_row("username", username, url)
                self.update_row("password", password, url)

        elif choice == "delete":
            url = input("Url: ")
            self.delete_row(url)
        elif choice == "export":
            self.export_passwords()
        elif choice == "import":
            filepath = input("Filepath:")
            self.import_passwords(filepath)

    def update_row(self, field, new_data, url):
        if field == 'password':
            aes = AESCipher(self.current_user.master_key)
            new_data = aes.encrypt(new_data)  # new_Data here is pw

        sql = f"UPDATE Passwords SET {field} ='{new_data}' WHERE url='{url}' AND user_id='{self.current_user.id}'"

        self.cursor.execute(sql)
        self.connection.commit()
        print(f"{field} edited.")

    def get_db(self):
        sql = f"SELECT username, password, url FROM Passwords where user_id='{self.current_user.id}'"
        self.cursor.execute(sql)


    def print_db(self):
        self.get_db()

        creds=[]
        for (username, password, url) in self.cursor:
            creds.append((username,password,url))

        if len(creds)>0:# the user previously inserted passwords
            aes = AESCipher(self.key)
            print(" Username\tPassword\tUrl")
            for row in creds:
                password = aes.decrypt(row[1])
                entry = f"| {row[0]} | {password} | {row[2]} |"
                print(" " + "-" * (len(entry) - 2))
                print(entry)
                print(" " + "-" * (len(entry) - 2))

    def export_passwords(self):
        f = open("passwords.csv", "w")
        f.write('name,url,username,password\n')
        self.get_db()
        aes = AESCipher(self.key)
        for (username, password, url) in self.cursor:
            decrypted_password = aes.decrypt(password)
            f.write(f"{url},{username},{decrypted_password}\n")
        f.close()
        print("Passwords exported to passwords.csv in current directory.")

    def import_passwords(self,filepath):
        f = open(filepath, 'r')
        credentials = f.read()

        for line in credentials.splitlines()[1:]:  # we don't need the first line of a csv file it's always url , username , password
            url, username, password = line.split(',')
            self.insert_row(username, password, url)

        f.close()
        print("Passwords successfully imported.")
        self.print_db()


class AESCipher:

    def pad(self, raw):
        padded = raw + (self.BS - len(raw) % self.BS) * chr(self.BS - len(raw) % self.BS)

        return padded

    def __init__(self, key):
        self.BS = 16
        self.key = bytes(key, 'utf-8')


    def encrypt(self, raw):
        raw = self.pad(raw)  # pad
        iv = Random.new().read(AES.block_size)

        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw)).decode("utf-8")

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(enc[16:])
        decrypted = decrypted[:-ord(decrypted[len(decrypted) - 1:])]  # unpad
        return decrypted.decode("utf-8")




def main_menu():
    print("Welcome to Password Manager.")
    try:
        choice = int(input("1. Login \n2. Create New User\n>> "))
    except:
        choice = -1
    return choice


def user_interaction(password_manager):
    current_user = password_manager.current_user
    if not current_user:
        print("Error retrieving user information")
        return -1
    print(f"You're logged in as {current_user.username}")
    password_manager.print_db()
    try:
        choice = int(input("1. Insert\n2. Update\n3. Delete\n4. Export\n5. Import\n>>> "))
    except:
        choice = -1
    return choice


if __name__ == "__main__":

    password_manager = PasswordManager()
    operations = {1: "insert",
                  2: "update",
                  3: "delete",
                  4: "export",
                  5: "import"
                  }
    while True:
        # MAIN MENU
        choice = main_menu()
        if choice == 1:
            password_manager.sign_in()

        elif choice == 2:
            password_manager.register()
        else:
            print("Invalid choice")
            continue

        #USER MENU
        if password_manager.current_user:

            while True:
                choice = user_interaction(password_manager)
                if choice == -1: break
                if choice in operations:
                    password_manager.handle_input( operations[choice])

                else:
                    continue

