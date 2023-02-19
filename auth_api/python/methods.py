import mysql.connector
import jwt
import os


class Token:
    def __init__(self):
        # initiating the db connection by using env variables.
        self.connection = mysql.connector.connect(
            user=os.environ['DB_USER'],
            password=os.environ['DB_PASSWORD'],
            host=os.environ['DB_HOST'],
            port=os.environ['DB_PORT'],
            database=os.environ['DB_DATABASE']
        )

    def generate_jwt(self, db_role):
        payload = {"role": db_role}
        key = os.environ['JWT_KEY']
        algorithm = "HS256"
        token = jwt.encode(payload, key, algorithm=algorithm)
        return token

    def generate_token(self, username, password):
        # verifying the user and the plain password exist in the database.
        # using the sha2 function to derive the encrypted password in the DB side
        query = "SELECT * FROM users WHERE username = %s AND password = SHA2(CONCAT(%s, salt), 512)"
        values = (username, password)

        try:
            with self.connection.cursor() as cursor:
                cursor.execute(query, values)
                record = cursor.fetchone()
                # verifying i got at least one record to generate the jwt token response
                if record:
                    db_role = record[3]
                    jwt_token = self.generate_jwt(db_role)
                    return jwt_token
                # returning a 403 error message if password and username dont exist in the DB
                return 403
        except Exception:
            # raising an exception in case there is a an error in the server
            return 500


class Restricted:
    def __init__(self):
        # initiating the db connection by using env variables
        self.key = os.environ['JWT_KEY']

    def access_data(self, authorization):
        try:
            # decoding the JWT token and verify that it's valid
            decoded_token = jwt.decode(authorization, self.key, algorithms=['HS256'])

            # returning protected data if the user is an admin
            if decoded_token['role'] == 'admin':
                return 'You are under protected data'
            return None
        except jwt.InvalidTokenError:
            return None
