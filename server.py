import os
import sys
import socket
import threading
import ipaddress
import sqlite3
import hashlib

from cryptography.fernet import Fernet


class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class Enum(set):
    __hash_sums = dict()

    def __getattr__(self, name):
        if name in self:
            return name
        raise AttributeError

    @staticmethod
    def hash(name):
        if name not in Enum.__hash_sums:
            Enum.__hash_sums[name] = hashlib.md5(name.encode('utf-8')).hexdigest().encode('utf-8')
        return Enum.__hash_sums[name]


class Server(threading.Thread, metaclass=Singleton):
    __requests = Enum(['INVALID_USERNAME', 'INVALID_PASSWORD', 'LOGIN_ATTEMPTING', 'USER_IN_DATABASE',
                       'ACCOUNT_VERIFIED', 'CLIENT_CONNECTED', 'REGISTER_CLIENT_'])
    __messages = Enum(['SERVER_TO_CLIENT', 'CLIENT_TO_SERVER'])

    __LOGIN_KEY = b'O3pyhCca3n8x9AR96H4fp2lxgNjpnapBsrThGknNfZY='

    def __init__(self):
        super(Server, self).__init__()

        self.__stop_event, self.__wait_event = threading.Event(), threading.Event()
        self.__wait_condition = threading.Condition(threading.Lock())
        self.__wait_event.set()

        self.__host = socket.gethostbyname(socket.gethostname())
        self.__port = 9090

        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.__socket.bind((self.__host, self.__port))

        self.__crypto_login = Fernet(Server.__LOGIN_KEY)

        self.__database_name = 'accounts.db'

        self.__addresses = []

    def run(self):
        super(Server, self).run()

        self._initialize_database()

        while not self.__stop_event.is_set():
            with self.__wait_condition:
                while not self.__wait_event.is_set():
                    self.__wait_condition.wait()

                user_data, user_address = self.__socket.recvfrom(1024)

                hash_sum, message = user_data[:32], user_data[32:]

                if hash_sum == Enum.hash(Server.__requests.LOGIN_ATTEMPTING):
                    username, password = self.__crypto_login.decrypt(message).decode('utf-8').split('::')

                    if self._is_valid_username(username):
                        if self._is_valid_password(username, password):
                            self._send_message(Server.__requests.ACCOUNT_VERIFIED, user_address)
                            self._send_message(Server.__requests.CLIENT_CONNECTED, *self.__addresses)
                        else:
                            self._send_message(Server.__requests.INVALID_PASSWORD, user_address)
                    else:
                        self._send_message(Server.__requests.INVALID_USERNAME, user_address)
                elif hash_sum == Enum.hash(Server.__requests.REGISTER_CLIENT_):
                    username, password = self.__crypto_login.decrypt(message).decode('utf-8').split('::')
                    if self._is_valid_username(username):
                        self._send_message(Server.__requests.USER_IN_DATABASE, user_address)
                    else:
                        self._register_user(username, password)
                        self._send_message(Server.__requests.ACCOUNT_VERIFIED, user_address)
                elif hash_sum == Enum.hash(Server.__messages.CLIENT_TO_SERVER):
                    if user_address not in self.__addresses:
                        self.__addresses.append(user_address)
                    self._send_message(Server.__messages.SERVER_TO_CLIENT, *self.__addresses, message=message)

    def _send_message(self, message_type, *addresses, message=b''):
        if message_type in Server.__requests:
            for address in addresses:
                self.__socket.sendto(hashlib.md5(message_type.encode('utf-8')).hexdigest().encode('utf-8'), address)

        if message_type == Server.__messages.SERVER_TO_CLIENT:
            for address in addresses:
                self.__socket.sendto(hashlib.md5(message_type.encode('utf-8')).hexdigest().encode('utf-8')
                                     + message, address)

    def resume(self):
        if not self.__wait_event.is_set():
            self.__wait_event.set()
            self.__wait_condition.notify()
            self.__wait_condition.release()

    def pause(self):
        if self.__wait_event.is_set():
            self.__wait_event.clear()
            self.__wait_condition.acquire()

    def stop(self):
        self.__stop_event.set()
        self.__socket.close()

    @property
    def host(self):
        return self.__host

    @host.setter
    def host(self, host):
        try:
            ipaddress.ip_address(host)
        except ValueError:
            print('Invalid host')
        else:
            self.__host = host

    @property
    def port(self):
        return self.__port

    @port.setter
    def port(self, port):
        if not 1 <= port <= 65535:
            print('Invalid port number')
        else:
            self.__port = port

    @property
    def database_name(self):
        return self.__database_name

    @database_name.setter
    def database_name(self, database_name):
        if database_name.endswith('.db'):
            self.__database_name = database_name

    def _initialize_database(self):
        connection = sqlite3.connect(self.__database_name)
        connection.cursor().execute("CREATE TABLE IF NOT EXISTS `users` " +
                                    "(mem_id INTEGER NOT NULL PRIMARY KEY  AUTOINCREMENT, username TEXT, password TEXT)")
        connection.commit()
        connection.close()

    def _is_valid_username(self, username):
        connection = sqlite3.connect(self.__database_name)
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM `users` WHERE `username` = '{username}'".format(username=username))
        result = cursor.fetchone()
        connection.close()
        return result

    def _is_valid_password(self, username, password):
        connection = sqlite3.connect(self.__database_name)
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM `users` WHERE `username` = '{username}' AND `password` = '{password}'".format(
            username=username, password=password))
        result = cursor.fetchone()
        connection.close()
        return result

    def _register_user(self, username, password):
        connection = sqlite3.connect(self.__database_name)
        cursor = connection.cursor()
        cursor.execute("INSERT INTO `users` (username, password) VALUES('{username}', '{password}')".format(
            username=username, password=password))
        connection.commit()
        connection.close()


def start_cmd():
    if Server().is_alive():
        Server().resume()
        print('Starting server')
    else:
        server = Server()
        server.start()
        print('''Starting server..
    Host: {host}
    Port: {port}'''.format(host=server.host, port=server.port))


def stop_cmd():
    if Server().isAlive():
        Server().pause()
        print('Server stopped..')
    else:
        print('Server is not running yet..')


def set_database_cmd():
    if len(sys.argv) != 3 or not sys.argv[2].endswith('.db'):
        help_cmd()
    else:
        server = Server()
        server.database_name = sys.argv[2]


def exit_cmd():
    Server().stop()
    Server().join()
    sys.exit(0)


def help_cmd():
    print('''Usage: {name} [command]\n
Commands: 
\t {name} : <run server>
\t {name} start : <start server> 
\t {name} stop : <stop server>
\t {name} database [database_name.db] : <select database>
\t {name} exit : <shutdown server>
\t {name} help : <get this information>'''
          .format(name=os.path.basename(sys.argv[0])))


if __name__ == '__main__':
    COMMANDS = dict({'start': start_cmd, 'stop': stop_cmd, 'database': set_database_cmd,
                     'exit': exit_cmd, 'help': help_cmd})

    start_cmd()

    while True:
        try:
            COMMANDS[input()]()
        except KeyError:
            help_cmd()
