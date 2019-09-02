import tkinter
import socket
import threading
import hashlib
import datetime
import time

from cryptography.fernet import Fernet

SERVER_IP = '192.168.56.1'


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


class Client(tkinter.Tk):
    __LOGIN_SCREEN_WIDTH, __LOGIN_SCREEN_HEIGHT = 310, 205
    __CHAT_SCREEN_WIDTH, __CHAT_SCREEN_HEIGHT = 415, 560

    _requests = Enum(['INVALID_USERNAME', 'INVALID_PASSWORD', 'LOGIN_ATTEMPTING', 'USER_IN_DATABASE',
                      'ACCOUNT_VERIFIED', 'CLIENT_CONNECTED', 'REGISTER_CLIENT_'])
    _messages = Enum(['SERVER_TO_CLIENT', 'CLIENT_TO_SERVER'])

    _LOGIN_KEY = b'O3pyhCca3n8x9AR96H4fp2lxgNjpnapBsrThGknNfZY='
    _MESSAGE_KEY = b'QiWhNBPyTxfWdWZ1CjgsejaUaDn55ZmI-_0MX9GyG6U='

    _SERVER_ADDRESS = (SERVER_IP, 9090)

    class LoginWindow(tkinter.Frame):
        def __init__(self, parent, controller):
            tkinter.Frame.__init__(self, parent)
            self.__controller = controller

            self.__username = tkinter.StringVar()
            self.__password = tkinter.StringVar()

            tkinter.Label(self, text='Username:', font=self.__controller.label_font, bd=15,
                          fg=self.__controller.gray_font_color).grid(row=0, sticky='e')
            tkinter.Label(self, text='Password:', font=self.__controller.label_font, bd=15,
                          fg=self.__controller.gray_font_color).grid(row=1, sticky='e')

            self.login_entry = tkinter.Entry(self, textvariable=self.__username, font=self.__controller.entry_font)
            self.login_entry.grid(row=0, column=1)
            self.password_entry = tkinter.Entry(self, textvariable=self.__password, show='*',
                                                font=self.__controller.entry_font)
            self.password_entry.grid(row=1, column=1)

            self.login_button = tkinter.Button(self, text='Login', width=40, relief='groove', highlightthickness=0,
                                               bg=self.__controller.gray_button_color,
                                               command=lambda: self._button_action('Login'))
            self.login_button.grid(pady=8, row=2, columnspan=2)
            self.sign_up_button = tkinter.Button(self, text='Sign Up', width=40, relief='groove', highlightthickness=0,
                                                 bg=self.__controller.gray_button_color,
                                                 command=lambda: self._button_action('Sign Up'))
            self.sign_up_button.grid(pady=8, row=3, columnspan=2)

            self.message_label = tkinter.Label(self, text='', fg='red')
            self.message_label.grid(pady=0, row=4, columnspan=2)

        def _button_action(self, button_type):
            username, password = self.login_entry.get(), self.password_entry.get()
            if not len(username) and not len(password):
                self.message_label.configure(text='Enter username and password')
            elif not len(username):
                self.message_label.configure(text='Enter username')
            elif not len(password):
                self.message_label.configure(text='Enter password')
            else:
                message = username + '::' + password
                if button_type == 'Login':
                    self.__controller.send_message(Client._requests.LOGIN_ATTEMPTING,
                                                   Client._SERVER_ADDRESS, message=message)
                elif button_type == 'Sign Up':
                    self.__controller.send_message(Client._requests.REGISTER_CLIENT_,
                                                   Client._SERVER_ADDRESS, message=message)

    class ChatWindow(tkinter.Frame):
        def __init__(self, parent, controller):
            tkinter.Frame.__init__(self, parent)
            self.__controller = controller

            self.configure(bg=self.__controller.chat_window_color)
            self.__message = tkinter.StringVar()

            self.text = tkinter.Text(self, height=30, width=50, font=self.__controller.chat_font,
                                     bg=self.__controller.chat_background_color, fg=self.__controller.chat_text_color)
            self.text.grid(padx=5, pady=5, row=0, column=0, columnspan=2)

            scrollbar = tkinter.Scrollbar(self)
            scrollbar.grid(row=0, column=0, columnspan=2, sticky='nes')
            scrollbar.config(command=self.text.yview)

            self.text.config(yscrollcommand=scrollbar.set)
            self.text.configure(state='disabled')

            self.message_entry = tkinter.Entry(self, width=41, textvariable=self.__message,
                                               font=self.__controller.chat_font,
                                               bg=self.__controller.chat_background_color,
                                               fg=self.__controller.chat_text_color)
            self.message_entry.grid(pady=5, row=1, column=0)

            self.send_button = tkinter.Button(self, text='Send', width=7, relief='groove', highlightthickness=0,
                                              bg=self.__controller.chat_button_color, command=self._send_button_action)
            self.send_button.grid(pady=5, row=1, column=1)

        def _send_button_action(self):
            message = self.message_entry.get()
            if len(message):
                self.__controller.send_message(Client._messages.CLIENT_TO_SERVER,
                                               Client._SERVER_ADDRESS, message=message)
            self.message_entry.delete(0, tkinter.END)

    def __init__(self):
        super(Client, self).__init__()

        self.title('Chat')
        self.resizable(0, 0)

        self.__screen_width = self.winfo_screenwidth()
        self.__screen_height = self.winfo_screenheight()

        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.__socket.bind((Client._SERVER_ADDRESS[0], 0))
        self.__socket.setblocking(False)

        self.__receiving_thread = threading.Thread(target=self._receive_messages, args=[], daemon=True)
        self.__receiving_thread.start()

        self.__crypto_login = Fernet(Client._LOGIN_KEY)
        self.__crypto_message = Fernet(Client._MESSAGE_KEY)

        self.__current_frame, self.__username = '', ''

        self.gray_button_color = "#%02x%02x%02x" % (210, 210, 210)
        self.gray_font_color = "#%02x%02x%02x" % (60, 60, 60)
        self.chat_window_color = "#%02x%02x%02x" % (235, 235, 235)
        self.chat_background_color = "#%02x%02x%02x" % (240, 240, 240)
        self.chat_text_color = "#%02x%02x%02x" % (70, 70, 70)
        self.chat_button_color = "#%02x%02x%02x" % (170, 193, 250)

        self.label_font = ('arial', 10, 'bold')
        self.entry_font = ('arial', 10)
        self.chat_font = ('arial', 11)

        container = tkinter.Frame(self)
        container.pack(side='top', fill='both', expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.frames = dict()

        self.frames['LoginWindow'] = Client.LoginWindow(parent=container, controller=self)
        self.frames['ChatWindow'] = Client.ChatWindow(parent=container, controller=self)

        self.protocol('WM_DELETE_WINDOW', self._on_close)
        self.bind('<Return>', self._enter_key_event)

        self.show_frame('LoginWindow')

    def _enter_key_event(self, event):
        if self.__current_frame == 'LoginWindow':
            self.frames[self.__current_frame].login_button.invoke()
        elif self.__current_frame == 'ChatWindow':
            self.frames[self.__current_frame].send_button.invoke()

    def show_frame(self, name):
        if name == 'LoginWindow':
            self.frames['ChatWindow'].grid_forget()
            self.frames['LoginWindow'].grid(row=0, column=0, padx=10, sticky='nsew')

            x = self.__screen_width / 2 - Client.__LOGIN_SCREEN_WIDTH / 2
            y = self.__screen_height / 2 - Client.__LOGIN_SCREEN_HEIGHT / 2

            self.geometry('%dx%d+%d+%d' % (Client.__LOGIN_SCREEN_WIDTH, Client.__LOGIN_SCREEN_HEIGHT, x, y))
            self.__current_frame = name
        elif name == 'ChatWindow':
            self.frames['LoginWindow'].grid_forget()
            self.frames['ChatWindow'].grid(row=0, column=0, sticky='nsew')

            x = self.winfo_screenwidth() / 2 - Client.__CHAT_SCREEN_WIDTH / 2
            y = self.winfo_screenheight() / 2 - Client.__CHAT_SCREEN_HEIGHT / 2

            self.geometry('%dx%d+%d+%d' % (Client.__CHAT_SCREEN_WIDTH, Client.__CHAT_SCREEN_HEIGHT, x, y))
            self.__current_frame = name

    def send_message(self, message_type, address, message):
        hash_sum = hashlib.md5(message_type.encode('utf-8')).hexdigest().encode('utf-8')

        if message_type == Client._requests.LOGIN_ATTEMPTING or \
                message_type == Client._requests.REGISTER_CLIENT_:
            message = hash_sum + self.__crypto_login.encrypt(message.encode('utf-8'))
        elif message_type == Client._messages.CLIENT_TO_SERVER:
            message = hash_sum + self.__crypto_message.encrypt(message.encode('utf-8'))

        self.__socket.sendto(message, address)

    def _receive_messages(self):
        while True:
            try:
                data = self.__socket.recvfrom(1024)[0]
            except BlockingIOError:
                pass
            else:
                hash_sum, message = data[:32], data[32:]

                if hash_sum == Enum.hash(Client._requests.INVALID_USERNAME):
                    self.frames['LoginWindow'].message_label.configure(text='Invalid username')
                elif hash_sum == Enum.hash(Client._requests.INVALID_PASSWORD):
                    self.frames['LoginWindow'].message_label.configure(text='Invalid password')
                elif hash_sum == Enum.hash(Client._requests.USER_IN_DATABASE):
                    self.frames['LoginWindow'].message_label.configure(text='User already exists')
                elif hash_sum == Enum.hash(Client._requests.ACCOUNT_VERIFIED):
                    self.show_frame('ChatWindow')
                    self.__username = self.frames['LoginWindow'].login_entry.get()
                elif hash_sum == Enum.hash(Client._requests.CLIENT_CONNECTED):
                    self.frames['ChatWindow'].text.configure(state='normal')
                    self.frames['ChatWindow'].text.insert(tkinter.END, self.__username + ' --> joined\n')
                    self.frames['ChatWindow'].text.configure(state='disabled')
                elif hash_sum == Enum.hash(Client._messages.SERVER_TO_CLIENT):
                    self.frames['ChatWindow'].text.configure(state='normal')
                    self.frames['ChatWindow'].text.insert(tkinter.END,
                                                          str(datetime.datetime.now().time())[:5] + ' ' +
                                                          self.__username + ' :: ' +
                                                          self.__crypto_message.decrypt(message).decode('utf-8') + '\n')
                    self.frames['ChatWindow'].text.configure(state='disabled')

            time.sleep(0.2)

    def _on_close(self):
        self.__socket.close()
        self.destroy()


if __name__ == '__main__':
    client = Client()
    client.mainloop()
