# improved-enigma

Чат состоит из сервера и клиентов. Чат работает таким образом, что клиент отправляет зашифрованное пользовательское сообщение на сервер. Сервер, в свою очередь, получив пользовательское сообщение, отправляет его всем подключенным клиентам.

Для поднятия сервера нужно запустить скрипт server.py. В консоле выведется локальный IP-адрес. Этот адрес нужно скопировать в глобальную переменную SERVER_IP в скрипте клиента client.py. Также файл accounts.db должен находится в одной папке с server.py, чтобы сервер мог использовать уже сохраненные аккаунты. 

Пользователю для работы с чатом нужно ввести имя пользователя и пароль для авторизации. Чтобы отправить сообщение в чат можно нажимать Enter или кнопку Send. Для клиента был разработан графический интерфейс. Сервер настраивается в консольном режиме.

Для настройки сервера используются такие комманды:
- start. Запустить сервер снова, если ранее он был приостановлен коммандой stop
- stop. Приостановить работу сервера
- database [имя_базы данных.db]. Создать новую базу данных для регистрации новых пользователей или выбрать уже существующую
- exit. Завершить работу сервера
- help. Вывести справочную информацию

Графический интерфейс клиента состоит из окон регистрации и самого чата. В окне регистрации нужно указать имя пользователя и пароль, также там находятся кнопки входа и регистрации нового пользователя. Окно чата состоит из текстового поля, поля ввода текста и кнопки Send.

Данные, передаваемые от сервера к клиенту и наоборот разделены на разные типы сообщений в зависимости от которых будут выполняться соответствующие действия.

Типы сообщений от клиента к серверу:
1. Запрос на авторизацию пользователя (LOGIN_ATTEMPTING)
2. Запрос на регистрацию пользователя (REGISTER_CLIENT_)
3. Отправка пользователем сообщения на сервер (CLIENT_TO_SERVER)

Типы сообщений от сервера к клиенту:
1. Неправильное имя пользователя (INVALID_USERNAME)
2. Неправильный пароль (INVALID_PASSWORD)
3. Данный пользователь уже зарегестрирован (USER_IN_DATABASE)
4. Сообщение об успешной авторизации (ACCOUNT_VERIFIED)
5. Сообщение об подключении нового клиента (CLIENT_CONNECTED)
6. Отправка пользовательского сообщения от другого клиента (SERVER_TO_CLIENT)

Структура сообщений имеет такой вид:
[хэш_сумма][текст_сообщения]

Для различения одного сообщения от другого используется хэш-сумма md5. Текст сообщения представляет собой строку, зашифрованную методом шифрования Fernet из модуля cryptography. В зависимости от типа сообщения текст_сообщения может отсутсвовать, что означает выполнить соответствующие действия в зависимости от хеш суммы.

Когда клиент отправляет логин и пароль на сервер, то он предварительно шифрует сообщение с ключом LOGIN_KEY, который также находится на сервере, чтобы сервер мог расшифровать логин и пароль и проверить их соответствие в базе данных. Если клиент отправляет обычное пользовательское сообщение, то оно шифруется с ключом MESSAGE_KEY, которого нет на сервере. Таким образом, при получениии пользовательских сообщений сервер не сможет их прочитать, а только отправить их всем подключенным клиентам.

Данные о зарегестрированных пользователях хранятся в базе данных в виде таблицы users, которая имеет такую структуру:
id, username, password

Файл accounts.db представляет собой базу данных sqlite3, в которой содержатся данные о двух аккаунтах:
- user1 (имя пользователя) user1 (пароль)
- user2 (имя пользователя) user2 (пароль)


