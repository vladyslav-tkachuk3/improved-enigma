# improved-enigma

Чат состоит из сервера и множества клиентов. Чат работает таким образом, что клиент отправляет зашифрованное пользовательское сообщение на сервер. Сервер в свою очередь, получив пользовательское сообщение, отправляет его всем подключенным клиентам.

Для различения одного сообщения от другого используется хэш-сумма md5.

Для клиента был разработан графический интерфейс. Сервер настраивается в консольном режиме. Для настройки сервера используются такие комманды:
- start. Запустить сервер снова, если ранее он был приостановлен коммандой stop.
- stop. Приостановить работу сервера.
- database [имя_базы данных.db]. Создать новую базу данных для регистрации новых пользователей или выбрать уже существующую.

Типы сообщений от клиента к серверу:
1. Запрос на авторизацию пользователя (LOGIN_ATTEMPTING)
2. Запрос на регистрацию пользователя (REGISTER_CLIENT_)
3. Отправка пользователем сообщения на сервер (CLIENT_TO_SERVER)

Типы сообщений от сервера к клиенту:
1. Неправильное имя пользователя (INVALID_USERNAME)
2. Неправильный пароль (INVALID_PASSWORD)
3. Данный пользователь уже зарегестрирован (USER_IN_DATABASE)
4. Сообщение об успешной авторизации
5. Сообщение об подключении нового клиента

Структура сообщений имеет такой вид:
[хэш_сумма][текст_сообщения]


Данные о зарегестрированных пользователях хранятся в базе данных в виде таблицы users, которая имеет такую структуру:
id, username, password



Файл accounts.db представляет собой базу данных sqlite3, в которой содержатся данные о двух аккаунтах:


