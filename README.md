
<div align="center">
  <h1>  Mail server </h1>
</div>

Сервер поддерживает SMTP и imap протоколы. IMAPS в разработке

Репозиторий содержит как среверную часть,так и клиентскую.

Build:
```
make
bash makeDB.sh

openssl req -x509 -newkey rsa:4096 -keyout ssl_certs/mail_server.key -out ssl_certs/mail_server.pem -days 365 -nodes -subj "/CN=oditynet.ru"

sudo ./mail_server
python web_client.py
```

Перед запуском настройке DNS, MX записи и обратный relay.

Почтовые ящики содаются через web клиента.

<img src="https://github.com/oditynet/ODQmail/blob/main/result1.png" title="example" width="800" />
<img src="https://github.com/oditynet/ODQmail/blob/main/result2.png" title="example" width="800" />
