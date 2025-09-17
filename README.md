
<div align="center">
  <h1>  Mail server </h1>
</div>

Сервер поддерживает SMTP и imap протоколы.

Репозиторий содержит как среверную часть,так и клиентскую.

Build:
```
make
bash makeDB.sh
sudo ./mail_server
python web_client.py
```

Перед запуском настройке DNS, MX записи и обратный relay.

Почтовые ящики содаются через web клиента.

<img src="https://github.com/oditynet/ODQmail/blob/main/result1.png" title="example" width="800" />
<img src="https://github.com/oditynet/ODQmail/blob/main/result2.png" title="example" width="800" />
