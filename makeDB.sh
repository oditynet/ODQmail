rm -f mail_server.db
sqlite3 mail_server.db "VACUUM;"
chmod 644 mail_server.db
