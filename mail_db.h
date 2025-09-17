#ifndef MAIL_DB_H
#define MAIL_DB_H

#include <stdbool.h>
#include <sqlite3.h>
#include <stddef.h>

// Структура для представления email
typedef struct {
    char uuid[37];
    char from_email[256];
    char to_email[256];
    char subject[256];
    char date[64];
    int size;
    char* body;
} Email;

// Основные функции
bool db_init_database();
void db_close_database();
bool db_authenticate_user(const char* username, const char* password);
bool db_user_exists(const char* username);
bool db_register_user(const char* email, const char* password, const char* name, const char* phone);
bool db_store_email(const char* from, const char* to, const char* subject, 
                   const char* body, int body_size, const char* folder);

// Функции для работы с письмами
int db_get_email_count(const char* username, const char* folder);
int db_get_unseen_count(const char* username, const char* folder);
Email* db_get_email(const char* username, const char* folder, int msg_num);
int* db_search_emails(const char* username, const char* folder, const char* criteria);

// Вспомогательные функции
void hash_password(const char* password, const char* salt, char* output);
void generate_salt(char* salt, size_t length);

#endif