#include "mail_db.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <unistd.h>

static sqlite3 *db = NULL;
static pthread_mutex_t db_mutex = PTHREAD_MUTEX_INITIALIZER;

// Функция для хеширования пароля с солью
void hash_password(const char* password, const char* salt, char* output) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    char combined[256];
    
    // Убедимся, что combined строка правильно формируется
    int combined_len = snprintf(combined, sizeof(combined), "%s%s", salt, password);
    if (combined_len >= sizeof(combined)) {
        printf("ERROR: Combined string too long!\n");
        return;
    }
    
    printf("Hashing: salt='%s', password='%s', combined='%s'\n", salt, password, combined);
    
    // Вычисляем SHA256
    SHA256((unsigned char*)combined, strlen(combined), hash);
    
    // Преобразуем в hex
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[SHA256_DIGEST_LENGTH * 2] = '\0';
    
    printf("Hash result: %s\n", output);
}
// Функция для генерации соли
void generate_salt(char* salt, size_t length) {
    const char chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (size_t i = 0; i < length - 1; i++) {
        salt[i] = chars[rand() % (sizeof(chars) - 1)];
    }
    salt[length - 1] = '\0';
}

// Функция для инициализации базы данных
bool db_init_database() {
    printf("Initializing SQLite database...\n");
    
    int rc = sqlite3_open("mail_server.db", &db);
    if (rc != SQLITE_OK) {
        printf("Cannot open database: %s\n", sqlite3_errmsg(db));
        return false;
    }
    
    // Включаем foreign keys
    sqlite3_exec(db, "PRAGMA foreign_keys = ON;", NULL, NULL, NULL);
    
    // Создаем таблицы (такая же структура как в Python)
    const char* create_tables_sql = 
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "email TEXT UNIQUE NOT NULL,"
        "password_hash TEXT NOT NULL,"
        "salt TEXT NOT NULL,"
        "name TEXT NOT NULL,"
        "phone TEXT,"
        "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
        ");"
        
        "CREATE TABLE IF NOT EXISTS emails ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "uuid TEXT UNIQUE NOT NULL,"
        "from_email TEXT NOT NULL,"
        "to_email TEXT NOT NULL,"
        "subject TEXT NOT NULL,"
        "body TEXT NOT NULL,"
        "size INTEGER NOT NULL,"
        "folder TEXT NOT NULL,"
        "is_read BOOLEAN DEFAULT 0,"
        "received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
        "user_id INTEGER,"
        "FOREIGN KEY (user_id) REFERENCES users (id)"
        ");"
        
        "CREATE INDEX IF NOT EXISTS idx_emails_user_folder ON emails (user_id, folder);"
        "CREATE INDEX IF NOT EXISTS idx_emails_received ON emails (received_at);";
    
    char* err_msg = NULL;
    rc = sqlite3_exec(db, create_tables_sql, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        printf("SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        return false;
    }    
    // Создаем тестовых пользователей если их нет
    const char* check_user_sql = "SELECT id FROM users WHERE email = ?";
    const char* insert_user_sql = "INSERT INTO users (email, password_hash, salt, name, phone) VALUES (?, ?, ?, ?, ?)";
    
    struct TestUser {
        const char* email;
        const char* password;
        const char* name;
        const char* phone;
    };
    
    struct TestUser test_users[] = {
        {"admin@oditynet.ru", "admin123", "Administrator", "+1234567890"},
        {"user@oditynet.ru", "user123", "Test User", "+79876543210"},
        {NULL, NULL, NULL, NULL}
    };
    
    for (int i = 0; test_users[i].email != NULL; i++) {
        sqlite3_stmt* stmt;
        rc = sqlite3_prepare_v2(db, check_user_sql, -1, &stmt, NULL);
        if (rc != SQLITE_OK) {
            printf("Failed to prepare statement: %s\n", sqlite3_errmsg(db));
            continue;
        }
        
        sqlite3_bind_text(stmt, 1, test_users[i].email, -1, SQLITE_STATIC);
        
        if (sqlite3_step(stmt) != SQLITE_ROW) {
            // Пользователь не существует - создаем
            char salt[17];
            char password_hash[65];
            
            generate_salt(salt, sizeof(salt));
            hash_password(test_users[i].password, salt, password_hash);
            printf("Salt: %s, Hash: %s\n", salt, password_hash);
            
            sqlite3_stmt* insert_stmt;
            rc = sqlite3_prepare_v2(db, insert_user_sql, -1, &insert_stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_bind_text(insert_stmt, 1, test_users[i].email, -1, SQLITE_STATIC);
                sqlite3_bind_text(insert_stmt, 2, password_hash, -1, SQLITE_STATIC);
                sqlite3_bind_text(insert_stmt, 3, salt, -1, SQLITE_STATIC);
                sqlite3_bind_text(insert_stmt, 4, test_users[i].name, -1, SQLITE_STATIC);
                sqlite3_bind_text(insert_stmt, 5, test_users[i].phone, -1, SQLITE_STATIC);
                
                if (sqlite3_step(insert_stmt) == SQLITE_DONE) {
                    printf("Created user: %s\n", test_users[i].email);
                }
                sqlite3_finalize(insert_stmt);
            }
        }
        sqlite3_finalize(stmt);
    }
    const char* external_user_sql = "INSERT OR IGNORE INTO users (email, password_hash, salt, name, phone) VALUES ('external@oditynet.ru', 'external', 'salt', 'External User', '')";
    sqlite3_exec(db, external_user_sql, NULL, NULL, NULL);
    
    printf("Database initialized successfully\n");
    return true;
}

// Функция для закрытия базы данных
void db_close_database() {
    if (db != NULL) {
        sqlite3_close(db);
        db = NULL;
        printf("Database connection closed\n");
    }
}

// Функция для аутентификации пользователя
bool db_authenticate_user(const char* username, const char* password) {
    pthread_mutex_lock(&db_mutex);
    
    printf("=== AUTH DEBUG START ===\n");
    printf("Username: '%s'\n", username);
    printf("Password: '%s'\n", password);
    
    if (db == NULL) {
        printf("Database is NULL!\n");
        pthread_mutex_unlock(&db_mutex);
        return false;
    }
    
    // Проверим сначала, есть ли пользователь вообще
    const char* check_sql = "SELECT COUNT(*) FROM users WHERE email = ?";
    sqlite3_stmt* check_stmt;
    
    int rc = sqlite3_prepare_v2(db, check_sql, -1, &check_stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(check_stmt, 1, username, -1, SQLITE_STATIC);
        if (sqlite3_step(check_stmt) == SQLITE_ROW) {
            int count = sqlite3_column_int(check_stmt, 0);
            printf("Users found with this email: %d\n", count);
        }
        sqlite3_finalize(check_stmt);
    }
    
    // Теперь основной запрос
    const char* sql = "SELECT password_hash, salt FROM users WHERE email = ?";
    sqlite3_stmt* stmt;
    
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        printf("Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        pthread_mutex_unlock(&db_mutex);
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    
    rc = sqlite3_step(stmt);
    printf("sqlite3_step returned: %d\n", rc);
    
    bool auth_success = false;
    if (rc == SQLITE_ROW) {
        printf("Number of columns: %d\n", sqlite3_column_count(stmt));
        
        // Проверим каждую колонку отдельно
        for (int i = 0; i < sqlite3_column_count(stmt); i++) {
            const char* col_name = sqlite3_column_name(stmt, i);
            const char* col_value = (const char*)sqlite3_column_text(stmt, i);
            printf("Column %d: %s = '%s'\n", i, col_name, col_value ? col_value : "NULL");
        }
        
        const char* stored_hash = (const char*)sqlite3_column_text(stmt, 0);
        const char* salt = (const char*)sqlite3_column_text(stmt, 1);
        
        printf("Stored hash: %s\n", stored_hash ? stored_hash : "NULL");
        printf("Stored salt: %s\n", salt ? salt : "NULL");
        
        if (stored_hash && salt) {
            char input_hash[65];
            hash_password(password, salt, input_hash);
            
            printf("Input hash: %s\n", input_hash);
            
            if (strcmp(input_hash, stored_hash) == 0) {
                printf("Hashes match!\n");
                auth_success = true;
            } else {
                printf("Hashes DON'T match!\n");
            }
        } else {
            printf("Cannot authenticate - NULL hash or salt\n");
        }
    } else {
        printf("No user found with email: %s\n", username);
    }
    
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&db_mutex);
    
    printf("Auth result: %s\n", auth_success ? "SUCCESS" : "FAILED");
    printf("=== AUTH DEBUG END ===\n");
    
    return auth_success;
}

// Функция для проверки существования пользователя
bool db_user_exists(const char* username) {
    pthread_mutex_lock(&db_mutex);
    if (db == NULL) {
        pthread_mutex_unlock(&db_mutex);
        return false;
    }
    
    const char* sql = "SELECT id FROM users WHERE email = ?";
    sqlite3_stmt* stmt;
    
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        printf("Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        pthread_mutex_unlock(&db_mutex);
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    
    bool exists = (sqlite3_step(stmt) == SQLITE_ROW);
    
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&db_mutex);
    return exists;
}

// Функция для регистрации нового пользователя
bool db_register_user(const char* email, const char* password, const char* name, const char* phone) {
    //pthread_mutex_lock(&db_mutex);
    if (db == NULL) {
        pthread_mutex_unlock(&db_mutex);
        return false;
    }
    if (db_user_exists(email)) {
        pthread_mutex_unlock(&db_mutex);
        return false;
    }
    // Генерируем соль и хешируем пароль
    char salt[17];
    char password_hash[65];
    
    generate_salt(salt, sizeof(salt));
    hash_password(password, salt, password_hash);
    
    const char* sql = "INSERT INTO users (email, password_hash, salt, name, phone) VALUES (?, ?, ?, ?, ?)";
    sqlite3_stmt* stmt;
    
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        printf("Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        pthread_mutex_unlock(&db_mutex);
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, email, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, password_hash, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, salt, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, phone, -1, SQLITE_STATIC);
    
    bool success = (sqlite3_step(stmt) == SQLITE_DONE);
    
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&db_mutex);
    
    return success;
}
// Функция для извлечения темы из заголовков письма
/*const char* extract_subject(const char* email_data) {
    const char* subject_start = strstr(email_data, "Subject:");
    if (!subject_start) return "No Subject";
    
    subject_start += 8; // Пропускаем "Subject:"
    while (*subject_start == ' ' || *subject_start == '\t' || *subject_start == '\r' || *subject_start == '\n') {
        subject_start++;
    }
    
    const char* subject_end = strstr(subject_start, "\r\n");
    if (!subject_end) subject_end = subject_start + strlen(subject_start);
    
    // Выделяем память для темы
    static char subject[256];
    int len = subject_end - subject_start;
    if (len > sizeof(subject) - 1) len = sizeof(subject) - 1;
    
    strncpy(subject, subject_start, len);
    subject[len] = '\0';
    
    // Убираем возможные префиксы кодирования
    char* encoded_prefix = strstr(subject, "=?UTF-8?B?");
    if (encoded_prefix) {
        // Пропускаем обработку base64 для простоты
        return "Encoded Subject";
    }
    
    return subject;
}*/
const char* extract_subject(const char* email_data) {
    const char* subject_start = strstr(email_data, "Subject:");
    if (!subject_start) {
        printf("No Subject header found\n");
        return "No Subject";
    }
    
    subject_start += 8; // Пропускаем "Subject:"
    
    // Пропускаем пробелы и табы
    while (*subject_start == ' ' || *subject_start == '\t' || *subject_start == '\r' || *subject_start == '\n') {
        subject_start++;
    }
    
    // Ищем конец строки
    const char* subject_end = strstr(subject_start, "\r\n");
    if (!subject_end) {
        subject_end = subject_start + strlen(subject_start);
    }
    
    // Выделяем память для темы
    static char subject[256];
    int len = subject_end - subject_start;
    if (len > (int)sizeof(subject) - 1) {
        len = sizeof(subject) - 1;
    }
    
    strncpy(subject, subject_start, len);
    subject[len] = '\0';
    
    printf("Extracted subject: '%s'\n", subject);
    return subject;
}

bool db_store_email(const char* from, const char* to, const char* subject, 
                   const char* body, int body_size, const char* folder) {
    
    pthread_mutex_lock(&db_mutex);
    printf("=== DB STORE EMAIL DEBUG ===\n");
    printf("From: %s\n", from);
    printf("To: %s\n", to);
    printf("Original subject: %s\n", subject);
    printf("Folder: %s\n", folder);
    printf("Body size: %d\n", body_size);
    
    if (db == NULL) {
        printf("Database not initialized\n");
        pthread_mutex_unlock(&db_mutex);
        return false;
    }
    
    // Извлекаем реальную тему из тела письма
    const char* actual_subject = subject;
    if (strcmp(subject, "Email from SMTP") == 0) {
        actual_subject = extract_subject(body);
        printf("Extracted subject: %s\n", actual_subject);
    }
    
    // Сохраняем письмо для ОТПРАВИТЕЛЯ в папку SENT (только для локальных отправителей)
    int from_user_id = -1;
    if (strstr(from, "@oditynet.ru") != NULL) {
        const char* user_sql = "SELECT id FROM users WHERE email = ?";
        sqlite3_stmt* user_stmt;
        
        int rc = sqlite3_prepare_v2(db, user_sql, -1, &user_stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_bind_text(user_stmt, 1, from, -1, SQLITE_STATIC);
            if (sqlite3_step(user_stmt) == SQLITE_ROW) {
                from_user_id = sqlite3_column_int(user_stmt, 0);
                printf("Found from_user_id: %d for email: %s\n", from_user_id, from);
                
                // Сохраняем для отправителя в SENT
                char uuid_sent[37];
                snprintf(uuid_sent, sizeof(uuid_sent), "%ld%d_sent", time(NULL), rand());
                
                const char* sql_sent = "INSERT INTO emails (uuid, from_email, to_email, subject, body, size, folder, user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
                sqlite3_stmt* stmt_sent;
                
                rc = sqlite3_prepare_v2(db, sql_sent, -1, &stmt_sent, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_bind_text(stmt_sent, 1, uuid_sent, -1, SQLITE_STATIC);
                    sqlite3_bind_text(stmt_sent, 2, from, -1, SQLITE_STATIC);
                    sqlite3_bind_text(stmt_sent, 3, to, -1, SQLITE_STATIC);
                    sqlite3_bind_text(stmt_sent, 4, actual_subject, -1, SQLITE_STATIC);
                    sqlite3_bind_text(stmt_sent, 5, body, -1, SQLITE_STATIC);
                    sqlite3_bind_int(stmt_sent, 6, body_size);
                    sqlite3_bind_text(stmt_sent, 7, "SENT", -1, SQLITE_STATIC);
                    sqlite3_bind_int(stmt_sent, 8, from_user_id);
                    
                    if (sqlite3_step(stmt_sent) == SQLITE_DONE) {
                        printf("Email stored in SENT folder for sender: %s\n", from);
                    } else {
                        printf("Failed to store email in SENT folder: %s\n", sqlite3_errmsg(db));
                    }
                    sqlite3_finalize(stmt_sent);
                }
            }
            sqlite3_finalize(user_stmt);
        }
    }
    
    // Сохраняем письмо для ПОЛУЧАТЕЛЯ в папку INBOX (только для локальных получателей)
    int to_user_id = -1;
    if (strstr(to, "@oditynet.ru") != NULL) {
        const char* user_sql = "SELECT id FROM users WHERE email = ?";
        sqlite3_stmt* user_stmt;
        
        int rc = sqlite3_prepare_v2(db, user_sql, -1, &user_stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_bind_text(user_stmt, 1, to, -1, SQLITE_STATIC);
            if (sqlite3_step(user_stmt) == SQLITE_ROW) {
                to_user_id = sqlite3_column_int(user_stmt, 0);
                printf("Found to_user_id: %d for email: %s\n", to_user_id, to);
                
                // Сохраняем для получателя в INBOX
                char uuid_inbox[37];
                snprintf(uuid_inbox, sizeof(uuid_inbox), "%ld%d_inbox", time(NULL), rand());
                
                const char* sql_inbox = "INSERT INTO emails (uuid, from_email, to_email, subject, body, size, folder, user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
                sqlite3_stmt* stmt_inbox;
                
                rc = sqlite3_prepare_v2(db, sql_inbox, -1, &stmt_inbox, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_bind_text(stmt_inbox, 1, uuid_inbox, -1, SQLITE_STATIC);
                    sqlite3_bind_text(stmt_inbox, 2, from, -1, SQLITE_STATIC);
                    sqlite3_bind_text(stmt_inbox, 3, to, -1, SQLITE_STATIC);
                    sqlite3_bind_text(stmt_inbox, 4, actual_subject, -1, SQLITE_STATIC);
                    sqlite3_bind_text(stmt_inbox, 5, body, -1, SQLITE_STATIC);
                    sqlite3_bind_int(stmt_inbox, 6, body_size);
                    sqlite3_bind_text(stmt_inbox, 7, "INBOX", -1, SQLITE_STATIC);
                    sqlite3_bind_int(stmt_inbox, 8, to_user_id);
                    
                    if (sqlite3_step(stmt_inbox) == SQLITE_DONE) {
                        printf("Email stored in INBOX folder for recipient: %s\n", to);
                    } else {
                        printf("Failed to store email in INBOX folder: %s\n", sqlite3_errmsg(db));
                    }
                    sqlite3_finalize(stmt_inbox);
                }
            }
            sqlite3_finalize(user_stmt);
        }
    } else {
        // Для внешних получателей просто логируем, но не пытаемся сохранять
        printf("External recipient %s - no need to store in local database\n", to);
    }
    
    pthread_mutex_unlock(&db_mutex);
    
    // Возвращаем true если хотя бы одна копия сохранена (для локальных пользователей)
    return (from_user_id != -1 || to_user_id != -1);
}

// Функция для получения количества писем в папке
int db_get_email_count(const char* username, const char* folder) {
    pthread_mutex_lock(&db_mutex);
    
    if (db == NULL) {
        pthread_mutex_unlock(&db_mutex);
        return 0;
    }
    
    printf("DB_GET_EMAIL_COUNT: username=%s, folder=%s\n", username, folder);
    
    const char* sql = "SELECT COUNT(*) FROM emails e JOIN users u ON e.user_id = u.id WHERE u.email = ? AND e.folder = ?";
    sqlite3_stmt* stmt;
    
    int count = 0;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, folder, -1, SQLITE_STATIC);
        
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            count = sqlite3_column_int(stmt, 0);
            printf("Found %d emails for %s in folder %s\n", count, username, folder);
        }
        sqlite3_finalize(stmt);
    } else {
        printf("Error preparing statement: %s\n", sqlite3_errmsg(db));
    }
    
    pthread_mutex_unlock(&db_mutex);
    return count;
}

// Функция для получения количества непрочитанных писем
int db_get_unseen_count(const char* username, const char* folder) {
    pthread_mutex_lock(&db_mutex);
    
    if (db == NULL) {
        pthread_mutex_unlock(&db_mutex);
        return 0;
    }
    
    const char* sql = "SELECT COUNT(*) FROM emails e JOIN users u ON e.user_id = u.id WHERE u.email = ? AND e.folder = ? AND e.is_read = 0";
    sqlite3_stmt* stmt;
    
    int count = 0;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, folder, -1, SQLITE_STATIC);
        
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            count = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }
    
    pthread_mutex_unlock(&db_mutex);
    return count;
}

// Функция для получения письма по номеру
Email* db_get_email(const char* username, const char* folder, int msg_num) {
    pthread_mutex_lock(&db_mutex);
    
    if (db == NULL) {
        pthread_mutex_unlock(&db_mutex);
        return NULL;
    }
    
    const char* sql = "SELECT e.uuid, e.from_email, e.to_email, e.subject, e.received_at, e.size, e.body "
                     "FROM emails e JOIN users u ON e.user_id = u.id "
                     "WHERE u.email = ? AND e.folder = ? "
                     "ORDER BY e.received_at DESC LIMIT 1 OFFSET ?";
    sqlite3_stmt* stmt;
    
    Email* email = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, folder, -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 3, msg_num - 1);
        
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            email = malloc(sizeof(Email));
            strncpy(email->uuid, (const char*)sqlite3_column_text(stmt, 0), sizeof(email->uuid));
            strncpy(email->from_email, (const char*)sqlite3_column_text(stmt, 1), sizeof(email->from_email));
            strncpy(email->to_email, (const char*)sqlite3_column_text(stmt, 2), sizeof(email->to_email));
            strncpy(email->subject, (const char*)sqlite3_column_text(stmt, 3), sizeof(email->subject));
            strncpy(email->date, (const char*)sqlite3_column_text(stmt, 4), sizeof(email->date));
            email->size = sqlite3_column_int(stmt, 5);
            
            const char* body = (const char*)sqlite3_column_text(stmt, 6);
            email->body = malloc(email->size + 1);
            strncpy(email->body, body, email->size);
            email->body[email->size] = '\0';
        }
        sqlite3_finalize(stmt);
    }
    
    pthread_mutex_unlock(&db_mutex);
    return email;
}

// Функция для поиска писем
int* db_search_emails(const char* username, const char* folder, const char* criteria) {
    pthread_mutex_lock(&db_mutex);
    
    if (db == NULL) {
        pthread_mutex_unlock(&db_mutex);
        return NULL;
    }
    
    // Упрощенная реализация - возвращаем все письма
    int count = db_get_email_count(username, folder);
    int* result = malloc((count + 1) * sizeof(int));
    
    for (int i = 0; i < count; i++) {
        result[i] = i + 1;
    }
    result[count] = 0;
    
    pthread_mutex_unlock(&db_mutex);
    return result;
}