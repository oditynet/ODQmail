#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdarg.h>
#include <strings.h>
#include <sys/stat.h>
#include "mail_db.h"

#define MAX_CLIENTS 100
#define BUFFER_SIZE 4096
#define CONFIG_FILE "mail_server.conf"
#define MAX_LINE_LENGTH 256
#define MAX_CONFIG_ENTRIES 100

#include <arpa/nameser.h>
#include <resolv.h>

// Структура для хранения конфигурационных параметров
typedef struct {
    char key[100];
    char value[200];
} ConfigEntry;

// Структура для хранения информации о клиенте
typedef struct {
    int socket;
    SSL* ssl;
    bool use_ssl;
    char username[100];
    bool authenticated;
    char current_folder[50];
    struct sockaddr_in addr;
} ClientInfo;

// Структура для конфигурации сервера
typedef struct {
    // IMAP настройки
    int imap_port;
    int imaps_port;
    char imap_bind_addr[16];
    
    // SMTP настройки
    int smtp_port;
    int smtps_port;
    char smtp_bind_addr[16];
    
    // SSL настройки
    char ssl_cert_file[256];
    char ssl_key_file[256];
    
    // Сервисные учетные записи
    char imap_service_user[100];
    char imap_service_password[100];
    char smtp_service_user[100];
    char smtp_service_password[100];
    char smtp_relay_host[100];
    int smtp_relay_port;
    
    // Блокировка доменов
    char blocked_domains[10][100];
    int blocked_domains_count;
} ServerConfig;

// Глобальные переменные сервера
int imap_server_socket = -1;
int smtp_server_socket = -1;
int imaps_server_socket = -1;
int smtps_server_socket = -1;
SSL_CTX* imap_ssl_ctx = NULL;
SSL_CTX* smtp_ssl_ctx = NULL;
pthread_mutex_t db_mutex = PTHREAD_MUTEX_INITIALIZER;
ServerConfig server_config;

// Прототипы функций
bool load_config();
void init_openssl();
SSL_CTX* create_ssl_context();
void cleanup_openssl();
int create_server_socket(int port, const char* bind_addr);
void* imap_server_thread(void* arg);
void* smtp_server_thread(void* arg);
void* imaps_server_thread(void* arg);
void* smtps_server_thread(void* arg);
void* handle_imap_client(void* arg);
void* handle_smtp_client(void* arg);
void process_imap_command(ClientInfo* client, const char* command);
void process_smtp_command(ClientInfo* client, const char* command);
void send_response(ClientInfo* client, const char* response, ...);
int read_from_client(ClientInfo* client, char* buffer, int size);
void log_connection(const char* protocol, const char* action, ClientInfo* client);
bool is_domain_blocked(const char* email);
bool send_external_email(const char* from, const char* to, const char* subject, const char* body);
char* get_mx_record(const char* domain);
void trim_whitespace(char* str);
int parse_config_file(const char* filename, ConfigEntry* entries, int max_entries);
const char* extract_subject(const char* email_data); // ДОБАВЬТЕ ЭТУ СТРОКУ

// Функция для удаления пробелов в начале и конце строки
void trim_whitespace(char* str) {
    char* end;
    
    // Удаляем пробелы в начале
    while (isspace((unsigned char)*str)) str++;
    
    if (*str == 0) return;
    
    // Удаляем пробелы в конце
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    
    // Записываем новый null terminator
    *(end + 1) = 0;
}

// Функция парсинга конфигурационного файла
int parse_config_file(const char* filename, ConfigEntry* entries, int max_entries) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        return -1;
    }
    
    char line[MAX_LINE_LENGTH];
    int count = 0;
    
    while (fgets(line, sizeof(line), file) && count < max_entries) {
        // Пропускаем комментарии и пустые строки
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') {
            continue;
        }
        
        trim_whitespace(line);
        
        // Ищем разделитель '='
        char* separator = strchr(line, '=');
        if (!separator) {
            continue;
        }
        
        *separator = '\0';
        char* key = line;
        char* value = separator + 1;
        
        trim_whitespace(key);
        trim_whitespace(value);
        
        // Удаляем кавычки если есть
        if (value[0] == '"' && value[strlen(value)-1] == '"') {
            value[strlen(value)-1] = '\0';
            value++;
        }
        
        if (strlen(key) > 0 && strlen(value) > 0) {
            strncpy(entries[count].key, key, sizeof(entries[count].key)-1);
            strncpy(entries[count].value, value, sizeof(entries[count].value)-1);
            count++;
        }
    }
    
    fclose(file);
    return count;
}

// Загрузка конфигурации
bool load_config() {
    ConfigEntry entries[MAX_CONFIG_ENTRIES];
    int count = parse_config_file(CONFIG_FILE, entries, MAX_CONFIG_ENTRIES);
    
    if (count <= 0) {
        printf("Error: Cannot read or parse config file %s\n", CONFIG_FILE);
        return false;
    }
    
    // Устанавливаем значения по умолчанию
    server_config.imap_port = 143;
    server_config.imaps_port = 993;
    server_config.smtp_port = 25;
    server_config.smtps_port = 587;
    server_config.smtp_relay_port = 587;
    
    strcpy(server_config.imap_bind_addr, "imap.oditynet.ru");
    strcpy(server_config.smtp_bind_addr, "oditynet.ru");
    strcpy(server_config.ssl_cert_file, "ssl_certs/mail_server.pem");
    strcpy(server_config.ssl_key_file, "ssl_certs/mail_server.key");
    strcpy(server_config.imap_service_user, "imap@oditynet.ru");
    strcpy(server_config.imap_service_password, "imap_password123");
    strcpy(server_config.smtp_service_user, "smtp@oditynet.ru");
    strcpy(server_config.smtp_service_password, "smtp_password123");
    strcpy(server_config.smtp_relay_host, "smtp.oditynet.ru");
    
    server_config.blocked_domains_count = 0;
    
    // Парсим конфигурационные параметры
    for (int i = 0; i < count; i++) {
        if (strcmp(entries[i].key, "imap.port") == 0) {
            server_config.imap_port = atoi(entries[i].value);
        }
        else if (strcmp(entries[i].key, "imaps.port") == 0) {
            server_config.imaps_port = atoi(entries[i].value);
        }
        else if (strcmp(entries[i].key, "imap.bind_address") == 0) {
            strncpy(server_config.imap_bind_addr, entries[i].value, sizeof(server_config.imap_bind_addr)-1);
        }
        else if (strcmp(entries[i].key, "smtp.port") == 0) {
            server_config.smtp_port = atoi(entries[i].value);
        }
        else if (strcmp(entries[i].key, "smtps.port") == 0) {
            server_config.smtps_port = atoi(entries[i].value);
        }
        else if (strcmp(entries[i].key, "smtp.bind_address") == 0) {
            strncpy(server_config.smtp_bind_addr, entries[i].value, sizeof(server_config.smtp_bind_addr)-1);
        }
        else if (strcmp(entries[i].key, "ssl.certificate_file") == 0) {
            strncpy(server_config.ssl_cert_file, entries[i].value, sizeof(server_config.ssl_cert_file)-1);
        }
        else if (strcmp(entries[i].key, "ssl.private_key_file") == 0) {
            strncpy(server_config.ssl_key_file, entries[i].value, sizeof(server_config.ssl_key_file)-1);
        }
        else if (strcmp(entries[i].key, "service_accounts.imap_user") == 0) {
            strncpy(server_config.imap_service_user, entries[i].value, sizeof(server_config.imap_service_user)-1);
        }
        else if (strcmp(entries[i].key, "service_accounts.imap_password") == 0) {
            strncpy(server_config.imap_service_password, entries[i].value, sizeof(server_config.imap_service_password)-1);
        }
        else if (strcmp(entries[i].key, "service_accounts.smtp_user") == 0) {
            strncpy(server_config.smtp_service_user, entries[i].value, sizeof(server_config.smtp_service_user)-1);
        }
        else if (strcmp(entries[i].key, "service_accounts.smtp_password") == 0) {
            strncpy(server_config.smtp_service_password, entries[i].value, sizeof(server_config.smtp_service_password)-1);
        }
        else if (strcmp(entries[i].key, "smtp.relay_host") == 0) {
            strncpy(server_config.smtp_relay_host, entries[i].value, sizeof(server_config.smtp_relay_host)-1);
        }
        else if (strcmp(entries[i].key, "smtp.relay_port") == 0) {
            server_config.smtp_relay_port = atoi(entries[i].value);
        }
        else if (strcmp(entries[i].key, "security.blocked_domains") == 0) {
            // Парсим список доменов через запятую
            char* token = strtok(entries[i].value, ",");
            while (token && server_config.blocked_domains_count < 10) {
                trim_whitespace(token);
                strncpy(server_config.blocked_domains[server_config.blocked_domains_count], 
                        token, sizeof(server_config.blocked_domains[0])-1);
                server_config.blocked_domains_count++;
                token = strtok(NULL, ",");
            }
        }
    }
    
    printf("Configuration loaded successfully\n");
    return true;
}

// Проверка блокировки домена
bool is_domain_blocked(const char* email) {
    const char* at = strchr(email, '@');
    if (!at) return false;
    
    const char* domain = at + 1;
    for (int i = 0; i < server_config.blocked_domains_count; i++) {
        if (strcasecmp(domain, server_config.blocked_domains[i]) == 0) {
            return true;
        }
    }
    return false;
}

// Инициализация OpenSSL
void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

// Создание SSL контекста
SSL_CTX* create_ssl_context() {
    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    
    if (!ctx) {
        perror("Unable to create SSL context");
        return NULL;
    }
    
    // Загружаем сертификат и приватный ключ
    if (SSL_CTX_use_certificate_file(ctx, server_config.ssl_cert_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    if (SSL_CTX_use_PrivateKey_file(ctx, server_config.ssl_key_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    // Проверяем соответствие ключа и сертификата
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the certificate public key\n");
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    return ctx;
}

// Очистка OpenSSL
void cleanup_openssl() {
    EVP_cleanup();
}

// Создание серверного сокета
int create_server_socket(int port, const char* bind_addr) {
    int server_fd;
    struct sockaddr_in address;
    int opt = 1;
    
    // Создаем сокет
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        return -1;
    }
    
    // Настраиваем опции сокета
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt");
        close(server_fd);
        return -1;
    }
    
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    
    if (bind_addr && strlen(bind_addr) > 0) {
        inet_pton(AF_INET, bind_addr, &address.sin_addr);
    } else {
        address.sin_addr.s_addr = INADDR_ANY;
    }
    
    // Биндим сокет
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        close(server_fd);
        return -1;
    }
    
    // Слушаем
    if (listen(server_fd, 10) < 0) {
        perror("listen");
        close(server_fd);
        return -1;
    }
    
    printf("Server listening on %s:%d\n", 
           bind_addr && strlen(bind_addr) > 0 ? bind_addr : "0.0.0.0", port);
    return server_fd;
}

// Логирование подключений
void log_connection(const char* protocol, const char* action, ClientInfo* client) {
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client->addr.sin_addr, ip_str, INET_ADDRSTRLEN);
    
    printf("[%s] %s - %s:%d - %s\n", 
           protocol, action, ip_str, ntohs(client->addr.sin_port), 
           client->username[0] ? client->username : "anonymous");
}

// Чтение данных от клиента
int read_from_client(ClientInfo* client, char* buffer, int size) {
    if (client->use_ssl && client->ssl) {
        return SSL_read(client->ssl, buffer, size);
    } else {
        return read(client->socket, buffer, size);
    }
}

// Отправка ответа клиенту
void send_response(ClientInfo* client, const char* response, ...) {
    char formatted_response[BUFFER_SIZE];
    va_list args;
    
    va_start(args, response);
    vsnprintf(formatted_response, sizeof(formatted_response), response, args);
    va_end(args);
    
    if (client->use_ssl && client->ssl) {
        SSL_write(client->ssl, formatted_response, strlen(formatted_response));
    } else {
        send(client->socket, formatted_response, strlen(formatted_response), 0);
    }
}

// Функция для определения MX-записи (упрощенная версия)
/*char* get_mx_record(const char* domain) {
    unsigned char response[NS_PACKETSZ];
    ns_msg handle;
    ns_rr rr;
    
    int len = res_query(domain, ns_c_in, ns_t_mx, response, sizeof(response));
    if (len < 0) {
        return NULL;
    }
    
    ns_initparse(response, len, &handle);
    
    // Ищем MX запись с наивысшим приоритетом (наименьшим числом)
    char* mx_host = NULL;
    int min_priority = INT_MAX;
    
    for (int i = 0; i < ns_msg_count(handle, ns_s_an); i++) {
        if (ns_parserr(&handle, ns_s_an, i, &rr) == 0) {
            if (ns_rr_type(rr) == ns_t_mx) {
                int priority = ns_get16(ns_rr_rdata(rr));
                if (priority < min_priority) {
                    min_priority = priority;
                    if (mx_host) free(mx_host);
                    mx_host = strdup((char*)ns_rr_rdata(rr) + 2);
                }
            }
        }
    }
    
    return mx_host;
}*/
char* get_mx_record(const char* domain) {
    printf("Querying MX record for domain: %s\n", domain);
    
    unsigned char response[NS_PACKETSZ];
    ns_msg handle;
    ns_rr rr;
    
    // Инициализируем resolver
    if (res_init() != 0) {
        printf("Failed to initialize resolver\n");
        return NULL;
    }
    
    // Выполняем DNS запрос
    int len = res_query(domain, ns_c_in, ns_t_mx, response, sizeof(response));
    if (len < 0) {
        printf("DNS query failed for %s: %s\n", domain, hstrerror(h_errno));
        return NULL;
    }
    
    // Парсим ответ
    if (ns_initparse(response, len, &handle) < 0) {
        printf("Failed to parse DNS response\n");
        return NULL;
    }
    
    // Ищем MX запись с наивысшим приоритетом (наименьшим числом)
    char* mx_host = NULL;
    int min_priority = INT_MAX;
    int mx_count = ns_msg_count(handle, ns_s_an);
    
    printf("Found %d MX records\n", mx_count);
    
    for (int i = 0; i < mx_count; i++) {
        if (ns_parserr(&handle, ns_s_an, i, &rr) == 0) {
            if (ns_rr_type(rr) == ns_t_mx) {
                int priority = ns_get16(ns_rr_rdata(rr));
                char mx_name[NS_MAXDNAME];
                
                // Получаем имя MX сервера
                if (ns_name_uncompress(response, response + len, 
                                      ns_rr_rdata(rr) + 2, 
                                      mx_name, sizeof(mx_name)) < 0) {
                    printf("Failed to uncompress MX name\n");
                    continue;
                }
                
                printf("MX record: priority=%d, host=%s\n", priority, mx_name);
                
                // Выбираем MX с наивысшим приоритетом
                if (priority < min_priority) {
                    min_priority = priority;
                    if (mx_host) {
                        free(mx_host);
                    }
                    mx_host = strdup(mx_name);
                }
            }
        }
    }
    
    if (mx_host) {
        printf("Selected MX server: %s (priority %d)\n", mx_host, min_priority);
    } else {
        printf("No MX records found for %s\n", domain);
        
        // Fallback: используем домен как MX (стандартное поведение)
        char fallback[256];
        snprintf(fallback, sizeof(fallback), "smtp.%s", domain);
        mx_host = strdup(fallback);
        printf("Using fallback MX: %s\n", mx_host);
    }
    
    return mx_host;
}

// Отправка внешнего email через MX сервер
/*bool send_external_email(const char* from, const char* to, const char* subject, const char* body) {
    printf("Attempting to send external email from %s to %s\n", from, to);
    
    // Извлекаем домен из адреса получателя
    const char* at = strchr(to, '@');
    if (!at) {
        printf("Invalid email address: %s\n", to);
        return false;
    }
    
    char domain[256];
    strncpy(domain, at + 1, sizeof(domain) - 1);
    domain[sizeof(domain) - 1] = '\0';
    
    // Получаем MX запись для домена
    char* mx_host = get_mx_record(domain);
    if (!mx_host) {
        printf("Failed to get MX record for domain: %s\n", domain);
        return false;
    }
    
    printf("Using MX server: %s for domain: %s\n", mx_host, domain);
    
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        free(mx_host);
        return false;
    }
    
    struct hostent* server = gethostbyname(mx_host);
    if (!server) {
        printf("Error: no such host %s\n", mx_host);
        free(mx_host);
        close(sockfd);
        return false;
    }
    
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    memcpy(&serv_addr.sin_addr.s_addr, server->h_addr_list[0], server->h_length);
    serv_addr.sin_port = htons(25); // Стандартный SMTP порт
    
    // Устанавливаем таймаут
    struct timeval timeout;
    timeout.tv_sec = 30;
    timeout.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connect");
        free(mx_host);
        close(sockfd);
        return false;
    }
    
    char buffer[BUFFER_SIZE];
    int bytes;
    
    // Читаем приветствие сервера
    bytes = read(sockfd, buffer, sizeof(buffer) - 1);
    if (bytes <= 0) {
        printf("No greeting from MX server\n");
        free(mx_host);
        close(sockfd);
        return false;
    }
    buffer[bytes] = '\0';
    
    // Отправляем EHLO
    snprintf(buffer, sizeof(buffer), "EHLO oditynet.ru\r\n");
    if (write(sockfd, buffer, strlen(buffer)) <= 0) {
        perror("write EHLO");
        free(mx_host);
        close(sockfd);
        return false;
    }
    
    bytes = read(sockfd, buffer, sizeof(buffer) - 1);
    if (bytes <= 0) {
        printf("No response to EHLO\n");
        free(mx_host);
        close(sockfd);
        return false;
    }
    buffer[bytes] = '\0';
    
    // MAIL FROM
    snprintf(buffer, sizeof(buffer), "MAIL FROM:<%s>\r\n", from);
    if (write(sockfd, buffer, strlen(buffer)) <= 0) {
        perror("write MAIL FROM");
        free(mx_host);
        close(sockfd);
        return false;
    }
    
    bytes = read(sockfd, buffer, sizeof(buffer) - 1);
    if (bytes <= 0) {
        printf("No response to MAIL FROM\n");
        free(mx_host);
        close(sockfd);
        return false;
    }
    buffer[bytes] = '\0';
    
    // RCPT TO
    snprintf(buffer, sizeof(buffer), "RCPT TO:<%s>\r\n", to);
    if (write(sockfd, buffer, strlen(buffer)) <= 0) {
        perror("write RCPT TO");
        free(mx_host);
        close(sockfd);
        return false;
    }
    
    bytes = read(sockfd, buffer, sizeof(buffer) - 1);
    if (bytes <= 0) {
        printf("No response to RCPT TO\n");
        free(mx_host);
        close(sockfd);
        return false;
    }
    buffer[bytes] = '\0';
    
    // DATA
    snprintf(buffer, sizeof(buffer), "DATA\r\n");
    if (write(sockfd, buffer, strlen(buffer)) <= 0) {
        perror("write DATA");
        free(mx_host);
        close(sockfd);
        return false;
    }
    
    bytes = read(sockfd, buffer, sizeof(buffer) - 1);
    if (bytes <= 0) {
        printf("No response to DATA\n");
        free(mx_host);
        close(sockfd);
        return false;
    }
    buffer[bytes] = '\0';
    
    // Формируем полное письмо с заголовками
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    char date_str[100];
    strftime(date_str, sizeof(date_str), "%a, %d %b %Y %H:%M:%S %z", tm_info);
    
    char message_id[50];
    snprintf(message_id, sizeof(message_id), "%ld.%d@oditynet.ru", now, rand());
    
    char email_data[BUFFER_SIZE * 2];
    snprintf(email_data, sizeof(email_data),
        "From: %s\r\n"
        "To: %s\r\n"
        "Subject: %s\r\n"
        "Date: %s\r\n"
        "Message-ID: <%s>\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "Content-Transfer-Encoding: 7bit\r\n"
        "\r\n"
        "%s\r\n"
        ".\r\n",
        from, to, subject, date_str, message_id, body);
    
    if (write(sockfd, email_data, strlen(email_data)) <= 0) {
        perror("write email data");
        free(mx_host);
        close(sockfd);
        return false;
    }
    
    bytes = read(sockfd, buffer, sizeof(buffer) - 1);
    if (bytes <= 0) {
        printf("No response to email data\n");
        free(mx_host);
        close(sockfd);
        return false;
    }
    buffer[bytes] = '\0';
    
    // QUIT
    snprintf(buffer, sizeof(buffer), "QUIT\r\n");
    write(sockfd, buffer, strlen(buffer));
    
    free(mx_host);
    close(sockfd);
    
    printf("Email successfully delivered to %s\n", to);
    return true;
}*/
// Отправка внешнего email через MX сервер
bool send_external_email(const char* from, const char* to, const char* subject, const char* body) {
    printf("=== EXTERNAL EMAIL START ===\n");
    printf("From: %s\n", from);
    printf("To: %s\n", to);
    printf("Subject: %s\n", subject);
    
    // Извлекаем домен из адреса получателя
    const char* at = strchr(to, '@');
    if (!at) {
        printf("Invalid email address: %s\n", to);
        return false;
    }
    
    char domain[256];
    strncpy(domain, at + 1, sizeof(domain) - 1);
    domain[sizeof(domain) - 1] = '\0';
    
    // Получаем MX запись для домена получателя
    printf("Getting MX record for: %s\n", domain);
    char* mx_host = get_mx_record(domain);
    if (!mx_host) {
        printf("Failed to get MX record for domain: %s\n", domain);
        return false;
    }
    
    printf("Using MX server: %s\n", mx_host);
    
    // Создаем сокет
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        free(mx_host);
        return false;
    }
    
    // Получаем адрес MX сервера
    struct hostent* server = gethostbyname(mx_host);
    if (!server) {
        printf("Error: no such host %s\n", mx_host);
        free(mx_host);
        close(sockfd);
        return false;
    }
    
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    memcpy(&serv_addr.sin_addr.s_addr, server->h_addr_list[0], server->h_length);
    serv_addr.sin_port = htons(25); // SMTP порт
    
    // Таймауты
    struct timeval timeout;
    timeout.tv_sec = 30;
    timeout.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    // Подключаемся к MX серверу
    printf("Connecting to MX server: %s:25\n", mx_host);
    if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connect");
        free(mx_host);
        close(sockfd);
        return false;
    }
    
    char buffer[BUFFER_SIZE];
    int bytes;
    
    // Читаем приветствие MX сервера
    bytes = read(sockfd, buffer, sizeof(buffer) - 1);
    if (bytes <= 0) {
        printf("No greeting from MX server\n");
        free(mx_host);
        close(sockfd);
        return false;
    }
    buffer[bytes] = '\0';
    printf("MX greeting: %s", buffer);
    
    // Отправляем EHLO с вашим доменом
    const char* ehlo_domain = "oditynet.ru";
    snprintf(buffer, sizeof(buffer), "EHLO %s\r\n", ehlo_domain);
    printf("Sending: %s", buffer);
    if (write(sockfd, buffer, strlen(buffer)) <= 0) {
        perror("write EHLO");
        free(mx_host);
        close(sockfd);
        return false;
    }
    
    bytes = read(sockfd, buffer, sizeof(buffer) - 1);
    if (bytes <= 0) {
        printf("No response to EHLO\n");
        free(mx_host);
        close(sockfd);
        return false;
    }
    buffer[bytes] = '\0';
    printf("EHLO response: %s", buffer);
    
    // MAIL FROM
    snprintf(buffer, sizeof(buffer), "MAIL FROM:<%s>\r\n", from);
    printf("Sending: %s", buffer);
    if (write(sockfd, buffer, strlen(buffer)) <= 0) {
        perror("write MAIL FROM");
        free(mx_host);
        close(sockfd);
        return false;
    }
    
    bytes = read(sockfd, buffer, sizeof(buffer) - 1);
    if (bytes <= 0) {
        printf("No response to MAIL FROM\n");
        free(mx_host);
        close(sockfd);
        return false;
    }
    buffer[bytes] = '\0';
    printf("MAIL FROM response: %s", buffer);
    
    // RCPT TO
    snprintf(buffer, sizeof(buffer), "RCPT TO:<%s>\r\n", to);
    printf("Sending: %s", buffer);
    if (write(sockfd, buffer, strlen(buffer)) <= 0) {
        perror("write RCPT TO");
        free(mx_host);
        close(sockfd);
        return false;
    }
    
    bytes = read(sockfd, buffer, sizeof(buffer) - 1);
    if (bytes <= 0) {
        printf("No response to RCPT TO\n");
        free(mx_host);
        close(sockfd);
        return false;
    }
    buffer[bytes] = '\0';
    printf("RCPT TO response: %s", buffer);
    
    // DATA
    snprintf(buffer, sizeof(buffer), "DATA\r\n");
    printf("Sending: %s", buffer);
    if (write(sockfd, buffer, strlen(buffer)) <= 0) {
        perror("write DATA");
        free(mx_host);
        close(sockfd);
        return false;
    }
    
    bytes = read(sockfd, buffer, sizeof(buffer) - 1);
    if (bytes <= 0) {
        printf("No response to DATA\n");
        free(mx_host);
        close(sockfd);
        return false;
    }
    buffer[bytes] = '\0';
    printf("DATA response: %s", buffer);
    
    // Отправляем само письмо
    printf("Sending email content...\n");
    if (write(sockfd, body, strlen(body)) <= 0) {
        perror("write email body");
        free(mx_host);
        close(sockfd);
        return false;
    }
    
    // Конец данных
    if (write(sockfd, "\r\n.\r\n", 5) <= 0) {
        perror("write end of data");
        free(mx_host);
        close(sockfd);
        return false;
    }
    
    bytes = read(sockfd, buffer, sizeof(buffer) - 1);
    if (bytes <= 0) {
        printf("No response to email data\n");
        free(mx_host);
        close(sockfd);
        return false;
    }
    buffer[bytes] = '\0';
    printf("Email response: %s", buffer);
    
    // QUIT
    snprintf(buffer, sizeof(buffer), "QUIT\r\n");
    write(sockfd, buffer, strlen(buffer));
    
    free(mx_host);
    close(sockfd);
    
    printf("=== EXTERNAL EMAIL SUCCESS ===\n");
    return true;
}

// Поток IMAP сервера
void* imap_server_thread(void* arg) {
    (void)arg;
    imap_server_socket = create_server_socket(server_config.imap_port, server_config.imap_bind_addr);
    if (imap_server_socket < 0) {
        printf("Failed to start IMAP server\n");
        return NULL;
    }
    
    printf("IMAP server started on port %d\n", server_config.imap_port);
    
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_socket;
        
        // Принимаем соединение
        client_socket = accept(imap_server_socket, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket < 0) {
            perror("accept");
            continue;
        }
        
        // Создаем структуру для клиента
        ClientInfo* client_info = malloc(sizeof(ClientInfo));
        memset(client_info, 0, sizeof(ClientInfo));
        client_info->socket = client_socket;
        client_info->use_ssl = false;
        client_info->authenticated = false;
        client_info->addr = client_addr;
        strcpy(client_info->current_folder, "INBOX");
        
        log_connection("IMAP", "CONNECT", client_info);
        
        // Обрабатываем клиента в отдельном потоке
        pthread_t thread_id;
        pthread_create(&thread_id, NULL, handle_imap_client, client_info);
        pthread_detach(thread_id);
    }
    
    return NULL;
}

// Поток IMAPS сервера
void* imaps_server_thread(void* arg) {
    (void)arg;
    imaps_server_socket = create_server_socket(server_config.imaps_port, server_config.imap_bind_addr);
    if (imaps_server_socket < 0) {
        printf("Failed to start IMAPS server\n");
        return NULL;
    }
    
    imap_ssl_ctx = create_ssl_context();
    if (!imap_ssl_ctx) {
        printf("Failed to create SSL context for IMAPS\n");
        close(imaps_server_socket);
        return NULL;
    }
    
    printf("IMAPS server started on port %d\n", server_config.imaps_port);
    
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_socket;
        
        // Принимаем соединение
        client_socket = accept(imaps_server_socket, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket < 0) {
            perror("accept");
            continue;
        }
        
        // Создаем SSL соединение
        SSL* ssl = SSL_new(imap_ssl_ctx);
        SSL_set_fd(ssl, client_socket);
        
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(client_socket);
            continue;
        }
        
        // Создаем структуру для клиента
        ClientInfo* client_info = malloc(sizeof(ClientInfo));
        memset(client_info, 0, sizeof(ClientInfo));
        client_info->socket = client_socket;
        client_info->ssl = ssl;
        client_info->use_ssl = true;
        client_info->authenticated = false;
        client_info->addr = client_addr;
        strcpy(client_info->current_folder, "INBOX");
        
        log_connection("IMAPS", "CONNECT", client_info);
        
        // Обрабатываем клиента в отдельном потоке
        pthread_t thread_id;
        pthread_create(&thread_id, NULL, handle_imap_client, client_info);
        pthread_detach(thread_id);
    }
    
    return NULL;
}

// Обработчик IMAP клиента
void* handle_imap_client(void* arg) {
    ClientInfo* client = (ClientInfo*)arg;
    char buffer[BUFFER_SIZE];
    int valread;
    
    // Отправляем приветствие
    send_response(client, "* OK ODQ IMAP4rev1 Server ready\r\n");
    
    while (1) {
        // Читаем команду от клиента
        valread = read_from_client(client, buffer, BUFFER_SIZE - 1);
        
        if (valread <= 0) {
            break;
        }
        
        buffer[valread] = '\0';
        log_connection(client->use_ssl ? "IMAPS" : "IMAP", "RECV", client);
        
        // Обрабатываем команду
        process_imap_command(client, buffer);
    }
    
    log_connection(client->use_ssl ? "IMAPS" : "IMAP", "DISCONNECT", client);
    close(client->socket);
    if (client->ssl) {
        SSL_free(client->ssl);
    }
    free(client);
    return NULL;
}

// Обработка IMAP команд
void process_imap_command(ClientInfo* client, const char* command) {
    char tag[50], cmd[50], params[500];
    
    if (sscanf(command, "%s %s %[^\r\n]", tag, cmd, params) < 2) {
        send_response(client, "BAD Command error\r\n");
        return;
    }
    
    // Преобразуем команду в верхний регистр для сравнения
    for (char* p = cmd; *p; p++) *p = toupper(*p);
    
    if (strcmp(cmd, "CAPABILITY") == 0) {
        send_response(client, "* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\n");
        send_response(client, "%s OK CAPABILITY completed\r\n", tag);
    }
    else if (strcmp(cmd, "LOGIN") == 0) {
        char username[100], password[100];
        if (sscanf(params, "%s %s", username, password) == 2) {
            pthread_mutex_lock(&db_mutex);
            bool auth_success = db_authenticate_user(username, password);
            pthread_mutex_unlock(&db_mutex);
            
            if (auth_success) {
                client->authenticated = true;
                strcpy(client->username, username);
                send_response(client, "%s OK LOGIN completed\r\n", tag);
                log_connection(client->use_ssl ? "IMAPS" : "IMAP", "AUTH_SUCCESS", client);
            } else {
                send_response(client, "%s NO Login failed: invalid credentials\r\n", tag);
                log_connection(client->use_ssl ? "IMAPS" : "IMAP", "AUTH_FAILED", client);
            }
        } else {
            send_response(client, "%s BAD Invalid syntax\r\n", tag);
        }
    }
    else if (strcmp(cmd, "SELECT") == 0) {
        if (!client->authenticated) {
            send_response(client, "%s NO Not authenticated\r\n", tag);
            return;
        }
        
        char mailbox[100];
        sscanf(params, "\"%[^\"]\"", mailbox);
        strcpy(client->current_folder, mailbox);
        
        pthread_mutex_lock(&db_mutex);
        int msg_count = db_get_email_count(client->username, mailbox);
        pthread_mutex_unlock(&db_mutex);
        
        send_response(client, "* %d EXISTS\r\n", msg_count);
        send_response(client, "* 0 RECENT\r\n");
        send_response(client, "* OK [UNSEEN 1]\r\n");
        send_response(client, "* OK [UIDVALIDITY 1]\r\n");
        send_response(client, "* OK [UIDNEXT 1000]\r\n");
        send_response(client, "%s OK [READ-WRITE] SELECT completed\r\n", tag);
    }
    else if (strcmp(cmd, "FETCH") == 0) {
        if (!client->authenticated) {
            send_response(client, "%s NO Not authenticated\r\n", tag);
            return;
        }
        
        unsigned int msg_num;
        char what[100];
        sscanf(params, "%u %[^)]", &msg_num, what);
        
        pthread_mutex_lock(&db_mutex);
        Email* email = db_get_email(client->username, client->current_folder, msg_num);
        pthread_mutex_unlock(&db_mutex);
        
        if (email) {
            char response[BUFFER_SIZE];
            snprintf(response, sizeof(response), 
                    "* %u FETCH (UID %s RFC822.SIZE %d BODY[] {%d}\r\n%s)\r\n", 
                    msg_num, email->uuid, email->size, email->size, email->body);
            send_response(client, response);
            send_response(client, "%s OK FETCH completed\r\n", tag);
            free(email->body);
            free(email);
        } else {
            send_response(client, "%s NO Message not found\r\n", tag);
        }
    }
    else if (strcmp(cmd, "LOGOUT") == 0) {
        send_response(client, "* BYE ODQ IMAP4rev1 Server logging out\r\n");
        send_response(client, "%s OK LOGOUT completed\r\n", tag);
        close(client->socket);
    }
    else if (strcmp(cmd, "NOOP") == 0) {
        send_response(client, "%s OK NOOP completed\r\n", tag);
    }
    else if (strcmp(cmd, "LIST") == 0) {
        send_response(client, "* LIST (\\HasNoChildren) \".\" \"INBOX\"\r\n");
        send_response(client, "* LIST (\\HasNoChildren) \".\" \"Sent\"\r\n");
        send_response(client, "* LIST (\\HasNoChildren) \".\" \"Drafts\"\r\n");
        send_response(client, "* LIST (\\HasNoChildren) \".\" \"Trash\"\r\n");
        send_response(client, "%s OK LIST completed\r\n", tag);
    }
    else if (strcmp(cmd, "STATUS") == 0) {
        char mailbox[100];
        sscanf(params, "\"%[^\"]\"", mailbox);
        
        pthread_mutex_lock(&db_mutex);
        int msg_count = db_get_email_count(client->username, mailbox);
        int unseen_count = db_get_unseen_count(client->username, mailbox);
        pthread_mutex_unlock(&db_mutex);
        
        send_response(client, "* STATUS %s (MESSAGES %d RECENT 0 UNSEEN %d)\r\n", 
                     mailbox, msg_count, unseen_count);
        send_response(client, "%s OK STATUS completed\r\n", tag);
    }
    else if (strcmp(cmd, "SEARCH") == 0) {
        if (!client->authenticated) {
            send_response(client, "%s NO Not authenticated\r\n", tag);
            return;
        }
        
        pthread_mutex_lock(&db_mutex);
        int* msg_nums = db_search_emails(client->username, client->current_folder, params);
        pthread_mutex_unlock(&db_mutex);
        
        if (msg_nums) {
            send_response(client, "* SEARCH");
            for (int i = 0; msg_nums[i] != 0; i++) {
                send_response(client, " %d", msg_nums[i]);
            }
            send_response(client, "\r\n");
            send_response(client, "%s OK SEARCH completed\r\n", tag);
            free(msg_nums);
        } else {
            send_response(client, "* SEARCH\r\n");
            send_response(client, "%s OK SEARCH completed\r\n", tag);
        }
    }
    else {
        send_response(client, "%s BAD Unknown command\r\n", tag);
    }
}

// Поток SMTP сервера
void* smtp_server_thread(void* arg) {
    (void)arg;
    smtp_server_socket = create_server_socket(server_config.smtp_port, server_config.smtp_bind_addr);
    if (smtp_server_socket < 0) {
        printf("Failed to start SMTP server\n");
        return NULL;
    }
    
    printf("SMTP server started on port %d\n", server_config.smtp_port);
    
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_socket;
        
        // Принимаем соединение
        client_socket = accept(smtp_server_socket, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket < 0) {
            perror("accept");
            continue;
        }
        
        // Создаем структуру для клиента
        ClientInfo* client_info = malloc(sizeof(ClientInfo));
        memset(client_info, 0, sizeof(ClientInfo));
        client_info->socket = client_socket;
        client_info->use_ssl = false;
        client_info->authenticated = false;
        client_info->addr = client_addr;
        
        log_connection("SMTP", "CONNECT", client_info);
        
        // Обрабатываем клиента в отдельном потоке
        pthread_t thread_id;
        pthread_create(&thread_id, NULL, handle_smtp_client, client_info);
        pthread_detach(thread_id);
    }
    
    return NULL;
}

// Поток SMTPS сервера
void* smtps_server_thread(void* arg) {
    (void)arg;
    smtps_server_socket = create_server_socket(server_config.smtps_port, server_config.smtp_bind_addr);
    if (smtps_server_socket < 0) {
        printf("Failed to start SMTPS server\n");
        return NULL;
    }
    
    smtp_ssl_ctx = create_ssl_context();
    if (!smtp_ssl_ctx) {
        printf("Failed to create SSL context for SMTPS\n");
        close(smtps_server_socket);
        return NULL;
    }
    
    printf("SMTPS server started on port %d\n", server_config.smtps_port);
    
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_socket;
        
        // Принимаем соединение
        client_socket = accept(smtps_server_socket, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket < 0) {
            perror("accept");
            continue;
        }
        
        // Создаем SSL соединение
        SSL* ssl = SSL_new(smtp_ssl_ctx);
        SSL_set_fd(ssl, client_socket);
        
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(client_socket);
            continue;
        }
        
        // Создаем структуру для клиента
        ClientInfo* client_info = malloc(sizeof(ClientInfo));
        memset(client_info, 0, sizeof(ClientInfo));
        client_info->socket = client_socket;
        client_info->ssl = ssl;
        client_info->use_ssl = true;
        client_info->authenticated = false;
        client_info->addr = client_addr;
        
        log_connection("SMTPS", "CONNECT", client_info);
        
        // Обрабатываем клиента в отдельном потоке
        pthread_t thread_id;
        pthread_create(&thread_id, NULL, handle_smtp_client, client_info);
        pthread_detach(thread_id);
    }
    
    return NULL;
}

// Обработчик SMTP клиента
/*void* handle_smtp_client(void* arg) {
    ClientInfo* client = (ClientInfo*)arg;
    char buffer[BUFFER_SIZE];
    int valread;
    
    char from[256] = {0};
    char to[256] = {0};
    char data_buffer[65536] = {0};
    int data_size = 0;
    bool in_data = false;
    bool mail_from_received = false;
    bool rcpt_to_received = false;
    
    // Отправляем приветствие
    send_response(client, "220 oditynet.ru ESMTP ODQ Mail Server ready\r\n");
    
    while (1) {
        // Читаем команду от клиента
        valread = read_from_client(client, buffer, BUFFER_SIZE - 1);
        if (valread <= 0) {
            break;
        }
        
        buffer[valread] = '\0';
        log_connection(client->use_ssl ? "SMTPS" : "SMTP", "RECV", client);
        
        if (in_data) {
            if (strcmp(buffer, ".\r\n") == 0) {
                // Конец данных
                in_data = false;
                
                if (mail_from_received && rcpt_to_received) {
                    // Проверяем блокировку домена отправителя
                    if (is_domain_blocked(from)) {
                        send_response(client, "550 5.7.1 Message rejected: sender domain blocked\r\n");
                        log_connection(client->use_ssl ? "SMTPS" : "SMTP", "DOMAIN_BLOCKED", client);
                    } else {
                        // Сохраняем письмо в базе данных
                        pthread_mutex_lock(&db_mutex);
                        bool success = db_store_email(from, to, "Email from SMTP", 
                                                     data_buffer, data_size, "INBOX");
                        pthread_mutex_unlock(&db_mutex);
                        
                        if (success) {
                            send_response(client, "250 2.0.0 OK: Message accepted for delivery\r\n");
                            log_connection(client->use_ssl ? "SMTPS" : "SMTP", "EMAIL_ACCEPTED", client);
                            
                            // Если письмо на внешний адрес - отправляем через MX
                            printf("from %s to %s\n",from,to);
                            if (strstr(to, "@oditynet.ru") == NULL) {
                                if (send_external_email(from, to, "Email from SMTP", data_buffer)) {
                                    printf("Email forwarded to external address: %s\n", to);
                                }
                            }
                        } else {
                            send_response(client, "550 5.0.0 Error: Failed to store message\r\n");
                        }
                    }
                } else {
                    send_response(client, "503 5.5.1 Error: need MAIL and RCPT commands\r\n");
                }
                
                // Сбрасываем состояние
                mail_from_received = false;
                rcpt_to_received = false;
                from[0] = '\0';
                to[0] = '\0';
                data_size = 0;
                data_buffer[0] = '\0';
            } else {
                // Добавляем данные
                if (data_size + (size_t)valread < sizeof(data_buffer)) {
                    memcpy(data_buffer + data_size, buffer, valread);
                    data_size += valread;
                }
            }
            continue;
        }
        
        // Парсим команду
        char command[10];
        sscanf(buffer, "%4s", command);
        
        if (strcasecmp(command, "HELO") == 0 || strcasecmp(command, "EHLO") == 0) {
            char domain[256];
            sscanf(buffer, "%*s %255s", domain);
            send_response(client, "250-oditynet.ru Hello\r\n");
            send_response(client, "250-SIZE 36700160\r\n");
            send_response(client, "250-8BITMIME\r\n");
            send_response(client, "250-PIPELINING\r\n");
            send_response(client, "250-AUTH PLAIN LOGIN\r\n");
            send_response(client, "250 HELP\r\n");
        }
        else if (strcasecmp(command, "MAIL") == 0) {
            if (strstr(buffer, "FROM:") != NULL) {
                sscanf(buffer, "MAIL FROM:<%255[^>]>", from);
                mail_from_received = true;
                send_response(client, "250 2.1.0 OK\r\n");
                log_connection(client->use_ssl ? "SMTPS" : "SMTP", "MAIL_FROM", client);
            } else {
                send_response(client, "501 5.5.4 Syntax error in parameters\r\n");
            }
        }
        else if (strcasecmp(command, "RCPT") == 0) {
            if (strstr(buffer, "TO:") != NULL) {
                sscanf(buffer, "RCPT TO:<%255[^>]>", to);
                
                // Проверяем существование пользователя для локальных адресов
                if (strstr(to, "@oditynet.ru") != NULL) {
                    pthread_mutex_lock(&db_mutex);
                    bool user_exist = db_user_exists(to);
                    pthread_mutex_unlock(&db_mutex);
                    
                    if (user_exist) {
                        rcpt_to_received = true;
                        send_response(client, "250 2.1.5 OK\r\n");
                        log_connection(client->use_ssl ? "SMTPS" : "SMTP", "RCPT_TO", client);
                    } else {
                        send_response(client, "550 5.1.1 User unknown\r\n");
                    }
                } else {
                    // Внешний адрес - всегда разрешаем
                    rcpt_to_received = true;
                    send_response(client, "250 2.1.5 OK - will attempt delivery\r\n");
                    log_connection(client->use_ssl ? "SMTPS" : "SMTP", "RCPT_TO_EXTERNAL", client);
                }
            } else {
                send_response(client, "501 5.5.4 Syntax error in parameters\r\n");
            }
        }
        else if (strcasecmp(command, "DATA") == 0) {
            if (mail_from_received && rcpt_to_received) {
                in_data = true;
                send_response(client, "354 Start mail input; end with <CRLF>.<CRLF>\r\n");
            } else {
                send_response(client, "503 5.5.1 Error: need MAIL and RCPT commands\r\n");
            }
        }
        else if (strcasecmp(command, "QUIT") == 0) {
            send_response(client, "221 2.0.0 oditynet.ru closing connection\r\n");
            break;
        }
        else if (strcasecmp(command, "RSET") == 0) {
            mail_from_received = false;
            rcpt_to_received = false;
            from[0] = '\0';
            to[0] = '\0';
            data_size = 0;
            data_buffer[0] = '\0';
            in_data = false;
            send_response(client, "250 2.0.0 OK\r\n");
        }
        else if (strcasecmp(command, "NOOP") == 0) {
            send_response(client, "250 2.0.0 OK\r\n");
        }
        else if (strcasecmp(command, "VRFY") == 0) {
            char user[256];
            sscanf(buffer, "%*s %255s", user);
            
            pthread_mutex_lock(&db_mutex);
            bool user_exist = db_user_exists(user);
            pthread_mutex_unlock(&db_mutex);
            
            if (user_exist) {
                char vrfy_response[256];
                snprintf(vrfy_response, sizeof(vrfy_response), "250 2.1.5 <%s>\r\n", user);
                send_response(client, vrfy_response);
            } else {
                send_response(client, "550 5.1.1 User unknown\r\n");
            }
        }
        else if (strcasecmp(command, "AUTH") == 0) {
            if (strstr(buffer, "LOGIN") != NULL) {
                send_response(client, "334 VXNlcm5hbWU6\r\n"); // "Username:" in base64
                
                // Читаем логин
                valread = read_from_client(client, buffer, BUFFER_SIZE - 1);
                if (valread <= 0) break;
                buffer[valread] = '\0';
                
                char username[256];
                // Декодируем base64 (упрощенно)
                if (strlen(buffer) >= 2) {
                    strncpy(username, buffer, sizeof(username) - 1);
                    username[strcspn(username, "\r\n")] = '\0';
                }
                
                send_response(client, "334 UGFzc3dvcmQ6\r\n"); // "Password:" in base64
                
                // Читаем пароль
                valread = read_from_client(client, buffer, BUFFER_SIZE - 1);
                if (valread <= 0) break;
                buffer[valread] = '\0';
                
                char password[256];
                if (strlen(buffer) >= 2) {
                    strncpy(password, buffer, sizeof(password) - 1);
                    password[strcspn(password, "\r\n")] = '\0';
                }
                
                // Аутентифицируем
                pthread_mutex_lock(&db_mutex);
                bool auth_success = db_authenticate_user(username, password);
                pthread_mutex_unlock(&db_mutex);
                
                if (auth_success) {
                    client->authenticated = true;
                    strcpy(client->username, username);
                    send_response(client, "235 2.7.0 Authentication successful\r\n");
                    log_connection(client->use_ssl ? "SMTPS" : "SMTP", "AUTH_SUCCESS", client);
                } else {
                    send_response(client, "535 5.7.8 Authentication credentials invalid\r\n");
                    log_connection(client->use_ssl ? "SMTPS" : "SMTP", "AUTH_FAILED", client);
                }
            } else {
                send_response(client, "504 5.7.4 Unrecognized authentication type\r\n");
            }
        }
        else {
            send_response(client, "500 5.5.1 Command not recognized\r\n");
        }
    }
    
    log_connection(client->use_ssl ? "SMTPS" : "SMTP", "DISCONNECT", client);
    close(client->socket);
    if (client->ssl) {
        SSL_free(client->ssl);
    }
    free(client);
    return NULL;
}*/

/*void* handle_smtp_client(void* arg) {
    ClientInfo* client = (ClientInfo*)arg;
    char buffer[BUFFER_SIZE];
    int valread;
    
    char from[256] = {0};
    char to[256] = {0};
    char data_buffer[65536] = {0};
    int data_size = 0;
    bool in_data = false;
    bool mail_from_received = false;
    bool rcpt_to_received = false;
    
    // Отправляем приветствие
    send_response(client, "220 oditynet.ru ESMTP ODQ Mail Server ready\r\n");
    
    while (1) {
        // Читаем команду от клиента
        valread = read_from_client(client, buffer, BUFFER_SIZE - 1);
        if (valread <= 0) {
            break;
        }
        
        buffer[valread] = '\0';
        log_connection(client->use_ssl ? "SMTPS" : "SMTP", "RECV", client);
        printf("Received: %s", buffer);  // Добавляем отладочный вывод
        
        if (in_data) {
            if (strcmp(buffer, ".\r\n") == 0) {
                // Конец данных
                in_data = false;
                
                if (mail_from_received && rcpt_to_received) {
                    // Проверяем блокировку домена отправителя
                    if (is_domain_blocked(from)) {
                        send_response(client, "550 5.7.1 Message rejected: sender domain blocked\r\n");
                        log_connection(client->use_ssl ? "SMTPS" : "SMTP", "DOMAIN_BLOCKED", client);
                    } else {
                        // Сохраняем письмо в базе данных
                        pthread_mutex_lock(&db_mutex);
                        bool success = db_store_email(from, to, "Email from SMTP", 
                                                     data_buffer, data_size, "INBOX");
                        pthread_mutex_unlock(&db_mutex);
                        
                        if (success) {
                            send_response(client, "250 2.0.0 OK: Message accepted for delivery\r\n");
                            log_connection(client->use_ssl ? "SMTPS" : "SMTP", "EMAIL_ACCEPTED", client);
                            
                            // Если письмо на внешний адрес - отправляем через MX
                            if (strstr(to, "@oditynet.ru") == NULL) {
                                if (send_external_email(from, to, "Email from SMTP", data_buffer)) {
                                    printf("Email forwarded to external address: %s\n", to);
                                }
                            }
                        } else {
                            send_response(client, "550 5.0.0 Error: Failed to store message\r\n");
                        }
                    }
                } else {
                    send_response(client, "503 5.5.1 Error: need MAIL and RCPT commands\r\n");
                }
                
                // Сбрасываем состояние
                mail_from_received = false;
                rcpt_to_received = false;
                from[0] = '\0';
                to[0] = '\0';
                data_size = 0;
                data_buffer[0] = '\0';
            } else {
                // Добавляем данные
                if (data_size + (size_t)valread < sizeof(data_buffer)) {
                    memcpy(data_buffer + data_size, buffer, valread);
                    data_size += valread;
                }
            }
            continue;
        }
        
        // Парсим команду - исправленная версия
        if (strncasecmp(buffer, "HELO", 4) == 0 || strncasecmp(buffer, "EHLO", 4) == 0) {
            char domain[256];
            if (sscanf(buffer, "%*s %255s", domain) == 1) {
                send_response(client, "250-oditynet.ru Hello\r\n");
                send_response(client, "250-SIZE 36700160\r\n");
                send_response(client, "250-8BITMIME\r\n");
                send_response(client, "250-PIPELINING\r\n");
                send_response(client, "250-AUTH PLAIN LOGIN\r\n");
                send_response(client, "250 HELP\r\n");
            } else {
                send_response(client, "501 5.5.4 Syntax error\r\n");
            }
        }
        else if (strncasecmp(buffer, "MAIL FROM:", 10) == 0) {
            // Парсим MAIL FROM команду
            char* start = strchr(buffer, '<');
            char* end = strchr(buffer, '>');
            
            if (start && end && start < end) {
                *end = '\0';
                strncpy(from, start + 1, sizeof(from) - 1);
                mail_from_received = true;
                printf("MAIL FROM parsed: %s\n", from);  // Отладочный вывод
                send_response(client, "250 2.1.0 OK\r\n");
                log_connection(client->use_ssl ? "SMTPS" : "SMTP", "MAIL_FROM", client);
            } else {
                send_response(client, "501 5.5.4 Syntax error in parameters\r\n");
            }
        }
        else if (strncasecmp(buffer, "RCPT TO:", 8) == 0) {
            // Парсим RCPT TO команду
            char* start = strchr(buffer, '<');
            char* end = strchr(buffer, '>');
            
            if (start && end && start < end) {
                *end = '\0';
                strncpy(to, start + 1, sizeof(to) - 1);
                printf("RCPT TO parsed: %s\n", to);  // Отладочный вывод
                
                // Проверяем существование пользователя для локальных адресов
                if (strstr(to, "@oditynet.ru") != NULL) {
                    pthread_mutex_lock(&db_mutex);
                    bool user_exist = db_user_exists(to);
                    pthread_mutex_unlock(&db_mutex);
                    
                    if (user_exist) {
                        rcpt_to_received = true;
                        send_response(client, "250 2.1.5 OK\r\n");
                        log_connection(client->use_ssl ? "SMTPS" : "SMTP", "RCPT_TO", client);
                    } else {
                        send_response(client, "550 5.1.1 User unknown\r\n");
                    }
                } else {
                    // Внешний адрес - всегда разрешаем
                    rcpt_to_received = true;
                    send_response(client, "250 2.1.5 OK - will attempt delivery\r\n");
                    log_connection(client->use_ssl ? "SMTPS" : "SMTP", "RCPT_TO_EXTERNAL", client);
                }
            } else {
                send_response(client, "501 5.5.4 Syntax error in parameters\r\n");
            }
        }
        else if (strncasecmp(buffer, "DATA", 4) == 0) {
            if (mail_from_received && rcpt_to_received) {
                in_data = true;
                send_response(client, "354 Start mail input; end with <CRLF>.<CRLF>\r\n");
            } else {
                send_response(client, "503 5.5.1 Error: need MAIL and RCPT commands\r\n");
            }
        }
        else if (strncasecmp(buffer, "QUIT", 4) == 0) {
            send_response(client, "221 2.0.0 oditynet.ru closing connection\r\n");
            break;
        }
        else if (strncasecmp(buffer, "RSET", 4) == 0) {
            mail_from_received = false;
            rcpt_to_received = false;
            from[0] = '\0';
            to[0] = '\0';
            data_size = 0;
            data_buffer[0] = '\0';
            in_data = false;
            send_response(client, "250 2.0.0 OK\r\n");
        }
        else if (strncasecmp(buffer, "NOOP", 4) == 0) {
            send_response(client, "250 2.0.0 OK\r\n");
        }
        else if (strncasecmp(buffer, "VRFY", 4) == 0) {
            char user[256];
            if (sscanf(buffer, "%*s %255s", user) == 1) {
                pthread_mutex_lock(&db_mutex);
                bool user_exist = db_user_exists(user);
                pthread_mutex_unlock(&db_mutex);
                
                if (user_exist) {
                    char vrfy_response[256];
                    snprintf(vrfy_response, sizeof(vrfy_response), "250 2.1.5 <%s>\r\n", user);
                    send_response(client, vrfy_response);
                } else {
                    send_response(client, "550 5.1.1 User unknown\r\n");
                }
            } else {
                send_response(client, "501 5.5.4 Syntax error\r\n");
            }
        }
        else if (strncasecmp(buffer, "AUTH", 4) == 0) {
            if (strstr(buffer, "LOGIN") != NULL) {
                send_response(client, "334 VXNlcm5hbWU6\r\n");
                
                // Читаем логин
                valread = read_from_client(client, buffer, BUFFER_SIZE - 1);
                if (valread <= 0) break;
                buffer[valread] = '\0';
                printf("Auth username: %s", buffer);
                
                char username[256];
                strncpy(username, buffer, sizeof(username) - 1);
                username[strcspn(username, "\r\n")] = '\0';
                
                send_response(client, "334 UGFzc3dvcmQ6\r\n");
                
                // Читаем пароль
                valread = read_from_client(client, buffer, BUFFER_SIZE - 1);
                if (valread <= 0) break;
                buffer[valread] = '\0';
                printf("Auth password: %s", buffer);
                
                char password[256];
                strncpy(password, buffer, sizeof(password) - 1);
                password[strcspn(password, "\r\n")] = '\0';
                
                // Аутентифицируем
                pthread_mutex_lock(&db_mutex);
                bool auth_success = db_authenticate_user(username, password);
                pthread_mutex_unlock(&db_mutex);
                
                if (auth_success) {
                    client->authenticated = true;
                    strcpy(client->username, username);
                    send_response(client, "235 2.7.0 Authentication successful\r\n");
                    log_connection(client->use_ssl ? "SMTPS" : "SMTP", "AUTH_SUCCESS", client);
                } else {
                    send_response(client, "535 5.7.8 Authentication credentials invalid\r\n");
                    log_connection(client->use_ssl ? "SMTPS" : "SMTP", "AUTH_FAILED", client);
                }
            } else {
                send_response(client, "504 5.7.4 Unrecognized authentication type\r\n");
            }
        }
        else {
            send_response(client, "500 5.5.1 Command not recognized: %s\r\n", buffer);
        }
    }
    
    log_connection(client->use_ssl ? "SMTPS" : "SMTP", "DISCONNECT", client);
    close(client->socket);
    if (client->ssl) {
        SSL_free(client->ssl);
    }
    free(client);
    return NULL;
}*/

void* handle_smtp_client(void* arg) {
    ClientInfo* client = (ClientInfo*)arg;
    char buffer[BUFFER_SIZE];
    int valread;
    
    char from[256] = {0};
    char to[256] = {0};
    char data_buffer[65536] = {0};
    int data_size = 0;
    bool in_data = false;
    bool mail_from_received = false;
    bool rcpt_to_received = false;
    char actual_subject[256] = {0};
    
    // Отправляем приветствие
    send_response(client, "220 oditynet.ru ESMTP ODQ Mail Server ready\r\n");
    
    while (1) {
        // Читаем команду от клиента
        valread = read_from_client(client, buffer, BUFFER_SIZE - 1);
        if (valread <= 0) {
            break;
        }
        
        buffer[valread] = '\0';
        log_connection(client->use_ssl ? "SMTPS" : "SMTP", "RECV", client);
        printf("Received %d bytes: %s", valread, buffer);
        
        if (in_data) {
            // Проверяем, содержит ли буфер точку на отдельной строке
            char* dot_ptr = strstr(buffer, "\r\n.\r\n");
            if (dot_ptr) {
                // Нашли конец данных
                in_data = false;
                
                // Добавляем данные до точки
                int bytes_before_dot = dot_ptr - buffer;
                if (data_size + bytes_before_dot < (int)sizeof(data_buffer)) {
                    memcpy(data_buffer + data_size, buffer, bytes_before_dot);
                    data_size += bytes_before_dot;
                    data_buffer[data_size] = '\0';
                }
                
                printf("End of DATA reached, data size: %d\n", data_size);
                
                if (mail_from_received && rcpt_to_received) {
                    // Проверяем блокировку домена отправителя
                    if (is_domain_blocked(from)) {
                        send_response(client, "550 5.7.1 Message rejected: sender domain blocked\r\n");
                        log_connection(client->use_ssl ? "SMTPS" : "SMTP", "DOMAIN_BLOCKED", client);
                    } else {
                        // Извлекаем тему из тела письма
                        if (strlen(actual_subject) == 0) {
                            const char* extracted_subject = extract_subject(data_buffer);
                            strncpy(actual_subject, extracted_subject, sizeof(actual_subject) - 1);
                            printf("Extracted subject: %s\n", actual_subject);
                        }
                        
                        // Сохраняем письмо в базе данных
                        pthread_mutex_lock(&db_mutex);
                        bool success = db_store_email(from, to, actual_subject, 
                                                     data_buffer, data_size, "INBOX");
                        pthread_mutex_unlock(&db_mutex);
                        
                        if (success) {
                            send_response(client, "250 2.0.0 OK: Message accepted for delivery\r\n");
                            log_connection(client->use_ssl ? "SMTPS" : "SMTP", "EMAIL_ACCEPTED", client);
                            
                            // Если письмо на внешний адрес - отправляем через MX
                            printf("DEBUG: Checking if external email needed for: %s\n", to);
                            if (strstr(to, "@oditynet.ru") == NULL) {
                                printf("DEBUG: External email detected! Calling send_external_email...\n");
                                if (send_external_email(from, to, actual_subject, data_buffer)) {
                                    printf("DEBUG: Email forwarded to external address: %s\n", to);
                                } else {
                                    printf("DEBUG: Failed to forward email to: %s\n", to);
                                }
                            } else {
                                printf("DEBUG: Local email, no forwarding needed\n");
                            }
                        } else {
                            send_response(client, "550 5.0.0 Error: Failed to store message\r\n");
                            printf("Failed to store email in database\n");
                        }
                    }
                } else {
                    send_response(client, "503 5.5.1 Error: need MAIL and RCPT commands\r\n");
                }
                
                // Сбрасываем состояние
                mail_from_received = false;
                rcpt_to_received = false;
                from[0] = '\0';
                to[0] = '\0';
                data_size = 0;
                data_buffer[0] = '\0';
                actual_subject[0] = '\0';
            } else {
                // Проверяем, не является ли вся строка точкой
                if (strcmp(buffer, ".\r\n") == 0) {
                    // Конец данных
                    in_data = false;
                    printf("End of DATA reached (single dot), data size: %d\n", data_size);
                    
                    if (mail_from_received && rcpt_to_received) {
                        // Извлекаем тему из тела письма
                        if (strlen(actual_subject) == 0) {
                            const char* extracted_subject = extract_subject(data_buffer);
                            strncpy(actual_subject, extracted_subject, sizeof(actual_subject) - 1);
                            printf("Extracted subject: %s\n", actual_subject);
                        }
                        
                        // Сохраняем письмо
                        pthread_mutex_lock(&db_mutex);
                        bool success = db_store_email(from, to, actual_subject, 
                                                     data_buffer, data_size, "INBOX");
                        pthread_mutex_unlock(&db_mutex);
                        
                        if (success) {
                            send_response(client, "250 2.0.0 OK: Message accepted for delivery\r\n");
                            log_connection(client->use_ssl ? "SMTPS" : "SMTP", "EMAIL_ACCEPTED", client);
                            
                            // Если письмо на внешний адрес - отправляем через MX
                            printf("DEBUG: Checking if external email needed for: %s\n", to);
                            if (strstr(to, "@oditynet.ru") == NULL) {
                                printf("DEBUG: External email detected! Calling send_external_email...\n");
                                if (send_external_email(from, to, actual_subject, data_buffer)) {
                                    printf("DEBUG: Email forwarded to external address: %s\n", to);
                                } else {
                                    printf("DEBUG: Failed to forward email to: %s\n", to);
                                }
                            } else {
                                printf("DEBUG: Local email, no forwarding needed\n");
                            }
                        } else {
                            send_response(client, "550 5.0.0 Error: Failed to store message\r\n");
                        }
                    }
                    
                    // Сбрасываем состояние
                    mail_from_received = false;
                    rcpt_to_received = false;
                    from[0] = '\0';
                    to[0] = '\0';
                    data_size = 0;
                    data_buffer[0] = '\0';
                    actual_subject[0] = '\0';
                } else {
                    // Обрабатываем "dot stuffing"
                    if (valread >= 3 && buffer[0] == '.' && buffer[1] == '.') {
                        // Убираем лишнюю точку
                        memmove(buffer, buffer + 1, valread - 1);
                        valread--;
                        buffer[valread] = '\0';
                    }
                    
                    // Добавляем данные
                    if (data_size + valread < (int)sizeof(data_buffer)) {
                        memcpy(data_buffer + data_size, buffer, valread);
                        data_size += valread;
                        data_buffer[data_size] = '\0';
                    } else {
                        printf("DATA buffer overflow!\n");
                        send_response(client, "552 5.3.4 Error: message too large\r\n");
                        in_data = false;
                        // Сброс состояния
                        mail_from_received = false;
                        rcpt_to_received = false;
                        from[0] = '\0';
                        to[0] = '\0';
                        data_size = 0;
                        data_buffer[0] = '\0';
                        actual_subject[0] = '\0';
                    }
                }
            }
            continue;
        }
        
        // Убираем CRLF в конце команды для парсинга
        char command_buffer[BUFFER_SIZE];
        strncpy(command_buffer, buffer, sizeof(command_buffer));
        char* crlf = strstr(command_buffer, "\r\n");
        if (crlf) *crlf = '\0';
        
        // Парсим команду
        if (strncasecmp(command_buffer, "HELO", 4) == 0 || strncasecmp(command_buffer, "EHLO", 4) == 0) {
            char domain[256];
            if (sscanf(command_buffer + 5, "%255s", domain) == 1) {
                send_response(client, "250-oditynet.ru Hello %s\r\n", domain);
                send_response(client, "250-SIZE 36700160\r\n");
                send_response(client, "250-8BITMIME\r\n");
                send_response(client, "250-PIPELINING\r\n");
                send_response(client, "250-AUTH PLAIN LOGIN\r\n");
                send_response(client, "250 HELP\r\n");
            } else {
                send_response(client, "250 oditynet.ru Hello\r\n");
            }
        }
        else if (strncasecmp(command_buffer, "MAIL FROM:", 10) == 0) {
            // Парсим MAIL FROM команду
            char* start = strchr(command_buffer, '<');
            char* end = strchr(command_buffer, '>');
            
            if (start && end && start < end) {
                *end = '\0';
                strncpy(from, start + 1, sizeof(from) - 1);
                mail_from_received = true;
                printf("MAIL FROM parsed: %s\n", from);
                send_response(client, "250 2.1.0 OK\r\n");
                log_connection(client->use_ssl ? "SMTPS" : "SMTP", "MAIL_FROM", client);
            } else {
                send_response(client, "501 5.5.4 Syntax error in parameters\r\n");
            }
        }
        else if (strncasecmp(command_buffer, "RCPT TO:", 8) == 0) {
            // Парсим RCPT TO команду
            char* start = strchr(command_buffer, '<');
            char* end = strchr(command_buffer, '>');
            
            if (start && end && start < end) {
                *end = '\0';
                strncpy(to, start + 1, sizeof(to) - 1);
                printf("RCPT TO parsed: %s\n", to);
                
                // Проверяем существование пользователя для локальных адресов
                if (strstr(to, "@oditynet.ru") != NULL) {
                    pthread_mutex_lock(&db_mutex);
                    bool user_exist = db_user_exists(to);
                    pthread_mutex_unlock(&db_mutex);
                    
                    if (user_exist) {
                        rcpt_to_received = true;
                        send_response(client, "250 2.1.5 OK\r\n");
                        log_connection(client->use_ssl ? "SMTPS" : "SMTP", "RCPT_TO", client);
                    } else {
                        send_response(client, "550 5.1.1 User unknown\r\n");
                    }
                } else {
                    // Внешний адрес - всегда разрешаем
                    rcpt_to_received = true;
                    send_response(client, "250 2.1.5 OK - will attempt delivery\r\n");
                    log_connection(client->use_ssl ? "SMTPS" : "SMTP", "RCPT_TO_EXTERNAL", client);
                }
            } else {
                send_response(client, "501 5.5.4 Syntax error in parameters\r\n");
            }
        }
        else if (strncasecmp(command_buffer, "DATA", 4) == 0) {
            if (mail_from_received && rcpt_to_received) {
                in_data = true;
                send_response(client, "354 Start mail input; end with <CRLF>.<CRLF>\r\n");
                printf("Entering DATA mode\n");
            } else {
                send_response(client, "503 5.5.1 Error: need MAIL and RCPT commands\r\n");
            }
        }
        else if (strncasecmp(command_buffer, "QUIT", 4) == 0) {
            send_response(client, "221 2.0.0 oditynet.ru closing connection\r\n");
            break;
        }
        else if (strncasecmp(command_buffer, "RSET", 4) == 0) {
            mail_from_received = false;
            rcpt_to_received = false;
            from[0] = '\0';
            to[0] = '\0';
            data_size = 0;
            data_buffer[0] = '\0';
            in_data = false;
            actual_subject[0] = '\0';
            send_response(client, "250 2.0.0 OK\r\n");
            printf("RSET command received, state reset\n");
        }
        else if (strncasecmp(command_buffer, "NOOP", 4) == 0) {
            send_response(client, "250 2.0.0 OK\r\n");
        }
        else {
            send_response(client, "500 5.5.1 Command not recognized: %s\r\n", command_buffer);
        }
    }
    
    log_connection(client->use_ssl ? "SMTPS" : "SMTP", "DISCONNECT", client);
    close(client->socket);
    if (client->ssl) {
        SSL_free(client->ssl);
    }
    free(client);
    return NULL;
}

// Главная функция сервера
int main() {
    printf("Starting ODQ Mail Server...\n");
    
    // Загружаем конфигурацию
    if (!load_config()) {
        printf("Failed to load configuration from %s\n", CONFIG_FILE);
        return 1;
    }
    
    // Инициализируем OpenSSL
    init_openssl();
    
    // Инициализируем базу данных
    printf("Initializing database...\n");
    if (!db_init_database()) {
        printf("Failed to initialize database\n");
        return 1;
    }
    
    // Создаем сервисные учетные записи
    pthread_mutex_lock(&db_mutex);
    if (!db_user_exists(server_config.imap_service_user)) {
        //printf("%s\n",server_config.imap_service_user);
        db_register_user(server_config.imap_service_user, server_config.imap_service_password, 
                        "IMAP Service Account", "");
        printf("Created IMAP service account: %s\n", server_config.imap_service_user);
    }
    
    if (!db_user_exists(server_config.smtp_service_user)) {
        db_register_user(server_config.smtp_service_user, server_config.smtp_service_password, 
                        "SMTP Service Account", "");
        printf("Created SMTP service account: %s\n", server_config.smtp_service_user);
    }
    pthread_mutex_unlock(&db_mutex);
    
    // Проверяем наличие SSL сертификатов
    FILE* cert_file = fopen(server_config.ssl_cert_file, "r");
    if (!cert_file) {
	    printf("SSL certificate file not found: %s\n", server_config.ssl_cert_file);
        printf("Please generate SSL certificates\n");
        return 1;
    }
    fclose(cert_file);
    
    // Запускаем серверы в отдельных потоках
    pthread_t imap_thread, smtp_thread, imaps_thread, smtps_thread;
    
    if (pthread_create(&imap_thread, NULL, imap_server_thread, NULL) != 0) {
        perror("Failed to create IMAP thread");
        return 1;
    }
    
    if (pthread_create(&imaps_thread, NULL, imaps_server_thread, NULL) != 0) {
        perror("Failed to create IMAPS thread");
        return 1;
    }
    
    if (pthread_create(&smtp_thread, NULL, smtp_server_thread, NULL) != 0) {
        perror("Failed to create SMTP thread");
        return 1;
    }
    
    if (pthread_create(&smtps_thread, NULL, smtps_server_thread, NULL) != 0) {
        perror("Failed to create SMTPS thread");
        return 1;
    }
    
    printf("Mail server started successfully!\n");
    printf("IMAP server listening on %s:%d\n", server_config.imap_bind_addr, server_config.imap_port);
    printf("IMAPS server listening on %s:%d\n", server_config.imap_bind_addr, server_config.imaps_port);
    printf("SMTP server listening on %s:%d\n", server_config.smtp_bind_addr, server_config.smtp_port);
    printf("SMTPS server listening on %s:%d\n", server_config.smtp_bind_addr, server_config.smtps_port);
    printf("SMTP relay: %s:%d\n", server_config.smtp_relay_host, server_config.smtp_relay_port);
    
    // Ждем завершения потоков
    pthread_join(imap_thread, NULL);
    pthread_join(imaps_thread, NULL);
    pthread_join(smtp_thread, NULL);
    pthread_join(smtps_thread, NULL);
    
    // Очищаем ресурсы
    cleanup_openssl();
    close(imap_server_socket);
    close(imaps_server_socket);
    close(smtp_server_socket);
    close(smtps_server_socket);
    
    if (imap_ssl_ctx) SSL_CTX_free(imap_ssl_ctx);
    if (smtp_ssl_ctx) SSL_CTX_free(smtp_ssl_ctx);
    
    
    db_close_database();
    return 0;
}
