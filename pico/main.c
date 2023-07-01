#include "httpd.h"
#include "base64.h"
#include "encryption/encryption.h"
#include "assert.h"
#include "stdlib.h"
#include <openssl/md5.h>

typedef char Line[100];  // use lines of 100 chars max
Line encryption_key;
Line htpasswd[100];      // contents of /etc/htpasswd, max 100 entries, format is <username>:<password-md5>

void read_file(char* filename, Line lines[], int max_lines);
int check_auth(Line[], char*);
char* post_param(char* param_name );
void serve_index();


int main(int c, char **v) {
  // default accout: test/test (encrypted: 029794db6e76cb559613732d7c94b24b360bb6f05879bb99e7765518b55abc57)
  read_file("./config/htpasswd", htpasswd, 100);
  read_file("./config/key", &encryption_key, 1);

  serve_forever("8000");
  return 0;
}

void route() {
  // HTTP Basic Auth, seems to work.
  // TODO: gcc 7 gives warnings, check
  header_t *h = request_headers();
  while (h->name && strcmp(h->name, "Authorization") != 0)
    h++;

  if(h->name) {
    // Authorization header found, check it
    if(!check_auth(htpasswd, h->value))
      return;

  } else {
    // no Authorization header, return 401
    printf("HTTP/1.1 401 Unauthorized\r\n");
    printf("WWW-Authenticate: Basic realm=\"");
    printf("Enter username/password");
    printf("\"\r\n\r\n");
    return;
  }

  ROUTE_START()

  ROUTE_GET("/") {
    serve_index();
  }
  
  ROUTE_GET("/test") {
    printf("HTTP/1.1 200 OK\r\n\r\n");
    printf("List of request headers:\r\n\r\n");

    header_t *h = request_headers();

    while (h->name) {
      printf("%s: %s\n", h->name, h->value);
      h++;
    }
  }

  ROUTE_POST("/") {
    printf("HTTP/1.1 200 OK\r\n\r\n");
    printf("Wow, seems that you POSTed %d bytes. \r\n", payload_size);
    printf("Fetch the data using `payload` variable.");

    char* test = post_param("test");
    if(test)
      printf("Test param: %s\n", test);
  }

  ROUTE_END()
}

// Read at most max_lines lines from filename and store in lines[] array
void read_file(char* filename, Line lines[], int max_lines) {
  FILE *file = fopen(filename, "r");
  assert(file);

  int i;
  for(i = 0; i < max_lines && fgets(lines[i], sizeof(Line), file); i++)
    lines[i][strlen(lines[i])-1] = '\0'; // strip newline
  lines[i][0] = '\0'; // finish with empty string
  fclose(file);
}

// returns str's md5 in hex form in md5
void md5_hex(char *str, char *md5) {
  unsigned char md5_bin[16]; // 128bits=16 bytes
  MD5(str, strlen(str), md5_bin);
  for(int i = 0; i < 16; i++)  // 16 hex chars
    sprintf(md5 + 2*i, "%02x", md5_bin[i]);
}

int check_auth(Line users[], char *auth_header) {
  // auth_header contains "Basic <Base64>", extract <Base64> string and decode in auth_decoded
  unsigned char *auth_decoded;
  int length;
  Base64Decode(auth_header+6, &auth_decoded, &length); // +6 to skip "Basic "
  
  // auth_decoded is of the form "<username>:<password>", separate them
  char *auth_username = auth_decoded;         // username is at the start
  char *colon = strchr(auth_decoded, ':');    // find ':'
  if(colon != NULL)
    *colon = '\0';                            // change to \0 to split the string in two
  char *auth_password_enc = colon ? colon+1 : ""; // password starts after the colon

  // find auth_username in users (each line is <user>:<md5>)
  char *password_md5 = NULL;
  int ul = strlen(auth_username);
  for(int i = 0; strcmp(users[i], "") != 0; i++) {
    if(strncmp(users[i], auth_username, ul) == 0 && users[i][ul] == ':') {
      password_md5 = users[i] + ul + 1; // <md5> part, after the ':'
      break;
    }
  }

  // check if user is found
  if(password_md5 == NULL) {
    printf("HTTP/1.1 401 Unauthorized\r\n");
    printf("WWW-Authenticate: Basic realm=\"");
    printf("Invalid user: ");
    printf(auth_username);
    printf("\"\r\n\r\n");

    free(auth_decoded);
    return 0;
  }

  // since we run over http, the user should provide the password encrypted.
  // we decrypt here.
  char *auth_password = decrypt(encryption_key, auth_password_enc);
  fprintf(stderr, "decrypted: %s\n", auth_password);
  if (!auth_password) {
    printf("HTTP/1.1 500 Internal Server Error\r\n");

    free(auth_password);
    return 0;
  }

  // check password's md5
  char auth_password_md5[33];
  md5_hex(auth_password, auth_password_md5);
  free(auth_password);

  if(strcmp(password_md5, auth_password_md5) != 0) {
    printf("HTTP/1.1 401 Unauthorized\r\n");
    printf("WWW-Authenticate: Basic realm=\"");
    printf("Invalid password");
    printf("\"\r\n\r\n");

    free(auth_decoded);
    return 0;
  }

  free(auth_decoded);
  return 1; // both ok
}

void send_file(char *filename) {
  FILE *file = fopen(filename, "r");
  char buf[1024];
  int buflen;
  while((buflen = fread(buf, 1, 1024, file)) > 0)
    fwrite(buf, 1, buflen, stdout);
  fclose(file);
}

// Parses and returns (in new memory) the value of a POST param
char* post_param(char* param_name) {
  // These are provided by pico:
  //  payload      : points to the POST data
  //  payload_size : the size of the paylaod

  // The POST data are in the form name1=value1&name2=value2&...
  // We need NULL terminated strings, so change '&' and '=' to '\0'
  // (copy first to avoid changing the real payload).

  char post_data[payload_size+1];     // dynamic size, to ensure it's big enough
  strcpy(post_data, payload);

  for (char* c = post_data; *c != '\0'; c++)
    if (*c == '&' || *c == '=')
      *c = '\0';

  // Now loop over all name=value pairs
  char* value;
  for (
    char* name = post_data;
    name < &post_data[payload_size];
    name = &value[strlen(value) + 1]      // the next name is right after the value
  ) {
    value = &name[strlen(name) + 1];      // the value is right after the name
    if (strcmp(name, param_name) == 0)
      return strdup(value);
  }

  return NULL;   // not found
}

void serve_index() {
    printf("HTTP/1.1 200 OK\r\n\r\n");
    send_file("./www-root/index.html");
}
