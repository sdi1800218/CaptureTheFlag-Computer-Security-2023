## 2023 Project 2

Ο στόχος σας είναι να επιτεθείτε στον server `project-2.csec.chatzi.org`.
Γνωρίζετε ότι στο url http://project-2.csec.chatzi.org:8000
τρέχει o pico webserver, ο κώδικας του οποίου
υπάρχει στο [πακάτω repository](https://github.com/chatziko/pico).
Εχετε επίσης ήδη υποκλέψει:
- το username του site: `admin`
- το password: `8c6e2f34df08e2f879e61eeb9e8ba96f8d9e96d8033870f80127567d270d7d96`  
  (ο συγκεκριμένος webserver το δέχεται μόνο σε encrypted μορφή)

Tasks:

1. Βρείτε το MD5 digest του plaintext password
2. Βρείτε το plaintext password
3. Βρείτε το περιεχόμενο του αρχείου `/etc/secret` στον server
4. Βρείτε το αποτέλεσμα της εντολής `lspci` στον server


## Παρατηρήσεις
<details>
<summary> Touch me </summary>

- Οι ίδιες ομάδες με την εργασία 1
- Εγγραφή στο github: https://classroom.github.com/a/HxmDkdtS

- Η ταχύτητα επίλυσης __δεν__ έχει βαθμολογική σημασία, αλλά θα υπάρχει "leaderboard"
  με τους 3 πρώτους που λύνουν κάθε task καθαρά για λόγους "flexing". Αν είστε στους
  πρώτους στείλτε claim στο `ys13@chatzi.org` (αλλιώς δεν χρειάζεται).

- Τα βήματα μπορούν να λυθούν με οποιαδήποτε σειρά, δεν χρειάζεται
  η λύση του ενός για το επόμενο (αλλά προτείνεται η σειρά που δίνεται).

- Hints:
  - Task 1: πρέπει να χρησιμοποιήσετε μια απλή ευπάθεια στον C κώδικα
  - Task 2: πρέπει να σπάσετε το encryption χρησιμοποιώντας μια ευπάθεια της υλοποίησης. __Δεν__
       πρέπει να κάνετε invert το digest από το task 1 (δεν θα το βρείτε
       σε MD5 databases, εκτός και αν κάποια άλλη ομάδα το βρει και το προσθέσει).
  - Tasks 3/4: buffer overflow attack. Το attack στο task 4 είναι λίγο πιο δύσκολο (αν θέλετε μπορείτε να κάνετε τα δύο tasks μαζί, αλλά στο 3 υπάρχει και λίγο πιο εύκολη λύση).

- Βαθμολογία μαθήματος
    - Εργασία 1: 4 μονάδες
    - Εργασία 2:
      - Task 1: 1 μονάδα
      - Task 2: 1 μονάδα
      - Task 3: 2 μονάδες
      - Task 4: 1 μονάδα
      - Docker: 1 μονάδα

- Στο τέλος του `README.md`: αναφέρετε τις απαντήσεις, και περιγράψτε τα βήματα που ακολουθήσατε. Μην ξεχάσετε να κάνετε commit μαζί με οποιοδήποτε κώδικα χρησιμοποιήσατε.
    Για ό,τι δεν ολοκληρώσετε περιγράψτε (και υλοποιήστε στο πρόγραμμα) την πρόοδό σας και πώς θα μπορούσατε να συνεχίσετε.

- Για όλα τα βήματα απαιτείται να γράψετε ένα πρόγραμμα που να αυτοματοποιεί την εύρεση της λύσης.
  Μπορείτε να χρησιμοποιήσετε ό,τι γλώσσα προγραμματισμού θέλετε, αλλά θα πρέπει να μπορώ να το τρέξω
  σε Ubuntu 22.04 χρησιμοποιώντας software που είναι διαθέσιμο στο Ubuntu. Θα πρέπει επίσης
  να φτιάξετε ένα script `run.sh` που εκτελεί το πρόγραμμα με ό,τι παραμέτρους χρειάζονται.

- Η πλήρης λύση της εργασίας απαιτεί να φτιάξετε ένα Docker container που να αυτοματοποιεί πλήρως την επίθεση. Ένα script ουσιαστικά, που απλά να εκτελείται σε container
ώστε να μπορεί να τρέξει οπουδήποτε. Πάραδειγμα `Dockerfile` υπάρχει στο repository,
και θα πρέπει να τρέχει με:
  ```
  docker build --tag attack . && docker run attack
  ```
  Λύσεις χωρίς docker γίνονται δεκτές, απλά χάνετε 1 μονάδα.

- Deadline: __20/7__ (μέχρι το τέλος της ημέρας)
  - Μπορείτε να παραδώσετε την εργασία και το Σεπτέμβρη, με μόνη διαφορά
  ότι το docker τότε θα πιάνει 3 μονάδες γιατί έχετε παραπάνω χρόνο
  (και πάλι όμως μπορείτε να πάρετε 10).

- __Οχι spoilers__

- __Οχι DoS__ ή brute force. Μπορείτε να χρησιμοποιείτε scripts που να κάνουν μια επίθεση με έναν λογικό αριθμό από requests (να μπορεί να τελειώσει σε μία ώρα max). Aλλά όποιος βαράει στα τυφλά μηδενίζεται
   (θέλουμε οι servers να είναι accessible από όλους). Αν δεν είστε σίγουροι αν κάτι επιτρέπεται, απλά ρωτήστε.

- Είναι σαφώς προτιμότερο να υλοποιήσετε πρώτα όλα τα attacks locally πριν τα τρέξετε στον server.

- Ο pico server έχει γίνει compile στο `linux03.di.uoa.gr`, οπότε μπορείτε εκεί να φτιάξετε
  ένα executable ακριβώς σαν αυτό που εκτελείται στον server.

- Αν θέλετε hints ρωτήστε privately (χωρίς βαθμολογική συνέπεια, σε λογικά πλαίσια).

</details>

## Vulnerability Assessment Report

### Overview

In order to complete the above 4 tasks we are effectively asked to perform a vulnerability analysis and exploitation of the pico server project which is set up at the server domain we are given.  

Effectively this means we need to go through source code analysis and dynamic execution of the binary in order to achieve exploitation of the remote executable.

In order to achieve this we will need to specify our toolkit and protections active in the binary:

- The binary's protections:  
```gdb
Canary                        : ✓ (value: 0xcafebabe)
NX                            : ✓ 
PIE                           : ✓ 
Fortify                       : ✘ 
RelRO                         : Full
```

- Tools:
  - gdb (gef)
  - objdump
  - strace/ltrace
  - 
  - spidey sense


++ Maybe just describe the overall functionality of the binary

## TASK 1 -- Information Leak
------------------------------

**TARGET**: Find the MD5 digest of the admin user's password.

- The MD5 of the password is fetched from the `./config/htpasswd` file in the server's runtime.  
- Specifically when a GET request on root is received by the server, the [check_auth()](./pico/main.c#99L) function is executed.
- The parameter of that function is the Base64 encoded username and password in the `<username>:<password>` format which is passed via the GET request's HTTP Basic Auth header: `Authorization: Basic`.

We identify a format string vulnerability in the [check_auth()](./pico/main.c#99) function of `pico` server, where the code execution of the username provided is invalid (doesn't exist in the htpasswd file) the `printf()` function is called **without a format specifier**, but with the `auth_username` variable directly.
This allows us to input username strings that are format specifiers in C's `printf()`.

```c
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
```

- _(No assembly snippets are needed here since we have the actual source code and we can identify the vulnerability via code auditing)_.

- Here after we pass an invalid user in the base64 encoded Basic Auth string pair we get a message that informs us of the invalid username we gave.
- There we have a format string vulnerability in the `printf()`.  
- We can use that to leak information from the stack (!!!) or even write to arbitrary memory addresses.  
- Observing the pico server's runtime we figure out that the MD5 password value is on the 7th position in the stack when the vulnerable `printf()` is executed.  
- Formulate a base64 Auth string with `%7$s:hello` and perform a GET request at the root route of the server.

- We get back the MD5 hash of the password in the HTTP response.

```
Flag #1
MD5 HASH: ef281a07091268a0d779cf489d00380c
```

## TASK 2 -- Password Decryption
------------------------------

There are **3 ways** to get this flag:
1. The intended one is a padding oracle attack on `AES-128 CBC`.
2. The unintended is that the encryption key is stored in the `encryption_key` variable which is stored in the stack. We can use the format string vulnerability from Task 1 to extract the key.
3. The third way and trivial way is after completing [Task 3](#task-3----local-file-read) we can read the key file from the local filesystem.

### 1. Intended

A padding oracle is identified in the `check_auth()` function of the pico server. There, when the credential check is being performed, after the check of whether the username exists (and if does indeed exist) then the password is checked whether it's correct. Since we provide the password already encrypted as an **AES-128 CBC mode cyphertext** the password get's decrypted via the `decrypt()` function.

The logical bug that allows for the padding oracle lies exactly there, where if the padding is wrong then the server returns a 500 HTTP response code. While if the padding is okay but the password wrong then we get 401 code.

So, we can go through every single byte of the ciphertext and use the response codes as our oracle (a crypto side-channel gotcha essentially), exfiltrating one bit of info on every request.

The vulnerable code:
```c
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
```

More info on padding oracle cryptanalysis and the project used as a template to create the [cracking script](./pown/padding_oracles.py) can be found at the [padding oracle attack explained github repo](https://github.com/flast101/padding-oracle-attack-explained/).


### 2. Unintended

As we can see at the main function of pico the `encryption_key` is fetched and stored in a local variable.  
By supplying the payload `%60$s:hello` we find the location where the key is stored in the memory and leak it.

Then we create a decryptor program in C that utilizes the `decrypt()` function where we pass as parameters the key we extracted and the initial encrypted admin password we were provided.

```http
GET / HTTP/1.1
Host: project-2.csec.chatzi.org:8000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:103.0) Gecko/20100101 Firefox/103.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Authorization: Basic JTYwJHM6aGVsbG8=
Connection: close
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
```

```bash
# and in curl
curl http://project-2.csec.chatzi.org:8000/ -H 'Authorization: Basic JTY0JHM6aGVsbG8=' -v
```

### 3. Trivial

We can fetch the key file from `./config/key` and run the decryption process described in Solution 2.

```
Flag #2:
ENCRYPTION KEY: c56b2fa8d1a21183a185f7c1e526a0b8
PLAINTEXT PASSWORD: aCEDIsRateRe
```

## TASK 3 -- Local File Read
------------------------------

++ TODO: Content-length
++ TODO: Canary and threads
++ EBP and other dragons

Here we need to go a level deeper in our binary analysis to achieve the task.  
We start off by getting a sense of the protections of the binary.

### Context

- The general idea:  
The server hosted at the target address is the same pico server that we can compile locally. Since we know the execution environment of it we can deduce certain things for it's runtime.


### Analysis

- The pico server is made in such a way as to handle HTTP POST and GET requests by fork()ing to different children that perform the actual handling. Since our case in point.

We already have a format string vulnerability identified in the executable which we know how to trigger. This allows us to extract information for the context of execution of the binary. We can leak an incredible amount of stack values which in x86 are gonna be very useful since they encapsulate what has been pushed in the stack on runtime.

In order to capitalize on this we need to identify a second vulnerability which allows us to redirect the execution.

### POST -- post_param
------------------------------

1. Content-length
2. Bof
3. canary, libc base, ebp, 
We can perform a buffer overflow attack on 

In the pico servers code, we identify an HTTP POST route which `post_param()`

```
Flag #3:
[ascii art] + You guessed it... puppies!
```

### Attack Layout

- Leak necessary info from the stack
- Use the post_data bof
- Redirect execution to the send_file function
- Handle runtime behaviour and load the filename as the function's argument

### TASK 4 -- lspci aka Remote Command Execution
------------------------------
**Target:** Remote Code Execution on the remote server

2 RCE solutions:
1. Glibc's `system()` function redirection
2. ROPchain via glibc gadgets to execve single commands (like one word coammnds with no params)

```
Flag #4:
00:00.0 Host bridge: Intel Corporation 440FX - 82441FX PMC [Natoma]
00:01.0 ISA bridge: Intel Corporation 82371SB PIIX3 ISA [Natoma/Triton II]
00:01.3 Non-VGA unclassified device: Intel Corporation 82371AB/EB/MB PIIX4 ACPI (rev 08)
00:03.0 VGA compatible controller: Amazon.com, Inc. Device 1111
00:04.0 Non-Volatile memory controller: Amazon.com, Inc. Device 8061
00:05.0 Ethernet controller: Amazon.com, Inc. Elastic Network Adapter (ENA)
```