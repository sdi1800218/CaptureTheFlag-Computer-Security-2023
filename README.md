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

All stages of the above tasks can be found in the [Proof of Concept exploit script](./pown/exploit.py) tucked nicely in sections.

In order to achieve this we will need to specify our toolkit and protections active in the binary:

### Binary Protections:  
```gdb
Canary                        : ✓ (value: 0xcafebabe)
NX                            : ✓ 
PIE                           : ✓ 
Fortify                       : ✘ 
RelRO                         : Full
```


1. **Canary**: A canary, also known as a stack protector, is a security mechanism used to detect buffer overflow attacks. It involves placing a random value (often called a canary) before the return address on the stack. If a buffer overflow occurs and the canary value is modified, an error will be triggered, indicating a possible attack. The canary value acts as a guard to protect the integrity of the stack. In the provided example, the canary value is 0xcafebabe.

2. **NX (No-Execute)**: NX or DEP (Data Execution Prevention) is a hardware or software feature that prevents the execution of data in certain regions of memory. It helps prevent buffer overflow and code injection attacks by marking certain memory pages as non-executable. This means that even if an attacker manages to inject malicious code into memory, it cannot be executed. The NX protection is enabled in the given example.

3. **PIE (Position Independent Executable)**: is a security feature that randomizes the base address of an executable at runtime. It prevents attackers from predicting the memory layout of the program, making it harder to exploit certain types of vulnerabilities, such as return-oriented programming (ROP) attacks. PIE ensures that the executable code, libraries, and data are loaded at different addresses each time the program is run. In the provided example, PIE protection is enabled.

4. **Fortify**: is a set of security enhancements provided by the GNU C Library (glibc) to make C programs more resistant to common security vulnerabilities, such as buffer overflows, format string vulnerabilities, and integer overflows. It provides additional checks and protections to detect and prevent these vulnerabilities at runtime. In the given example, Fortify protection is not enabled (marked as "✘").

5. **RelRO (Relocation Read-Only)**: is a memory protection mechanism that makes certain sections of an executable read-only after the dynamic linker has resolved all necessary relocations. It helps prevent certain types of attacks, such as overwriting function pointers or the Global Offset Table (GOT). The "Full" status indicates that all relevant sections have been made read-only. This provides stronger protection compared to partial RelRO.


### Toolkit

Necessary for analysis and exploitation are the following:
1. gdb (gef): for dynamic analysis of the server's behavior
2. objdump: to get the offsets of addresses
3. strace/ltrace: to observe the behavior of system calls and C library function calls during execution.
4. ROPGadget: for the ROPchain present in Task 4 solution.

### Context

++ (Overall behavior and protections and how to defeat them)

## TASK 1 -- Information Leak


**TARGET**: Find the MD5 digest of the admin user's password.

- The MD5 of the password is fetched from the `./config/htpasswd` file in the server's runtime.  
- Specifically when a GET request on root is received by the server, the [check_auth()](./pico/main.c#99L) function is executed.
- The parameter of that function is the Base64 encoded username and password in the `<username>:<password>` format which is passed via the GET request's HTTP Basic Auth header: `Authorization: Basic`.

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

_(No assembly snippets are needed here since we have the actual source code and we can identify the vulnerability via code auditing)_.

- We identify a format string vulnerability in the [check_auth()](./pico/main.c#99) function of `pico` server, where the code execution of the username provided when it is invalid (doesn't exist in the htpasswd file) the `printf()` function is called **without a format specifier**, but with the `auth_username` variable directly.
- This allows us to input username strings that are format specifiers in C's `printf()`.
- We can use that to leak information from the stack (!!!) or even write to arbitrary memory addresses.  
- Observing the pico server's runtime we figure out that the MD5 password value is on the 7th position in the stack when the vulnerable `printf()` is executed.
- Formulate a base64 Auth string with `%7$s:hello` and perform a GET request at the root route of the server.
- We get back the MD5 hash of the password in the HTTP response.



```
Flag #1
MD5 HASH: ef281a07091268a0d779cf489d00380c
```

### More on Format String Vulnerabilities and exploitation:
- [Format Strings 101](https://axcheron.github.io/exploit-101-format-strings/)
- [pwn.college::Format String Chapter](https://pwn.college/cse494-s2023/format-string-exploits)

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

Then we create a [decryptor program](./pico/encryption/decrypt.c) in C that utilizes the `decrypt()` function where we pass as parameters the key we extracted and the initial encrypted admin password we were provided.

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
**Target**: ret2win, with the win function being the already existing gift of `send_file()` in pico's codebase.

### Analysis

- The pico server is made in such a way as to handle HTTP POST and GET requests by fork()ing to different children that perform the actual handling of the request. This is awesome because the context of execution of the parent gets copied over to the child, which means that if we compromise the libc base, canary or stack values of a child, they are the same for the parent server as well as all other children.

Using our Info Leak vulnerability from [Task 1](#task-1----information-leak), we can leak an incredible amount of stack data which in x86 are gonna be very useful since they encapsulate what has been pushed in the stack on runtime.

Additionally, the developer of pico has been so kind to provide us with a win function to achieve our goal. That function is present in the codebase and is called `send_file()` and given a single argument which is the name and path of a file it returns its contents to us.

In order to capitalize on the above we need to identify a second vulnerability which allows us to redirect the execution of the server.

### Buffer Overflow on post_param()
------------------------------

POST requests to the root of the server are handled via the [post_param](./pico/main.c#174) function. Here it's trivial to identify that the memory handling is erroneous since it can lead to a buffer overflow.

First, the value of the `payload_size` variable can be tampered which results in a buffer much smaller than the payload, allowing us to overwrite data after the buffer in the stack. This allows us to rewrite the return address of the post_param() function and redirect execution.

Secondly, the implementation of pico has a logical error while parsing HTTP headers, where for the `Content-Length` header takes the value provided a verbatim. Usually, this header is auto-filled by the client that performs the HTTP request (browser, curl, etc.) but can also be manually assigned by hand. HTTP servers are also prepared to cross-check the size of data and the `Content-Length` value and correct it. In this case though, if the header is present pico trusts it explicitly and assigns the value provided to the `payload_size` variable.

So having the above in place we can perform a BOF attack against pico and redirect the execution via a POST request.

### Attack Layout

1. Leak necessary info from the stack
2. Use the `post_param()` buffer overflow
3. Redirect execution to the `send_file()` function

### Payload and Exploitation

canary, ebp, route-rel addr

After identifying the vulnerability now we can put everything together and craft a payload that exploits the binary. For testing, [the directions here were used](./pown/SETUP.md).

|  'A'   |  Filename + 'B'  |  Buffer  |  'C'   |  Canary  |  EBP Original x3 |  send_file()  |  Junk  |  Buffer  |
|:------:|:----------------:|:--------:|:------:|:--------:|:--------------:|:-------------:|:------:|:--------:|
| 12 bytes | len(filename) + len('B') (40 bytes total)| 4 bytes | 4 bytes | 4 bytes | 3x4 bytes | 4 bytes | 4 bytes | 4 bytes |

- The distance from the start of our saved buffer until overwriting the return address of the function (in the stack) is 76 bytes. On the way there certain things need to be setup.

- Caveats:
  1. We need to the filename we want to read, somewhere in our payload and point to it's address in the stack.
  2. The canary value is needed to avoid stack smashing detection.
  3. The original value of the `ebp` (base pointer) register is needed to be used for the execution to proceed properly.
  4. The address of our buffer goes 2 stack frames after the overwritten value of the return address (arguments in x86).

Having the above in mind, our payload takes the above format, by virtue of chance with whatever gadgets we can print out using our info leak exploit. A [special helper script](./print_stacks.sh) was used, which prints out the stack via the info leak. A friendly gdb session can cross-check which values are to be used.

Multiple variations of the payload can come up, but here the following were used:
1. A `route()` address leak was used to calculate the address of `send_file()` in order to defeat PIE. 
2. An ad-hoc address of the buffer could be obtained, hence why the filename is provided on the 4th frame.

- The whole info leak:
`libc.%23$p canary.%27$p buffer.%30$p route()ret.%31$p:hello`

```
Flag #3:
[ascii art] + You guessed it... puppies!
```

## TASK 4 -- RCE
------------------------------
**Target:** Remote Code Execution (RCE) on the remote server

- **2 ways to achieve RCE**, both of which require knowledge of the Glibc version which the binary is using.

We can identify that the Glibc version is 2.31 via sorcery and proceed with leaking a relative libc address via our Task 1 Info Leak from the stack. We can calculate the offset this libc address has from the libc base and then be able to calculate ad hoc any address we want in the libc of the binary.

++ Illustration

### 1. Glibc's `system()` function

- [Phrack Advanced libc exploitation](http://phrack.org/issues/58/4.html)

The most trivial way would be to build upon our Task 3 execution redirection, but instead of `ret`ing to the `send_file()` function we could redirect execution to libc's `system()` function.

_(Experimental version implemented according to "theory" but non-working during execution after the redirection to system() is successful.)_

### 2. ROPchain via glibc gadgets to execve commands without parameters

We can utilize the concept of Return Oriented Programming and create a chain of execution after the first jump from the overwritten return address of `post_param()` that imitates a system call in x86.

Specifically, we would like to imitate the following assembly sequence:

```as
      /* execve(path='ebx', argv='ecx', envp='edx') */
      mov ebx, edi
      xor ecx, ecx     /* arguments */
      xor edx, edx     /* NULL env */
      /* call execve() */
      push SYS_execve /* 0xb */
      pop eax
      int 0x80
```

To achieve the above concept we can reuse `pop-ret gadgets` present in the libc 2.31 and emulate the above behavior.

Our ROPchain fills the `eax` register with the system call number on x86, `edx` must be NULLed out, and `ebx` contains the address of our buffer whiuch contains the command string. Because we NULL out the env parameter the full path of the command we want to run must be used (i.e `ls` won't work, but `/bin/ls` will).

Additionally, `ecx` contains the arguments of our command, i.e `ls -al`, the `-al` part should be in the address pointed by `ecx`. Attempts on this was made, but in x86 the manual setting of the argument buffer is a bit tricky. On x86-64 this would be straightforward since we would just use the push-push nature of the stack to set everything proper.

At last, this is an RCE but only PoC since the commands are executed very narrowly (without arguments).


- Resources on the Return Oriented Programming technique:
1. [ROPEmporium's Intro](https://ropemporium.com/guide.html)
2. [ROP FTW](https://www.exploit-db.com/docs/english/28479-return-oriented-programming-(rop-ftw).pdf)
3. [pwn.college ROP resources](https://pwn.college/cse494-s2023/return-oriented-programming)

```
Flag #4:
00:00.0 Host bridge: Intel Corporation 440FX - 82441FX PMC [Natoma]
00:01.0 ISA bridge: Intel Corporation 82371SB PIIX3 ISA [Natoma/Triton II]
00:01.3 Non-VGA unclassified device: Intel Corporation 82371AB/EB/MB PIIX4 ACPI (rev 08)
00:03.0 VGA compatible controller: Amazon.com, Inc. Device 1111
00:04.0 Non-Volatile memory controller: Amazon.com, Inc. Device 8061
00:05.0 Ethernet controller: Amazon.com, Inc. Elastic Network Adapter (ENA)
``` 