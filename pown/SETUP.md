1. Ssh into linux03.di.uoa.gr
2. Start the server binary via gdb -> `gdb ./server` and constantly toggle `set follow-fork-mode child`
3. port forward via `ssh -L 8321:localhost:8321 user@linux03.di.uoa.gr`