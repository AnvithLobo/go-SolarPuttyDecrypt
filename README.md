# go-SolarPuttyDecrypt
 SolarPutty's sessions files decryptor / bruteforce

![-----------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/rainbow.png)

## ➤ Build

```console
git clone https://github.com/AnvithLobo/go-SolarPuttyDecrypt
cd go-SolarPuttyDecrypt
go mod tidy
go build
```

## ➤ Usage

```console
./go-SolarPuttyDecrypt -h

Usage of ./go-SolarPuttyDecrypt:
  -password string
        Password to decrypt the session file
  -session string
        SolarPutty session file path [required]
  -threads int
        Number of threads to use (default 16)
  -wordlist string
        Wordlist file path

```

## ➤ Example

```console
./go-SolarPuttyDecrypt -session sessions-backup.dat -wordlist wordlist.txt

-----------------------------------------------------
SolarPutty's Sessions Bruteforce Decrypter in go
-----------------------------------------------------
[0.65% done] [93775/14344393] [16162 p/s] Trying: misperros

```

```console
./go-SolarPuttyDecrypt -session sessions-backup.dat -password password

-----------------------------------------------------
SolarPutty's Sessions Bruteforce Decrypter in go
-----------------------------------------------------
password: password
  ->
{
    "AuthScript": [],
    "Credentials": [
        {
            "CredentialsName": "instant-root",
            "Id": "452ed919-530e-419b-b721-da76cbe8ed04",
            "Passphrase": "",
            "Password": "123456789",
            "PrivateKeyContent": null,
            "PrivateKeyPath": "",
            "Username": "root"
        }
    ],
    "Groups": [],
    "LogsFolderDestination": "C:\\ProgramData\\SolarWinds\\Logs\\Solar-PuTTY\\SessionLogs",
[...SNIP...]
}

-----------------------------------------------------
```

## ➤ Credits

https://github.com/VoidSec/SolarPuttyDecrypt
https://voidsec.com/solarputtydecrypt/
