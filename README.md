keep
====

`keep` is a very simple tool that lets you encrypt files with a passphrase.

It uses strong cryptographic primitives so the files are as secure as your
passphrase.

Use at own risk.

Examples
--------

Encrypt the file `mysecrets.txt` into `mysecrets.txt.keep`:

```bash
keep mysecrets.txt
```

Same, but delete the original file:

```bash
keep -d mysecrets.txt
```

Decrypt the file `mysecrets.txt.keep` into `mysecrets.txt`:

```bash
keep mysecrets.txt.keep
```

