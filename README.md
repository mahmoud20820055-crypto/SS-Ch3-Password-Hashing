# Password Hashing with Salt (SHA-256)

Software Security (SDEV 4303) – Chapter 03: User Authentication  
Student: Mahmoud Basel AL-Juaidi – 120230589

A small Python program that:

* **Registers** users by storing `username:salt:SHA-256(password + salt)` in `users.txt`
  (the salt is 16 random bytes from `secrets`).
* **Logs in** users by re-computing the hash with the stored salt and comparing it
  (constant-time comparison with `hmac.compare_digest`).

## Run

```bash
python3 password_hashing.py
```

No external libraries are needed (Python 3.6+).
