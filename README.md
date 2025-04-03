# Usage

1. Linux Environment (WSL/VMware/VitualBox)
2. install ngrok
3. install minianaconda
4. git clone https://github.com/cocaoreo/secure_coding
5. conda env create -f environment.yaml
6. openssl req -new -newkey rsa:2048 -nodes -keyout https.key -x509 -days 365 -out https.crt
7. python app.py

you must add Admin on DB. you cannot register as Admin on website.