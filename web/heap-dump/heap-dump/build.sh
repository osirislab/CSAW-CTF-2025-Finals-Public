docker build -t heap-dump .
docker run -p 8080:8080 -p 5432:5432 heap-dump