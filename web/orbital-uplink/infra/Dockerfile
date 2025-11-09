FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# app files
COPY . .

# create runtime dirs
RUN mkdir -p instance uploads

RUN echo "csawctf{5p4c3_mY573ry_r00t_up11nk_4040712f45886c74e395cd976c91b573}" > flag.txt \
    && chmod 444 flag.txt

# add start script
COPY start.sh /start.sh
RUN chmod +x /start.sh

EXPOSE 5001
ENV FLASK_ENV=production
ENV SECRET_KEY="689d887e-6941-35e69c84ecc1"

CMD ["/start.sh"]
