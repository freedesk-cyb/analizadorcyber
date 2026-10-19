FROM python:3.11-slim

WORKDIR /app

# Instalar Nmap + biblioteca de scripts NSE (requerido por network_analyzer / modo NSE)
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/* \
    && test -d /usr/share/nmap/scripts \
    && nmap --version

# Copiar e instalar dependencias
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el resto del código
COPY . .

# Exponer el puerto de FastAPI
EXPOSE 8000

# Comando para iniciar el servidor
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
