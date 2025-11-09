# -------- STAGE 1: Build binaries --------
FROM python:3.11-slim-bookworm as builder

# Install build tools
RUN apt-get update
RUN apt-get install -y gcc make

# Install PyInstaller
RUN pip install --no-cache-dir pyinstaller phe

# Copy source files
WORKDIR /build

# Compiling .py scripts to executibles

COPY ship_ai.py .
RUN pyinstaller --onefile ship_ai.py
RUN rm ship_ai.py

COPY navcomp.sh navcomp

COPY gen_keys.py .
RUN pyinstaller --onefile gen_keys.py
RUN rm gen_keys.py

COPY initial_jump.py .
RUN pyinstaller --onefile initial_jump.py
RUN rm initial_jump.py

COPY pallier_key_reader.py .
RUN pyinstaller --onefile pallier_key_reader.py
RUN rm pallier_key_reader.py

COPY pallier_jump_instr_encr.py .
RUN pyinstaller --onefile pallier_jump_instr_encr.py
RUN rm pallier_jump_instr_encr.py

COPY pallier_jump_instr_decr.py .
RUN pyinstaller --onefile pallier_jump_instr_decr.py
RUN rm pallier_jump_instr_decr.py

# -------- STAGE 2: Final runtime container --------
FROM debian:bookworm-slim
    
# Make sure we have a minimal set of needed tools
RUN apt-get update && apt-get install -y ca-certificates

# Create users and entities
RUN useradd -m -u 66 comnavcent
RUN useradd -m -u 404 pilot -g comnavcent
RUN useradd -m -u 1977 -g comnavcent security

RUN rm -rf /home/pilot

WORKDIR /ship-core

# Moving startup script to /ship-core, executible
COPY startup.sh startup
RUN chmod +x startup

# Copy compiled binaries from build to ship-core
COPY --from=builder /build/dist/gen_keys /ship-core/gen_keys
COPY --from=builder /build/dist/initial_jump /ship-core/initial_jump
COPY --from=builder /build/dist/pallier_key_reader /ship-core/pallier_key_reader
COPY --from=builder /build/dist/pallier_jump_instr_encr /ship-core/pallier_jump_instr_encr
COPY --from=builder /build/dist/pallier_jump_instr_decr /ship-core/pallier_jump_instr_decr
 
COPY --from=builder /build/dist/ship_ai /ship-core/ship_ai
COPY --from=builder /build/navcomp /ship-core/navcomp

# Move docs to /ship-core
COPY docs /ship-core/docs

# Comnavcent owns ship-core
RUN chown -R comnavcent:comnavcent /ship-core

# Make navcomp executible
RUN chmod +x /ship-core/navcomp

RUN chmod -R go-w /ship-core \
&& chmod 755 /ship-core \
&& find /ship-core -xdev -type d -exec chmod 755 {} + \
&& find /ship-core -xdev -type f -exec chmod 555 {} +

# root required to run startup
USER root

RUN apt-get install -y socat

EXPOSE 21009
# Run Startup
CMD socat -T60 TCP-LISTEN:21009,reuseaddr,fork EXEC:"/ship-core/startup,pty,stderr,setsid,sigint,sane,echo=0"
