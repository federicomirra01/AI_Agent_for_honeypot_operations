FROM vulhub/docker:28.0.1

# Create a directory and write the flag
RUN mkdir -p /home/ctf && \
    echo "flag{first_stage_compromised}" > /home/ctf/user.txt && \
    chmod 400 /home/ctf/user.txt && \
    chown root:root /home/ctf/user.txt

LABEL maintainer="phithon <root@leavesongs.com>"

COPY docker-entrypoint.sh /

ENTRYPOINT [ "/docker-entrypoint.sh" ]
