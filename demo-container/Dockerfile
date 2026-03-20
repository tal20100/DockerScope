# Base image
FROM ubuntu:22.04

# Install basic tools
RUN apt-get update && apt-get install -y curl iputils-ping

# Example dangerous mount simulation (we won't mount /host באמת)
VOLUME /test_mount

# Expose ports
EXPOSE 8080 22

# Run a simple service to keep container alive
CMD ["sleep", "infinity"]