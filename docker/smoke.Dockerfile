# Minimal offline image for scheduler and graph integration tests.
FROM python:3.11-slim

WORKDIR /ctf
CMD ["sleep", "infinity"]
