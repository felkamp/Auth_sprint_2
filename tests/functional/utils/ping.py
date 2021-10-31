import logging
import os
import socket
import sys
import time

logging.basicConfig(level=logging.INFO)


def ping(host: str, port: int, max_number_of_attempts: int = 10) -> bool:
    number_of_attempts = 0
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        while number_of_attempts < max_number_of_attempts:
            try:
                number_of_attempts += 1
                sock.connect((host, port))
            except socket.error:
                logging.error("Trying to connect to %s", host)
                time.sleep(2)
            else:
                logging.info(f"Connected to {host}:{port}")
                return False
    logging.error(f"Maximum number of attempts exceeded")
    return True


def main() -> int:
    has_errors = ping(
        os.getenv("REDIS_HOST", "redis"), int(os.getenv("REDIS_PORT", 6379))
    )
    return int(has_errors)


if __name__ == "__main__":
    sys.exit(main())
