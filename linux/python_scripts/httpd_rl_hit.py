
import time
from collections import defaultdict

# Configuration
ACCESS_LOG = "/usr/local/apache2/logs/access_log"
RATE_LIMIT = 10  # requests per second
TIME_WINDOW = 1  # in seconds

# In-memory store for IP requests
ip_requests = defaultdict(list)

def follow(thefile):
    """Generator function that yields new lines in a file."""
    thefile.seek(0, 2)  # Go to the end of the file
    while True:
        line = thefile.readline()
        if not line:
            time.sleep(0.1)  # Sleep briefly
            continue
        yield line

if __name__ == "__main__":
    print(f"Monitoring log file: {ACCESS_LOG}")
    print(f"Rate limit set to {RATE_LIMIT} requests per {TIME_WINDOW} second(s).")

    try:
        with open(ACCESS_LOG, 'r') as logfile:
            loglines = follow(logfile)
            for line in loglines:
                try:
                    # Extract IP address (usually the first part of the log line)
                    ip_address = line.split()[0]
                    current_time = time.time()

                    # Get the list of timestamps for the current IP
                    timestamps = ip_requests[ip_address]

                    # Remove timestamps older than the time window
                    timestamps = [t for t in timestamps if current_time - t <= TIME_WINDOW]

                    # Add the new request's timestamp
                    timestamps.append(current_time)
                    ip_requests[ip_address] = timestamps

                    # Check if the rate limit is exceeded
                    if len(timestamps) > RATE_LIMIT:
                        print(f"Rate limit exceeded for IP: {ip_address}")

                except IndexError:
                    # Handle empty or malformed lines
                    continue
    except FileNotFoundError:
        print(f"Error: Log file not found at {ACCESS_LOG}")
    except KeyboardInterrupt:
        print("\nMonitoring stopped.")


