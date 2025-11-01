
import os
import time
import re

files_to_monitor = {
    "/var/log/auth.log": [
        r"Failed password"
    ],
    "/var/log/vsftpd.log": [
        r"FAIL LOGIN"
    ]
}

def monitor_files(files):
    """Monitors files for changes and prints lines matching patterns."""
    file_positions = {}
    for file_path in files:
        try:
            file_positions[file_path] = os.path.getsize(file_path)
        except FileNotFoundError:
            print(f"Warning: {file_path} not found. Will monitor if it appears.")
            file_positions[file_path] = 0

    print("Monitoring files for changes...")
    try:
        while True:
            time.sleep(1)
            for file_path, patterns in files.items():
                try:
                    current_size = os.path.getsize(file_path)
                except FileNotFoundError:
                    continue

                last_position = file_positions.get(file_path, 0)

                if current_size < last_position:
                    # File was truncated or rotated
                    last_position = 0

                if current_size > last_position:
                    with open(file_path, 'r') as f:
                        f.seek(last_position)
                        new_lines = f.readlines()
                        for line in new_lines:
                            for pattern in patterns:
                                if re.search(pattern, line):
                                    print(f"[{os.path.basename(file_path)}] {line.strip()}")
                                    break
                    file_positions[file_path] = current_size

    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.")

if __name__ == "__main__":
    monitor_files(files_to_monitor)