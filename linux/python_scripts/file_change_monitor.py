import os
import time
import re
import subprocess
import threading

files_to_monitor = {
    "/var/log/auth.log": [
        r"Failed password"
    ],
    "/var/log/vsftpd.log": [
        r"FAIL LOGIN"
    ]
}

def run_command(command):
    """Runs a command and prints its output."""
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(result.stdout)
        if result.stderr:
            print(result.stderr)
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        print(e.stderr)

def monitor_files(files, stop_event):
    """Monitors files for changes in a background thread."""
    file_positions = {}
    for file_path in files:
        try:
            file_positions[file_path] = os.path.getsize(file_path)
        except FileNotFoundError:
            print(f"\nWarning: {file_path} not found. Will monitor if it appears.")
            file_positions[file_path] = 0

    print("\nMonitoring files for changes...")
    while not stop_event.is_set():
        for file_path, patterns in files.items():
            try:
                current_size = os.path.getsize(file_path)
            except FileNotFoundError:
                continue

            last_position = file_positions.get(file_path, 0)

            if current_size < last_position:
                last_position = 0

            if current_size > last_position:
                with open(file_path, 'r') as f:
                    f.seek(last_position)
                    new_lines = f.readlines()
                    for line in new_lines:
                        for pattern in patterns:
                            if re.search(pattern, line):
                                print(f"\n[{os.path.basename(file_path)}] {line.strip()}\n> ", end="")
                                break
                file_positions[file_path] = current_size
        time.sleep(1)

def print_help():
    """Prints the help message for the interactive console."""
    print("\nAvailable commands:")
    print("  block <ip> [port|*] - Block an IP. Defaults to all ports if none is specified.")
    print("  unblock <ip> [port|*] - Unblock an IP. Defaults to all ports if none is specified.")
    print("  list                - List all active UFW rules.")
    print("  help                - Show this help message.")
    print("  exit                - Stop the script and monitoring.")

def main():
    """Main function to run the interactive console and file monitor."""
    stop_event = threading.Event()
    monitor_thread = threading.Thread(target=monitor_files, args=(files_to_monitor, stop_event))
    monitor_thread.start()

    print_help()

    try:
        while True:
            try:
                user_input = input("\n> ").strip().split()
                if not user_input:
                    continue

                command = user_input[0].lower()

                if command == 'block':
                    if len(user_input) < 2:
                        print("Usage: block <ip> [port|*]")
                        continue
                    ip = user_input[1]
                    port = user_input[2] if len(user_input) > 2 else '*'
                    if port == '*':
                        run_command(f"sudo ufw insert 1 deny from {ip} to any")
                    else:
                        run_command(f"sudo ufw insert 1 deny from {ip} to any port {port}")
                elif command == 'unblock':
                    if len(user_input) < 2:
                        print("Usage: unblock <ip> [port|*]")
                        continue
                    ip = user_input[1]
                    port = user_input[2] if len(user_input) > 2 else '*'
                    if port == '*':
                        run_command(f"sudo ufw delete deny from {ip} to any")
                    else:
                        run_command(f"sudo ufw delete deny from {ip} to any port {port}")
                elif command == 'list':
                    run_command("sudo ufw status numbered")
                elif command == 'help':
                    print_help()
                elif command == 'exit':
                    break
                else:
                    print(f"Unknown command: {command}")
                    print_help()
            except (EOFError, KeyboardInterrupt):
                break
    finally:
        print("\nStopping monitoring thread...")
        stop_event.set()
        monitor_thread.join()
        print("Script finished.")

if __name__ == "__main__":
    main()