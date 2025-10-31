
#!/bin/bash

SCAN_DIR="${1:-/var/www}"

if [ ! -d "$SCAN_DIR" ]; then
    echo "Directory not found: $SCAN_DIR"
    exit 1
fi

echo "========================================="
echo "WEB SHELL SCANNER - $(date)"
echo "$(date) $(basename "$0") - Web shell scanner script started for directory $SCAN_DIR" >> /root/activity_log.txt
echo "Scanning: $SCAN_DIR"
echo "========================================="

OUTPUT="webshell_scan_$(date +%Y%m%d_%H%M%S).txt"

{
echo "=== WEB SHELL SCAN REPORT ==="
echo "Scan date: $(date)"
echo "Directory: $SCAN_DIR"
echo ""

# Common web shell patterns
PATTERNS=(
    "eval.*base64_decode"
    "system.*\\\$_"
    "exec.*\\\$_"
    "shell_exec.*\\\$_"
    "passthru.*\\\$_"
    "proc_open"
    "popen.*\\\$_"
    "curl_exec"
    "curl_multi_exec"
    "parse_ini_file.*\\\$_"
    "show_source"
    "file_get_contents.*\\\$_"
    "file_put_contents.*\\\$_"
    "fputs.*\\\$_"
    "fwrite.*\\\$_"
    "assert.*\\\$_"
    "create_function"
    "base64_decode.*eval"
    "gzinflate.*base64"
    "eval.*gzuncompress"
    "preg_replace.*\\/e"
    "\\$\\{.*\\(.*\\).*\\}"
)

echo "=== SCANNING FOR SUSPICIOUS PHP FILES ==="
for pattern in "${PATTERNS[@]}"; do
    echo -e "\nPattern: $pattern"
    find "$SCAN_DIR" -type f -name "*.php" -exec grep -l "$pattern" {} \; 2>/dev/null
done

echo -e "\n=== CHECKING FOR SUSPICIOUS FILE NAMES ==="
find "$SCAN_DIR" -type f \( -name "*shell*.php" -o -name "*cmd*.php" -o -name "*backdoor*.php" -o -name "c99*.php" -o -name "r57*.php" -o -name "b374k*.php" \) 2>/dev/null

echo -e "\n=== RECENTLY MODIFIED PHP FILES (last 24 hours) ==="
find "$SCAN_DIR" -type f -name "*.php" -mtime -1 -ls 2>/dev/null

echo -e "\n=== CHECKING UPLOAD DIRECTORIES ==="
find "$SCAN_DIR" -type d -name "*upload*" -o -name "*temp*" -o -name "*tmp*" 2>/dev/null | while read dir; do
    echo -e "\nDirectory: $dir"
    find "$dir" -type f -name "*.php" -ls 2>/dev/null
done

echo -e "\n=== WORLD-WRITABLE PHP FILES ==="
find "$SCAN_DIR" -type f -name "*.php" -perm -0002 -ls 2>/dev/null

echo -e "\n=== PHP FILES OWNED BY UNEXPECTED USERS ==="
find "$SCAN_DIR" -type f -name "*.php" ! -user www-data ! -user nginx ! -user apache ! -user root -ls 2>/dev/null

} | tee "$OUTPUT"

echo ""
echo "========================================="
echo "SCAN COMPLETE"
echo "Report saved to: $OUTPUT"
echo "========================================="
