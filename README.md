# log4j-finder

A Python3 script to scan the filesystem to find Log4j2 that is vulnerable to `Log4Shell (CVE-2021-44228)`
It scans recursively both on disk and inside Java Archive files (JARs).

![log4j-finder results](screenshot.png?raw=true "Output of log4j-finder")

## Usage

Example usage to scan a path (defaults to /):
```bash
$ python3 log4j-finder.py /path/to/scan
```

Or directly a JAR file:
```bash
$ python3 log4j-finder.py /path/to/jarfile.jar
```

Or multiple directories and or files:
```bash
$ python3 log4j-finder.py /path/to/dir1 /path/to/dir2 /path/to/jarfile.jar
```

Files or directories that cannot be accessed (Permission denied errors) are not printed.
If you want to see more output, you can give the `-v` flag for verbose, or `-vv` for debug mode (only recommended for debugging purposes).
