# log4j-finder

A Python3 script to scan the filesystem to find Log4j2 that is vulnerable to `Log4Shell (CVE-2021-44228)`
It scans recursively both on disk and inside Java Archive files (JARs).

![log4j-finder results](screenshot.png?raw=true "Output of log4j-finder")

## Downloading and running

You can install log4j-finder using one of the following methods:

### Using the release binary

You can download the correct binary for your Operating System:

 * Windows latest: [log4j-finder.exe](https://github.com/fox-it/log4j-finder/releases/latest/download/log4j-finder.exe)
 * Linux latest: [log4j-finder](https://github.com/fox-it/log4j-finder/releases/latest/download/log4j-finder)

If you are on Linux you can also download the latest release and run using one of the following ways:

```bash
curl -L https://github.com/fox-it/log4j-finder/releases/latest/download/log4j-finder -o log4j-finder
chmod +x log4j-finder
sudo ./log4j-finder
```

```bash
wget https://github.com/fox-it/log4j-finder/releases/latest/download/log4j-finder -O log4j-finder
chmod +x log4j-finder
sudo ./log4j-finder
```

### Using Python 3

For distribution with Python 3 installed, one following methods also work:

```bash
curl -L https://github.com/fox-it/log4j-finder/raw/main/log4j-finder.py -o log4j-finder.py
sudo python3 log4j-finder.py
```

```bash
wget https://github.com/fox-it/log4j-finder/raw/main/log4j-finder.py
sudo python3 log4j-finder.py
```

```bash
git clone https://github.com/fox-it/log4j-finder
cd log4j-finder
sudo python3 log4j-finder.py
```

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
