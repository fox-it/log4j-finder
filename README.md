# log4j-finder

A Python3 script to scan the filesystem to find Log4j2 that is vulnerable to _Log4Shell_ (`CVE-2021-44228` & `CVE-2021-45046` & `CVE-2021-45105`). 
It scans recursively both on disk and inside (nested) Java Archive files (JARs).

![log4j-finder results](screenshot.png?raw=true "Output of log4j-finder")

## How it works

log4j-finder identifies `log4j2` libraries on your filesystem using a list of *known bad* and *known good* MD5 hashes of specific files (currently only `JndiManager.class`) present in `log4j2-core-*` packages; the main package that is affected by `log4shell`. It searches for these files inside Java Archive files and on the filesystem. The `log4j2` version is then identified based on the MD5 hash of this file.

To optimize scanning speed, it searches the filesystem and processes ONLY the following filenames:

 * All files with `Java ARchive` file extensions in the filename (also nested in these archives):
    *  `*.jar`, `*.war`, `*.ear`
 * Filenames that we have *known bad* and *good* hashes for (also inside above archives, and nested):
    *  `JndiManager.class`

If the file matches one of the extensions mentioned above, it will check inside these archives (all in memory, nothing is unpacked) to search for the filenames that the script has *known* hashes for. It also looks inside nested archives, for example, a `JAR` file in a `WAR` file.

The script does NOT scan other archive file extensions such as `7z`, `RAR`, `TAR`, `BZ2`, etc. So, for example, if a `JAR` file is inside a `7z` file, the script will not find it. The rationale is that Java can only load `Java ARchive` formats so we only scan those.

Unknown MD5 hashes are shown as `UNKNOWN`; this could happen if a non `log4j2` Java package uses the same filename that this script searches for.
It's most likely not `log4j2` if the identified file path does not contain references to `org/apache/logging/log4j`. However, manual verification is still recommended.

## Downloading and running

You can install log4j-finder using one of the following methods:

### Using the release binary

You can download the correct binary for your Operating System:

 * Windows latest (signed): [log4j-finder-signed.exe](https://github.com/fox-it/log4j-finder/releases/latest/download/log4j-finder-signed.exe)
   * Non signed binaries are also available but can trigger your AntiVirus due to it being a [PyInstaller](https://pyinstaller.readthedocs.io/en/stable/) executable. You can also generate the executable yourself, see "Generating log4j-finder executables" on how to do this.
 * Linux x86_64 latest: [log4j-finder](https://github.com/fox-it/log4j-finder/releases/latest/download/log4j-finder)

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

For distribution with Python 3.6+ installed, one following methods also work:

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

## Generating log4j-finder executables

### Auto generated executables

There is a [GitHub Action](https://github.com/fox-it/log4j-finder/blob/main/.github/workflows/pyinstaller.yaml) in the repository that automatically generates a Windows and Linux binary of the `log4j-finder.py` script using  [PyInstaller](https://pyinstaller.readthedocs.io/en/stable/) on every commit. The build artifacts of these workflow runs are used to attach to the [Releases](https://github.com/fox-it/log4j-finder/releases/) page.

We are aware that some Anti Virus vendors don't like the Windows binaries, in that case we recommend using generating the executable yourself using the following steps (note that we now also provide signed binaries).

### Generating the Windows executable

1. If you don't have Python 3.6 or higher installed, download it first from https://www.python.org/downloads/

   * Choose `Python 3.8.10` if you want your binary to work on Windows 7:
     * Download [Python 3.8.10 Windows installer (32 bit)](https://www.python.org/ftp/python/3.8.10/python-3.8.10.exe)
     * Download [Python 3.8.10 Windows installer (64-bit)](https://www.python.org/ftp/python/3.8.10/python-3.8.10-amd64.exe)
   * Ensure that during install you choose: `Add Python 3.x to PATH`, this makes the following steps much easier.

2. Open a command prompt and use `pip` to install the `pyinstaller` package:

   ```bash
   pip install pyinstaller
   
   # In the output you will see where pyinstaller is installed, for example:
   # C:\Users\User\AppData\Roaming\Python\Python310\Scripts
   #
   # Verify using --version
   C:\Users\User\AppData\Roaming\Python\Python310\Scripts\pyinstaller.exe --version
   4.7
   ```
3. Optionally install the `colorama` package to add support for colors:

   ```bash
   pip install colorama
   ```

3.  Download the latest version of the `log4j-finder.py` script and then run PyInstaller:

   ```bash
   pyinstaller --onefile --hidden-import colorama log4j-finder.py
   ```

The Windows executable is then in the `dist` directory: `dist\log4j-finder.exe`

### Generating the Linux executable

Example given for Debian 11:

```bash
# Install PyInstaller using pip3
sudo apt update
sudo apt install python3-pip git
pip3 install --user pyinstaller

# Git clone and build using PyInstaller
git clone https://github.com/fox-it/log4j-finder
cd log4j-finder
~/.local/bin/pyinstaller --onefile log4j-finder.spec

# Verify that the binary works
./dist/log4j-finder --help
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

Exclude files or directories:
```bash
$ python3 log4j-finder.py / --exclude "/*/.dontgohere" --exclude "/home/user/*.war"
```

Note that on Windows it only scans the root `c:\` drive if you don't give any extra arguments.
We recommend specifying the drives you need to scan on the commandline such as (drives that don't exist are skipped):

```bash
log4j-finder.exe c:\ d:\ e:\ f:\
```

Files or directories that cannot be accessed (Permission denied errors) are not printed.

If you want to see more output, you can give the `-v` flag for verbose, or `-vv` for debug mode (only recommended for debugging purposes).

Application arguments:
```bash
positional arguments:
  PATH                  Directory or file(s) to scan (recursively) (default:
                        ['/'])

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         verbose output (-v is info, -vv is debug) (default: 0)
  -n, --no-color        disable color output (default: False)
  -q, --quiet           be more quiet, disables banner and summary (default:
                        False)
  -b, --no-banner       disable banner (default: False)
  -V, --version         show program's version number and exit
  -e PATTERN, --exclude PATTERN
                        exclude files/directories by pattern (can be used
                        multiple times) (default: None)
```
Files are scanned recursively, both on disk and in (nested) Java Archive Files
