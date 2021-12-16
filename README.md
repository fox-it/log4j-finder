# log4j-finder

A Python3 script to scan the filesystem to find Log4j2 that is vulnerable to _Log4Shell_ (`CVE-2021-44228` & `CVE-2021-45046`). 
It scans recursively both on disk and inside (nested) Java Archive files (JARs).

![log4j-finder results](screenshot.png?raw=true "Output of log4j-finder")

## Downloading and running

You can install log4j-finder using one of the following methods:

### Using the release binary

You can download the correct binary for your Operating System:

 * Windows latest: [log4j-finder.exe](https://github.com/fox-it/log4j-finder/releases/latest/download/log4j-finder.exe)
   * This can trigger your AntiVirus due to it being a [PyInstaller](https://pyinstaller.readthedocs.io/en/stable/) executable. You can also generate the executable yourself, see "Generating log4j-finder executables" on how to do this.
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

We are aware that some Anti Virus vendors don't like the Windows binaries, in that case we recommend using generating the executable yourself using the following steps.

### Generating the Windows executable

1. If you don't have Python 3.6 or higher installed, download it first from https://www.python.org/downloads/

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

Note that on Windows it only scans the root `c:\` drive if you don't give any extra arguments.
We recommend specifying the drives you need to scan on the commandline such as (drives that don't exist are skipped):

```bash
log4j-finder.exe c:\ d:\ e:\ f:\
```

Files or directories that cannot be accessed (Permission denied errors) are not printed.
If you want to see more output, you can give the `-v` flag for verbose, or `-vv` for debug mode (only recommended for debugging purposes).
