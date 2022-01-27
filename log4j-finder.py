#!/usr/bin/env python3
#
# file:     log4j-finder.py
# author:   NCC Group / Fox-IT / Research and Intelligence Fusion Team (RIFT)
#
#  Scan the filesystem to find Log4j2 files that is vulnerable to Log4Shell (CVE-2021-44228)
#  It scans recursively both on disk and inside Java Archive files (JARs).
#
#  Example usage to scan a path (defaults to /):
#      $ python3 log4j-finder.py /path/to/scan
#
#  Or directly a JAR file:
#      $ python3 log4j-finder.py /path/to/jarfile.jar
#
#  Or multiple directories:
#      $ python3 log4j-finder.py /path/to/dir1 /path/to/dir2
#
#  Exclude files or directories:
#      $ python3 log4j-finder.py / --exclude "/*/.dontgohere" --exclude "/home/user/*.war"
#
import os
import io
import sys
import time
import zipfile
import logging
import argparse
import hashlib
import platform
import datetime
import functools
import itertools
import collections
import fnmatch

from pathlib import Path

__version__ = "1.2.0"
FIGLET = f"""\
 __               _____  __         ___ __           __
|  |.-----.-----.|  |  ||__|______.'  _|__|.-----.--|  |.-----.----.
|  ||  _  |  _  ||__    |  |______|   _|  ||     |  _  ||  -__|   _|
|__||_____|___  |   |__||  |      |__| |__||__|__|_____||_____|__|
          |_____|      |___| v{__version__} https://github.com/fox-it/log4j-finder
"""

# Optionally import colorama to enable colored output for Windows
try:
    import colorama

    colorama.init()
    NO_COLOR = False
except ImportError:
    NO_COLOR = True if sys.platform == "win32" else False

log = logging.getLogger(__name__)

# Java Archive Extensions
JAR_EXTENSIONS = (".jar", ".war", ".ear", ".zip")

# Filenames to find and MD5 hash (also recursively in JAR_EXTENSIONS)
# Currently we just look for JndiManager.class
FILENAMES = [
    p.lower()
    for p in [
        "JndiManager.class",
    ]
]

# Known BAD
MD5_BAD = {
    # JndiManager.class (source: https://github.com/nccgroup/Cyber-Defence/blob/master/Intelligence/CVE-2021-44228/modified-classes/md5sum.txt)
    "04fdd701809d17465c17c7e603b1b202": "log4j 2.9.0 - 2.11.2",
    "21f055b62c15453f0d7970a9d994cab7": "log4j 2.13.0 - 2.13.3",
    "3bd9f41b89ce4fe8ccbf73e43195a5ce": "log4j 2.6 - 2.6.2",
    "415c13e7c8505fb056d540eac29b72fa": "log4j 2.7 - 2.8.1",
    "5824711d6c68162eb535cc4dbf7485d3": "log4j 2.12.0 - 2.12.1",
    "102cac5b7726457244af1f44e54ff468": "log4j 2.12.2",
    "6b15f42c333ac39abacfeeeb18852a44": "log4j 2.1 - 2.3",
    "8b2260b1cce64144f6310876f94b1638": "log4j 2.4 - 2.5",
    "a193703904a3f18fb3c90a877eb5c8a7": "log4j 2.8.2",
    "f1d630c48928096a484e4b95ccb162a0": "log4j 2.14.0 - 2.14.1",
    # 2.15.0 vulnerable to Denial of Service attack (source: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45046)
    "5d253e53fa993e122ff012221aa49ec3": "log4j 2.15.0",
    # 2.16.0 vulnerable to Infinite recursion in lookup evaluation (source: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45105)
    "ba1cf8f81e7b31c709768561ba8ab558": "log4j 2.16.0",
}

# Known GOOD
MD5_GOOD = {
    # JndiManager.class (source: https://repo.maven.apache.org/maven2/org/apache/logging/log4j/log4j-core/2.17.0/log4j-core-2.17.0.jar)
    "3dc5cf97546007be53b2f3d44028fa58": "log4j 2.17.0",
    "3c3a43af0930a658716b870e66db1569": "log4j 2.17.1",
}

HOSTNAME = platform.node()


def md5_digest(fobj):
    """Calculate the MD5 digest of a file object."""
    d = hashlib.md5()
    for buf in iter(functools.partial(fobj.read, io.DEFAULT_BUFFER_SIZE), b""):
        d.update(buf)
    return d.hexdigest()


def iter_scandir(path, stats=None, exclude=None):
    """
    Yields all files matcthing JAR_EXTENSIONS or FILENAMES recursively in path
    """
    p = Path(path)
    if p.is_file():
        if stats is not None:
            stats["files"] += 1
        yield p
        return
    if stats is not None:
        stats["directories"] += 1
    try:
        for entry in scantree(path, stats=stats, exclude=exclude):
            if entry.is_symlink():
                continue
            elif entry.is_file():
                name = entry.name.lower()
                if name.endswith(JAR_EXTENSIONS):
                    yield Path(entry.path)
                elif name in FILENAMES:
                    yield Path(entry.path)
    except IOError as e:
        log.debug(e)


def scantree(path, stats=None, exclude=None):
    """Recursively yield DirEntry objects for given directory."""
    exclude = exclude or [] 
    try:
        with os.scandir(path) as it:
            for entry in it:
                if any(fnmatch.fnmatch(entry.path, exclusion) for exclusion in exclude):
                    continue 
                if entry.is_dir(follow_symlinks=False):
                    if stats is not None:
                        stats["directories"] += 1
                    yield from scantree(entry.path, stats=stats, exclude=exclude)
                else:
                    if stats is not None:
                        stats["files"] += 1
                    yield entry
    except IOError as e:
        log.debug(e)


def iter_jarfile(fobj, parents=None, stats=None):
    """
    Yields (zfile, zinfo, zpath, parents) for each file in zipfile that matches `FILENAMES` or `JAR_EXTENSIONS` (recursively)
    """
    parents = parents or []
    try:
        with zipfile.ZipFile(fobj) as zfile:
            for zinfo in zfile.infolist():
                # log.debug(zinfo.filename)
                zpath = Path(zinfo.filename)
                if zpath.name.lower() in FILENAMES:
                    yield (zinfo, zfile, zpath, parents)
                elif zpath.name.lower().endswith(JAR_EXTENSIONS):
                    zfobj = zfile.open(zinfo.filename)
                    try:
                        # Test if we can open the zfobj without errors, fallback to BytesIO otherwise
                        # see https://github.com/fox-it/log4j-finder/pull/22
                        zipfile.ZipFile(zfobj)
                    except zipfile.BadZipFile as e:
                        log.debug(f"Got {zinfo}: {e}, falling back to BytesIO")
                        zfobj = io.BytesIO(zfile.open(zinfo.filename).read())
                    yield from iter_jarfile(zfobj, parents=parents + [zpath])
    except IOError as e:
        log.debug(f"{fobj}: {e}")
    except zipfile.BadZipFile as e:
        log.debug(f"{fobj}: {e}")
    except RuntimeError as e:
        # RuntimeError: File 'encrypted.zip' is encrypted, password required for extraction
        log.debug(f"{fobj}: {e}")


def red(s):
    if NO_COLOR:
        return s
    return f"\033[31m{s}\033[0m"


def green(s):
    if NO_COLOR:
        return s
    return f"\033[32m{s}\033[0m"


def yellow(s):
    if NO_COLOR:
        return s
    return f"\033[33m{s}\033[0m"


def cyan(s):
    if NO_COLOR:
        return s
    return f"\033[36m{s}\033[0m"


def magenta(s):
    if NO_COLOR:
        return s
    return f"\033[35m{s}\033[0m"


def bold(s):
    if NO_COLOR:
        return s
    return f"\033[1m{s}\033[0m"


def check_vulnerable(fobj, path_chain, stats, has_jndilookup=True):
    """
    Test if fobj matches any of the known bad or known good MD5 hashes.
    Also prints message if fobj is vulnerable or known good or unknown.

    if `has_jndilookup` is False, it means `lookup/JndiLookup.class` was not found and could
    indicate it was patched according to https://logging.apache.org/log4j/2.x/security.html using:
        zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class
    """
    md5sum = md5_digest(fobj)
    first_path = bold(path_chain.pop(0))
    path_chain = " -> ".join(str(p) for p in [first_path] + path_chain)
    comment = collections.ChainMap(MD5_BAD, MD5_GOOD).get(md5sum, "Unknown MD5")
    color_map = {"vulnerable": red, "good": green, "patched": cyan, "unknown": yellow}
    if md5sum in MD5_BAD:
        status = "vulnerable" if has_jndilookup else "patched"
    elif md5sum in MD5_GOOD:
        status = "good"
    else:
        status = "unknown"
    stats[status] += 1
    color = color_map.get(status, red)
    now = datetime.datetime.utcnow().replace(microsecond=0)
    hostname = magenta(HOSTNAME)
    status = bold(color(status.upper()))
    md5sum = color(md5sum)
    comment = bold(color(comment))
    print(f"[{now}] {hostname} {status}: {path_chain} [{md5sum}: {comment}]")


def print_summary(stats):
    print("\nSummary:")
    print(f" Processed {stats['files']} files and {stats['directories']} directories")
    print(f" Scanned {stats['scanned']} files")
    if stats["vulnerable"]:
        print("  Found {} vulnerable files".format(stats["vulnerable"]))
    if stats["good"]:
        print("  Found {} good files".format(stats["good"]))
    if stats["patched"]:
        print("  Found {} patched files".format(stats["patched"]))
    if stats["unknown"]:
        print("  Found {} unknown files".format(stats["unknown"]))
       

def view_results(fname):
    try:
        f = open(fname, "r")
    except IOError:
        print("Error:  File does not exist or cannot be opened.")
        return
        
    print(f.read())
    f.close


class Tee(object):
    def __init__(self, *files):
        self.files = files
    def write(self, obj):
        for f in self.files:
            f.write(obj)
            f.flush()
    def flush(self) :
        for f in self.files:
            f.flush()    
    
    
def main():
    parser = argparse.ArgumentParser(
        description=f"%(prog)s v{__version__} - Find vulnerable log4j2 on filesystem (Log4Shell CVE-2021-4428, CVE-2021-45046, CVE-2021-45105)",
        epilog="Files are scanned recursively, both on disk and in (nested) Java Archive Files",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "path",
        metavar="PATH",
        nargs="*",
        default=["/"],
        help="Directory or file(s) to scan (recursively)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="verbose output (-v is info, -vv is debug)",
    )
    parser.add_argument(
        "-n", "--no-color", action="store_true", help="disable color output"
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="be more quiet, disables banner and summary",
    )
    parser.add_argument("-b", "--no-banner", action="store_true", help="disable banner")
    parser.add_argument(
        "-V", "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument(
        "-e",
        "--exclude",
        action='append',
        help="exclude files/directories by pattern (can be used multiple times)",
        metavar='PATTERN'
    )
    parser.add_argument(
        "-s",
        "--saveresults",
        metavar = "RESULTS-FILE",
        help = "Save the results to a file in addition to stdout.  "\
               "Results will include any color formating unless disabled.  "\
               "Use --viewresults to view (stdout) the file with color highlighting."
    )
    parser.add_argument(
        "-r",
        "--viewresults",
        metavar = "RESULTS-FILE",
        help = "View saved results with  "\
               "color high-lighting (see --saveresults)."\
               "Scan is NOT performed."
    )
    args = parser.parse_args()
    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(message)s",
    )
    python_version = platform.python_version()
    if args.viewresults != None:
        view_results(args.viewresults)
        return
        
    if args.saveresults != None:
        try:
            resultfile = open(args.saveresults, "w")
        except IOError:
            print("Unable to create results file specified.")
            return
        
        sys.stdout = Tee(sys.stdout, resultfile)
    
    if args.verbose == 1:
        log.setLevel(logging.INFO)
        log.info(f"info logging enabled - log4j-finder {__version__} - Python {python_version}")
    elif args.verbose >= 2:
        log.setLevel(logging.DEBUG)
        log.debug(f"debug logging enabled - log4j-finder {__version__} - Python {python_version}")

    if args.no_color:
        global NO_COLOR
        NO_COLOR = True

    stats = collections.Counter()
    start_time = time.monotonic()
    hostname = magenta(HOSTNAME)

    if not args.no_banner and not args.quiet:
        print(FIGLET)
    for directory in args.path:
        now = datetime.datetime.utcnow().replace(microsecond=0)
        if not args.quiet:
            print(f"[{now}] {hostname} Scanning: {directory}")
        for p in iter_scandir(directory, stats=stats, exclude=args.exclude):
            if p.name.lower() in FILENAMES:
                stats["scanned"] += 1
                log.info(f"Found file: {p}")
                with p.open("rb") as fobj:
                    # If we find JndiManager, we also check if JndiLookup.class exists
                    has_lookup = True
                    if p.name.lower().endswith("JndiManager.class".lower()):
                        lookup_path = p.parent.parent / "lookup/JndiLookup.class"
                        has_lookup = lookup_path.exists()
                    check_vulnerable(fobj, [p], stats, has_lookup)
            if p.suffix.lower() in JAR_EXTENSIONS:
                try:
                    log.info(f"Found jar file: {p}")
                    stats["scanned"] += 1
                    for (zinfo, zfile, zpath, parents) in iter_jarfile(
                        p.open("rb"), parents=[p]
                    ):
                        log.info(f"Found zfile: {zinfo} ({parents}")
                        with zfile.open(zinfo.filename) as zf:
                            # If we find JndiManager.class, we also check if JndiLookup.class exists
                            has_lookup = True
                            if zpath.name.lower().endswith("JndiManager.class".lower()):
                                lookup_path = zpath.parent.parent / "lookup/JndiLookup.class"
                                try:
                                    has_lookup = zfile.open(lookup_path.as_posix())
                                except KeyError:
                                    has_lookup = False
                            check_vulnerable(zf, parents + [zpath], stats, has_lookup)
                except IOError as e:
                    log.debug(f"{p}: {e}")

    elapsed = time.monotonic() - start_time
    now = datetime.datetime.utcnow().replace(microsecond=0)
    if not args.quiet:
        print(f"[{now}] {hostname} Finished scan, elapsed time: {elapsed:.2f} seconds")
        print_summary(stats)
        print(f"\nElapsed time: {elapsed:.2f} seconds")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nAborted!")
