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

__version__ = "1.0.2"
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

###########
# Java Archive Extensions (tuple)
JAR_EXTENSIONS = (".jar", ".war", ".ear", ".zip")

###########
# filenames (List Comprehension)
FILENAMES = [
  p.lower()
  for p in [
    "JndiManager.class",
    "StrSubstitutor.class",
    "JmsAppender.class",
    "NetUtils.class",
    "AbstractSocketServer.class",
    "ObjectInputStreamLogEventBridge.class",
    "TcpSocketServer.class",
    "UdpSocketServer.class",
  ]
]

#MD5_HASHES ( key : list dictionary)
MD5_HASHES = {

  ###
  #./fingerprint.sh StrSubstitutor.class
  #org/apache/logging/log4j/core/lookup/StrSubstitutor.class:
  #de8030bb3cd1d6b24110c95562dbf399 log4j-2.0-alpha1, log4j-2.0-alpha2, log4j-2.0-beta1, log4j-2.0-beta2, log4j-2.0-beta3
  #6401fe7657ab25b20127efdc61398ae0 log4j-2.0-beta4
  #52454dab43c2fdf430d1733c84579d73 log4j-2.0-beta5, log4j-2.0-beta6, log4j-2.0-beta7, log4j-2.0-beta8, log4j-2.0-beta9, log4j-2.0-rc1
  #71774e0ae8aaafed229d9f1ac71f7445 log4j-2.0-rc2, log4j-2.0.1, log4j-2.0.2, log4j-2.0
  #4e1bbecb881eb0ed2b022ca35ecb1f9e log4j-2.1, log4j-2.2, log4j-2.3
  #46bcbc04843c5b2230b126e08d308a8c log4j-2.4.1, log4j-2.4, log4j-2.5
  #7ba0e39551863a364c4f1473b48b2dd0 log4j-2.6.1, log4j-2.6.2, log4j-2.6
  #a4fab2d08ba60b74c20959857d05d19a log4j-2.7
  #91e80b91b67511dee843705d111607f0 log4j-2.10.0, log4j-2.8.1, log4j-2.8, log4j-2.9.0, log4j-2.9.1
  #8ed924b12f793f59147046addc5b13ac log4j-2.8.2
  #f2a49a5da81d9f0253629c7ac56f4c28 log4j-2.11.0, log4j-2.11.1, log4j-2.11.2
  #e3fb2a9307a13e596cb63c2a105a5757 log4j-2.12.0, log4j-2.12.1, log4j-2.12.2
  #a031e7cf7bc665206676d1b986c7e47a log4j-2.13.0
  #7cf37e3bed3d306bbe502bb0fb44fa51 log4j-2.13.1, log4j-2.13.2, log4j-2.13.3
  #0d6a71c70eff31cc1a4e966666cdf473 log4j-2.14.0
  #1ac1fbb3d633a7e20608b3112c78ae34 log4j-2.14.1, log4j-2.15.0, log4j-2.16.0
  #c1dfe395359f872678e6e7b0daec657a log4j-2.17.0
  #

  # StrSubstitutor.class (source: https://logging.apache.org/log4j/2.x/security.html#CVE-2021-45105 )

  # StrSubstitutor.class
  # CVE-2021-45105 - All versions 2.0-alpha1 through 2.16.0
  # Apache Log4j2 does not always protect from infinite recursion in lookup evaluation
  # https://logging.apache.org/log4j/2.x/security.html#CVE-2021-45105

  "de8030bb3cd1d6b24110c95562dbf399": [ "BAD", ["CVE-2021-45105", ], "StrSubstitutor.class", "log4j 2.0-alpha1 - 2.0-beta3", ],
  "6401fe7657ab25b20127efdc61398ae0": [ "BAD", ["CVE-2021-45105", ], "StrSubstitutor.class", "log4j 2.0-beta4", ],
  "52454dab43c2fdf430d1733c84579d73": [ "BAD", ["CVE-2021-45105", ], "StrSubstitutor.class", "log4j 2.0-beta5 - 2.0-rc1", ],
  "71774e0ae8aaafed229d9f1ac71f7445": [ "BAD", ["CVE-2021-45105", ], "StrSubstitutor.class", "log4j 2.0-rc2 - 2.0.2", ],
  "4e1bbecb881eb0ed2b022ca35ecb1f9e": [ "BAD", ["CVE-2021-45105", ], "StrSubstitutor.class", "log4j 2.1 - 2.3", ],
  "46bcbc04843c5b2230b126e08d308a8c": [ "BAD", ["CVE-2021-45105", ], "StrSubstitutor.class", "log4j 2.4 - 2.5",  ],
  "7ba0e39551863a364c4f1473b48b2dd0": [ "BAD", ["CVE-2021-45105", ], "StrSubstitutor.class", "log4j 2.6", ],
  "a4fab2d08ba60b74c20959857d05d19a": [ "BAD", ["CVE-2021-45105", ], "StrSubstitutor.class", "log4j 2.7", ],
  "91e80b91b67511dee843705d111607f0": [ "BAD", ["CVE-2021-45105", ], "StrSubstitutor.class", "log4j 2.8 - 2.10.0", ],
  "8ed924b12f793f59147046addc5b13ac": [ "BAD", ["CVE-2021-45105", ], "StrSubstitutor.class", "log4j 2.8.2", ],
  "f2a49a5da81d9f0253629c7ac56f4c28": [ "BAD", ["CVE-2021-45105", ], "StrSubstitutor.class", "log4j 2.11.0 ", ],
  "e3fb2a9307a13e596cb63c2a105a5757": [ "BAD", ["CVE-2021-45105", ], "StrSubstitutor.class", "log4j 2.12.0 - 2.12.2 ", ],
  "a031e7cf7bc665206676d1b986c7e47a": [ "BAD", ["CVE-2021-45105", ], "StrSubstitutor.class", "log4j 2.13.0 ", ],
  "7cf37e3bed3d306bbe502bb0fb44fa51": [ "BAD", ["CVE-2021-45105", ], "StrSubstitutor.class", "log4j 2.13.1 - 2.13.3 ", ],
  "0d6a71c70eff31cc1a4e966666cdf473": [ "BAD", ["CVE-2021-45105", ], "StrSubstitutor.class", "log4j 2.14.0 ", ],
  "1ac1fbb3d633a7e20608b3112c78ae34": [ "BAD", ["CVE-2021-45105", ], "StrSubstitutor.class", "log4j 2.14.1 - 2.16.0 ", ],
  "c1dfe395359f872678e6e7b0daec657a": [ "BAD", ["CVE-2021-45105", ], "StrSubstitutor.class", "log4j 2.17.0 ", ],

  #org/apache/logging/log4j/core/net/JndiManager.class:
  #d41d8cd98f00b204e9800998ecf8427e log4j-2.0-alpha1, log4j-2.0-alpha2, log4j-2.0-beta1, log4j-2.0-beta2, log4j-2.0-beta3, log4j-2.0-beta4, log4j-2.0-beta5, log4j-2.0-beta6, log4j-2.0-beta7, log4j-2.0-beta8, log4j-2.0-beta9, log4j-2.0-rc1, log4j-2.0-rc2, log4j-2.0.1, log4j-2.0.2, log4j-2.0
  #6b15f42c333ac39abacfeeeb18852a44 log4j-2.1, log4j-2.2, log4j-2.3
  #8b2260b1cce64144f6310876f94b1638 log4j-2.4.1, log4j-2.4, log4j-2.5
  #3bd9f41b89ce4fe8ccbf73e43195a5ce log4j-2.6.1, log4j-2.6.2, log4j-2.6
  #415c13e7c8505fb056d540eac29b72fa log4j-2.7, log4j-2.8.1, log4j-2.8
  #a193703904a3f18fb3c90a877eb5c8a7 log4j-2.8.2
  #04fdd701809d17465c17c7e603b1b202 log4j-2.10.0, log4j-2.11.0, log4j-2.11.1, log4j-2.11.2, log4j-2.9.0, log4j-2.9.1
  #5824711d6c68162eb535cc4dbf7485d3 log4j-2.12.0, log4j-2.12.1
  #102cac5b7726457244af1f44e54ff468 log4j-2.12.2
  #21f055b62c15453f0d7970a9d994cab7 log4j-2.13.0, log4j-2.13.1, log4j-2.13.2, log4j-2.13.3
  #f1d630c48928096a484e4b95ccb162a0 log4j-2.14.0, log4j-2.14.1
  #5d253e53fa993e122ff012221aa49ec3 log4j-2.15.0
  #ba1cf8f81e7b31c709768561ba8ab558 log4j-2.16.0
  #3dc5cf97546007be53b2f3d44028fa58 log4j-2.17.0

  ## JndiManager.class
  ##
  ## CVE-2021-45105 - all versions from 2.0-beta9 to 2.15.0, excluding 2.12.2
  ## Apache Log4j2 does not always protect from infinite recursion in lookup evaluation
  ## https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45105)
  ##
  ## CVE-2021-44228 - all versions from 2.0-beta9 to 2.14.1
  ## Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints.
  ## https://github.com/nccgroup/Cyber-Defence/blob/master/Intelligence/CVE-2021-44228/modified-classes/md5sum.txt
  ## https://logging.apache.org/log4j/2.x/security.html#CVE-2021-44228

  "d41d8cd98f00b204e9800998ecf8427e": [ "BAD", ["CVE-2021-45105", "CVE-2021-44228", ], "JndiManager.class", "log4j-alpha1 - 2.0.2", ],
  "6b15f42c333ac39abacfeeeb18852a44": [ "BAD", ["CVE-2021-45105", "CVE-2021-44228", ], "JndiManager.class", "log4j-2.1 - 2.3", ],
  "8b2260b1cce64144f6310876f94b1638": [ "BAD", ["CVE-2021-45105", "CVE-2021-44228", ], "JndiManager.class", "log4j-2.4 - 2.5", ],
  "3bd9f41b89ce4fe8ccbf73e43195a5ce": [ "BAD", ["CVE-2021-45105", "CVE-2021-44228", ], "JndiManager.class", "log4j 2.6 - 2.6.2", ],
  "415c13e7c8505fb056d540eac29b72fa": [ "BAD", ["CVE-2021-45105", "CVE-2021-44228", ], "JndiManager.class", "log4j 2.7 - 2.8.1", ],
  "a193703904a3f18fb3c90a877eb5c8a7": [ "BAD", ["CVE-2021-45105", "CVE-2021-44228", ], "JndiManager.class", "log4j 2.8.2", ],
  "04fdd701809d17465c17c7e603b1b202": [ "BAD", ["CVE-2021-45105", "CVE-2021-44228", ], "JndiManager.class", "log4j 2.9.0 - 2.11.2", ],
  "5824711d6c68162eb535cc4dbf7485d3": [ "BAD", ["CVE-2021-45105", "CVE-2021-44228", ], "JndiManager.class", "log4j 2.12.0 - 2.12.1", ],
  "102cac5b7726457244af1f44e54ff468": [ "BAD", ["CVE-2021-45105", "CVE-2021-44228", ], "JndiManager.class", "log4j 2.12.2", ],
  "21f055b62c15453f0d7970a9d994cab7": [ "BAD", ["CVE-2021-45105", "CVE-2021-44228", ], "JndiManager.class", "log4j 2.13.0 - 2.13.3", ],
  "f1d630c48928096a484e4b95ccb162a0": [ "BAD", ["CVE-2021-45105", "CVE-2021-44228", ], "JndiManager.class", "log4j 2.14.0 - 2.14.1", ],
  "5d253e53fa993e122ff012221aa49ec3": [ "BAD", ["CVE-2021-45105", "CVE-2021-44228", ], "JndiManager.class", "log4j 2.15.0", ],
  # 2.16.0 vulnerable to Infinite recursion in lookup evaluation (source: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45105)
  "ba1cf8f81e7b31c709768561ba8ab558": [ "BAD", ["CVE-2021-45105", "CVE-2021-44228", ], "JndiManager.class", "log4j 2.16.0", ],
  # JndiManager.class (source: https://repo.maven.apache.org/maven2/org/apache/logging/log4j/log4j-core/2.17.0/log4j-core-2.17.0.jar)
  "3dc5cf97546007be53b2f3d44028fa58": [ "GOOD", ["CVE-2021-45105", "CVE-2021-44228", ], "JndiManager.class", "log4j 2.17.0", ],


  #./fingerprint.sh JmsAppender.class
  #org/apache/logging/log4j/core/appender/mom/JmsAppender.class:
  #d41d8cd98f00b204e9800998ecf8427e log4j-2.0-alpha1, log4j-2.0-alpha2, log4j-2.0-beta1, log4j-2.0-beta2, log4j-2.0-beta3, log4j-2.0-beta4, log4j-2.0-beta5, log4j-2.0-beta6, log4j-2.0-beta7, log4j-2.0-beta8, log4j-2.0-beta9, log4j-2.0-rc1, log4j-2.0-rc2, log4j-2.0.1, log4j-2.0.2, log4j-2.0
  #d92384ec301e1ebed95e2ca463b13409 log4j-2.1, log4j-2.2, log4j-2.3
  #b2375d87e8c2dea7b145fed1355e14cf log4j-2.4.1, log4j-2.4, log4j-2.5
  #ca2cb207a96338325c1a25d240f4e13b log4j-2.6.1, log4j-2.6.2, log4j-2.6
  #cc8a7d647d86ef1910a1430d25cc428c log4j-2.7, log4j-2.8.1, log4j-2.8
  #4bfe6e180d64e313d810c14a34fadc27 log4j-2.8.2
  #eaf0ad2e57051169b3357181a255c669 log4j-2.10.0, log4j-2.9.0, log4j-2.9.1
  #eba3d482e44d07e65becbe0dffa6c4a5 log4j-2.11.0, log4j-2.11.1
  #ffdb07954c99cac0190f88237af55632 log4j-2.11.2
  #3e41eb48e70075be693b5c27f4266bda log4j-2.12.0, log4j-2.12.1, log4j-2.12.2
  #1fd6c328f1ed3c7e2f74c1b284e999c7 log4j-2.13.0, log4j-2.13.1, log4j-2.13.2, log4j-2.13.3
  #7ada873ced8590b2e988b4099c9bfd0e log4j-2.14.0, log4j-2.14.1
  #0418394b441b37e2d36a51a6e64f7475 log4j-2.15.0, log4j-2.16.0
  #5c293f31b93620ffbc2a709577a3f3cd log4j-2.17.0

  #JmsAppender.class
  # CVE-2021-44228 - all versions from 2.0-beta9 to 2.14.1
  # Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints.
  # https://github.com/nccgroup/Cyber-Defence/blob/master/Intelligence/CVE-2021-44228/modified-classes/md5sum.txt
  # https://logging.apache.org/log4j/2.x/security.html#CVE-2021-44228

  # JndiManager.class
  # CVE-2021-45046 -  all versions from 2.0-beta9 to 2.15.0, excluding 2.12.2
  # Apache Log4j2 Thread Context Lookup Pattern vulnerable to remote code execution in certain non-default configurations
  #
  # the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations.
  # When the logging configuration uses a non-default Pattern Layout with a Context Lookup (for example, $${ctx:loginId}),
  #   attackers with control over Thread Context Map (MDC) input data can craft malicious input data using a JNDI Lookup pattern,
  #   resulting in an information leak and remote code execution in some environments and local code execution in all environments;
  #   remote code execution has been demonstrated on macOS but no other tested environments.
  #
  # 2.15.0 vulnerable to Denial of Service attack

  #"d41d8cd98f00b204e9800998ecf8427e": ["UNK", ["CVE-2021-44228", ], "JmsAppender.class", "log4j-alpha1 - 2.0.2" ],
  "d92384ec301e1ebed95e2ca463b13409": ["BAD",  ["CVE-2021-44228", ], "JmsAppender.class", "log4j-2.1 - 2.3" ],
  "b2375d87e8c2dea7b145fed1355e14cf": ["BAD",  ["CVE-2021-44228", ], "JmsAppender.class", "log4j-2.4 - 2.5" ],
  "ca2cb207a96338325c1a25d240f4e13b": ["BAD",  ["CVE-2021-44228", ], "JmsAppender.class", "log4j-2.6 - 2.6.2" ],
  "cc8a7d647d86ef1910a1430d25cc428c": ["BAD",  ["CVE-2021-44228", ], "JmsAppender.class", "log4j-2.7 - 2.8.1" ],
  "4bfe6e180d64e313d810c14a34fadc27": ["BAD",  ["CVE-2021-44228", ], "JmsAppender.class", "log4j-2.8.2" ],
  "eaf0ad2e57051169b3357181a255c669": ["BAD",  ["CVE-2021-44228", ], "JmsAppender.class", "log4j-2.9.0 - 2.10.0" ],
  "eba3d482e44d07e65becbe0dffa6c4a5": ["BAD",  ["CVE-2021-44228", ], "JmsAppender.class", "log4j-2.11.0 - 2.11.1" ],
  "ffdb07954c99cac0190f88237af55632": ["BAD",  ["CVE-2021-44228", ], "JmsAppender.class", "log4j-2.11.2" ],
  "3e41eb48e70075be693b5c27f4266bda": ["BAD",  ["CVE-2021-44228", ], "JmsAppender.class", "log4j-2.12.0 - 2.12.1" ],
  "1fd6c328f1ed3c7e2f74c1b284e999c7": ["BAD",  ["CVE-2021-44228", ], "JmsAppender.class", "log4j-2.13.0 - 2.13.3" ],
  "7ada873ced8590b2e988b4099c9bfd0e": ["BAD",  ["CVE-2021-44228", ], "JmsAppender.class", "log4j-2.14.0 - 2.14.1" ],
  "0418394b441b37e2d36a51a6e64f7475": ["GOOD", ["CVE-2021-44228", ], "JmsAppender.class", "log4j-2.15.0 - 2.1.6.0" ],
  "5c293f31b93620ffbc2a709577a3f3cd": ["GOOD", ["CVE-2021-44228", ], "JmsAppender.class", "log4j-2.17.0" ],


  #./fingerprint.sh NetUtils.class
  #org/apache/logging/log4j/core/helpers/NetUtils.class:
  #d41d8cd98f00b204e9800998ecf8427e log4j-2.0-alpha1, log4j-2.0-alpha2, log4j-2.0-beta1, log4j-2.0-beta2, log4j-2.0-beta3, log4j-2.0-rc2, log4j-2.0.1, log4j-2.0.2, log4j-2.0, log4j-2.1, log4j-2.10.0, log4j-2.11.0, log4j-2.11.1, log4j-2.11.2, log4j-2.12.0, log4j-2.12.1, log4j-2.12.2, log4j-2.13.0, log4j-2.13.1, log4j-2.13.2, log4j-2.13.3, log4j-2.14.0, log4j-2.14.1, log4j-2.15.0, log4j-2.16.0, log4j-2.17.0, log4j-2.2, log4j-2.3, log4j-2.4.1, log4j-2.4, log4j-2.5, log4j-2.6.1, log4j-2.6.2, log4j-2.6, log4j-2.7, log4j-2.8.1, log4j-2.8.2, log4j-2.8, log4j-2.9.0, log4j-2.9.1
  #97b35c87df2bdeb5c6ec96da87a8a41d log4j-2.0-beta4
  #a38bbf52caa31c8925d7e76ebd621239 log4j-2.0-beta5, log4j-2.0-beta6, log4j-2.0-beta7, log4j-2.0-beta8, log4j-2.0-beta9
  #3479f374c0179ccf0be61aef9c7e1988 log4j-2.0-rc1
  #org/apache/logging/log4j/core/util/NetUtils.class:
  #d41d8cd98f00b204e9800998ecf8427e log4j-2.0-alpha1, log4j-2.0-alpha2, log4j-2.0-beta1, log4j-2.0-beta2, log4j-2.0-beta3, log4j-2.0-beta4, log4j-2.0-beta5, log4j-2.0-beta6, log4j-2.0-beta7, log4j-2.0-beta8, log4j-2.0-beta9, log4j-2.0-rc1
  #7491c710314b1a076cdc69b81d1fdea1 log4j-2.0-rc2, log4j-2.0.1, log4j-2.0.2, log4j-2.0, log4j-2.1, log4j-2.2, log4j-2.3
  #24d6b9ae204d9a37b303acd924dd6631 log4j-2.4
  #513bb907af7070a2647fe316ca64d873 log4j-2.10.0, log4j-2.11.0, log4j-2.11.1, log4j-2.11.2, log4j-2.4.1, log4j-2.5, log4j-2.6.1, log4j-2.6.2, log4j-2.6, log4j-2.7, log4j-2.8.1, log4j-2.8, log4j-2.9.0, log4j-2.9.1
  #ab51a92ad721b527995abb8356df606a log4j-2.8.2
  #350a8a66d43690f417230a7217a28b62 log4j-2.12.0
  #e8dc5fab48ad3f347ea985b82ba48070 log4j-2.12.1, log4j-2.12.2
  #c7be540c8190bef020ba8706d330a174 log4j-2.13.0, log4j-2.13.1, log4j-2.13.2, log4j-2.13.3
  #a9bb8c2e829e31f572acfb9deacdc5d1 log4j-2.14.0
  #0cb33855431be6bc71db5d1fc65b3255 log4j-2.14.1
  #c706f4aa72f20de083b51ff9f5cdcb68 log4j-2.15.0, log4j-2.16.0, log4j-2.17.0

  # NetUtils.class
  #
  # the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations.
  # When the logging configuration uses a non-default Pattern Layout with a Context Lookup (for example, $${ctx:loginId}),
  #   attackers with control over Thread Context Map (MDC) input data can craft malicious input data using a JNDI Lookup pattern,
  #   resulting in an information leak and remote code execution in some environments and local code execution in all environments;
  #   remote code execution has been demonstrated on macOS but no other tested environments.
  #

  #"d41d8cd98f00b204e9800998ecf8427e": ["UNK", ["CVE-2021-44228", ], "helpers/NetUtils.class", "log4j-alpha1 - tbd" ],
  "97b35c87df2bdeb5c6ec96da87a8a41d": ["UNK", ["CVE-2021-44228", ], "helpers/NetUtils.class", "log4j-2.0-beta4" ],
  "a38bbf52caa31c8925d7e76ebd621239": ["UNK", ["CVE-2021-44228", ], "helpers/NetUtils.class", "log4j-2.0-beta5 - 2.0-beta9" ],
  "3479f374c0179ccf0be61aef9c7e1988": ["UNK", ["CVE-2021-44228", ], "helpers/NetUtils.class", "log4j-2.0-rc1" ],

  #"d41d8cd98f00b204e9800998ecf8427e": ["UNK", ["CVE-2021-44228", ], "util/NetUtils.class", "log4j-2.0-apha1 - 2.0-rc1" ],
  "7491c710314b1a076cdc69b81d1fdea1": ["UNK" , ["CVE-2021-44228", ], "util/NetUtils.class", "log4j-2.0-rc2 - 2.3" ],
  "24d6b9ae204d9a37b303acd924dd6631": ["UNK" , ["CVE-2021-44228", ], "util/NetUtils.class", "log4j-2.4" ],
  "513bb907af7070a2647fe316ca64d873": ["UNK" , ["CVE-2021-44228", ], "util/NetUtils.class", "log4j-2.4.1 - 2.11.2 except 2.8.2" ],
  "ab51a92ad721b527995abb8356df606a": ["UNK" , ["CVE-2021-44228", ], "util/NetUtils.class", "log4j-2.8.2" ],
  "350a8a66d43690f417230a7217a28b62": ["UNK" , ["CVE-2021-44228", ], "util/NetUtils.class", "log4j-2.12.0" ],
  "e8dc5fab48ad3f347ea985b82ba48070": ["UNK" , ["CVE-2021-44228", ], "util/NetUtils.class", "log4j-2.12.1" ],
  "c7be540c8190bef020ba8706d330a174": ["UNK" , ["CVE-2021-44228", ], "util/NetUtils.class", "log4j-2.13.0 - 2.13.3" ],
  "a9bb8c2e829e31f572acfb9deacdc5d1": ["UNK" , ["CVE-2021-44228", ], "util/NetUtils.class", "log4j-2.14.0" ],
  "0cb33855431be6bc71db5d1fc65b3255": ["UNK" , ["CVE-2021-44228", ], "util/NetUtils.class", "log4j-2.14.1" ],
  "c706f4aa72f20de083b51ff9f5cdcb68": ["GOOD", ["CVE-2021-44228", ], "util/NetUtils.class", "log4j-2.15.0 - 2.17.0" ],


  #./fingerprint.sh SslConfiguration.class
  #org/apache/logging/log4j/core/net/ssl/SSLConfiguration.class:
  #d41d8cd98f00b204e9800998ecf8427e log4j-2.0-alpha1, log4j-2.0-alpha2, log4j-2.0-beta1, log4j-2.0-beta2, log4j-2.0-beta3, log4j-2.0-beta4, log4j-2.0-beta5, log4j-2.0-beta6, log4j-2.0-beta7, log4j-2.0-beta8, log4j-2.0-rc2, log4j-2.0.1, log4j-2.0.2, log4j-2.0, log4j-2.1, log4j-2.10.0, log4j-2.11.0, log4j-2.12.0, log4j-2.12.1, log4j-2.12.2, log4j-2.13.0, log4j-2.13.1, log4j-2.13.2, log4j-2.13.3, log4j-2.14.0, log4j-2.14.1, log4j-2.15.0, log4j-2.16.0, log4j-2.17.0, log4j-2.2, log4j-2.3, log4j-2.4, log4j-2.5, log4j-2.6, log4j-2.7, log4j-2.8.1, log4j-2.8.2, log4j-2.8, log4j-2.9.0
  #b769a024f4ab34407086b01c452b1484 log4j-2.0-beta9
  #80a64a068388ce19879ba6776f50cd0f log4j-2.0-rc1
  #org/apache/logging/log4j/core/net/ssl/SslConfiguration.class:
  #d41d8cd98f00b204e9800998ecf8427e log4j-2.0-alpha1, log4j-2.0-alpha2, log4j-2.0-beta1, log4j-2.0-beta2, log4j-2.0-beta3, log4j-2.0-beta4, log4j-2.0-beta5, log4j-2.0-beta6, log4j-2.0-beta7, log4j-2.0-beta8, log4j-2.0-beta9, log4j-2.0-rc1
  #dbe11ed10f463c7b3f02ce6217bdfb7c log4j-2.0-rc2, log4j-2.0.1, log4j-2.0.2, log4j-2.0
  #616966d52e8b133fbd9b1145dc1178e2 log4j-2.1, log4j-2.2, log4j-2.3
  #6e55ee689ea2a42ab1b65e5ff1fdc2f0 log4j-2.4, log4j-2.5
  #4221faf04d16f17e5f4443221752388b log4j-2.6
  #78e024118884cd8cca83612f6251fa84 log4j-2.7
  #99a1f669b5afa792eb320de15b54921f log4j-2.8.1, log4j-2.8
  #748e9b5869d71bf7affcb3fa05b6bba2 log4j-2.8.2
  #55d54e40eb77cbfd425f4af89a3141d9 log4j-2.10.0, log4j-2.11.0, log4j-2.9.0
  #9f68652e73cfefdfd5bd0d5b40bf5b02 log4j-2.12.0, log4j-2.12.1, log4j-2.12.2
  #2fe2f3d6463729bc3d98ffc9ad618424 log4j-2.13.0, log4j-2.13.1
  #dfae17f8ce6f3cd0c10568d6f4c2b567 log4j-2.13.2, log4j-2.13.3
  #3f5380016304dbc89cdf87673982ae0c log4j-2.14.0
  #55ee19ab417d95b805807fed8d9a8414 log4j-2.14.1, log4j-2.15.0, log4j-2.16.0, log4j-2.17.0

  # SSLConfiguration.class
  #  CVE-2020-9488 - All versions from 2.0-alpha1 to 2.13.1
  #  Improper validation of certificate with host mismatch in Apache Log4j SMTP appender.
  #  Users should upgrade to Apache Log4j 2.13.2
  # https://logging.apache.org/log4j/2.x/security.html

  #"d41d8cd98f00b204e9800998ecf8427e": ["UNK",["CVE-2020-9488", ], "SSLConfiguration.class", "log4j-2.0-alpha1 - 2.0-beta8, log4j-2.0-rc2 ..." ],
  "b769a024f4ab34407086b01c452b1484": ["UNK", ["CVE-2020-9488", ], "SSLConfiguration.class", "log4j-2.0-beta9, " ],
  "80a64a068388ce19879ba6776f50cd0f": ["UNK", ["CVE-2020-9488", ], "SSLConfiguration.class", "log4j-2.0-rc1, " ],

  # SslConfiguration.class
  #  CVE-2020-9488 - All versions from 2.0-alpha1 to 2.13.1
  #  Improper validation of certificate with host mismatch in Apache Log4j SMTP appender.
  #  Users should upgrade to Apache Log4j 2.13.2
  # https://logging.apache.org/log4j/2.x/security.html
  #"d41d8cd98f00b204e9800998ecf8427e": ["BAD", ["CVE-2020-9488", ], "SslConfiguration.class", "log4j-2.0-alpha1 - 2.0-rc1" , ],
  "dbe11ed10f463c7b3f02ce6217bdfb7c":  ["BAD",  ["CVE-2020-9488", ], "SslConfiguration.class", "log4j-2.0-rc2 - 2.0.2" , ],
  "616966d52e8b133fbd9b1145dc1178e2":  ["BAD", ["CVE-2020-9488", ], "SslConfiguration.class", "log4j-2.1 - 2.3" , ],
  "6e55ee689ea2a42ab1b65e5ff1fdc2f0":  ["BAD", ["CVE-2020-9488", ], "SslConfiguration.class", "log4j-2.4-2.5" , ],
  "4221faf04d16f17e5f4443221752388b":  ["BAD", ["CVE-2020-9488", ], "SslConfiguration.class", "log4j-2.6" , ],
  "78e024118884cd8cca83612f6251fa84":  ["BAD", ["CVE-2020-9488", ], "SslConfiguration.class", "log4j-2.7" , ],
  "99a1f669b5afa792eb320de15b54921f":  ["BAD", ["CVE-2020-9488", ], "SslConfiguration.class", "log4j-2.8 - 2.8.1", ],
  "748e9b5869d71bf7affcb3fa05b6bba2":  ["BAD", ["CVE-2020-9488", ], "SslConfiguration.class", "log4j-2.8.2" , ],
  "55d54e40eb77cbfd425f4af89a3141d9":  ["BAD", ["CVE-2020-9488", ], "SslConfiguration.class", "log4j-2.9.0 - 2.11.0", ],
  "9f68652e73cfefdfd5bd0d5b40bf5b02":  ["BAD", ["CVE-2020-9488", ], "SslConfiguration.class", "log4j-2.12.0 - 2.12.2" , ],
  "2fe2f3d6463729bc3d98ffc9ad618424":  ["BAD", ["CVE-2020-9488", ], "SslConfiguration.class", "log4j-2.13.0 - 2.13.1" , ],
  "dfae17f8ce6f3cd0c10568d6f4c2b567":  ["GOOD", ["CVE-2020-9488", ], "SslConfiguration.class", "log4j-2.13.2 - 2.13.3" , ],
  "3f5380016304dbc89cdf87673982ae0c":  ["GOOD", ["CVE-2020-9488", ], "SslConfiguration.class", "log4j-2.14.0" , ],
  "55ee19ab417d95b805807fed8d9a8414":  ["GOOD", ["CVE-2020-9488", ], "SslConfiguration.class", "log4j-2.15.0 - 2.17.0" , ],

  #./fingerprint.sh UdpSocketServer.class
  #org/apache/logging/log4j/core/net/server/UdpSocketServer.class:
  #d41d8cd98f00b204e9800998ecf8427e log4j-2.0-alpha1, log4j-2.0-alpha2, log4j-2.0-beta1, log4j-2.0-beta2, log4j-2.0-beta3, log4j-2.0-beta4, log4j-2.0-beta5, log4j-2.0-beta6, log4j-2.0-beta7, log4j-2.0-beta8, log4j-2.0-beta9, log4j-2.0-rc1, log4j-2.10.0, log4j-2.11.0, log4j-2.12.0, log4j-2.12.1, log4j-2.12.2, log4j-2.13.0, log4j-2.13.1, log4j-2.13.2, log4j-2.13.3, log4j-2.14.0, log4j-2.14.1, log4j-2.15.0, log4j-2.16.0, log4j-2.17.0, log4j-2.9.0
  #f150389cc35c093317d0de0c1d5232cc log4j-2.0-rc2, log4j-2.0.1, log4j-2.0.2, log4j-2.0, log4j-2.1, log4j-2.2, log4j-2.3
  #d6584344dc4c7b8e4262cab63913e77e log4j-2.4
  #f2a64847dbf26641b0b4aac6b409e019 log4j-2.5, log4j-2.6
  #e307ead3d56edd9cc231a474f8553cb1 log4j-2.7
  #6a7e0c502d8060f24dd53ae3e706b2ea log4j-2.8.2
  #de8eff8b18c947e48b41f0ceef3cf0a8 log4j-2.8.1, log4j-2.8
  #org/apache/logging/log4j/core/net/UDPSocketServer.class:
  #d41d8cd98f00b204e9800998ecf8427e log4j-2.0-alpha1, log4j-2.0-alpha2, log4j-2.0-beta1, log4j-2.0-beta2, log4j-2.0-beta3, log4j-2.0-beta4, log4j-2.0-beta5, log4j-2.0-beta6, log4j-2.0-rc2, log4j-2.0.1, log4j-2.0.2, log4j-2.0, log4j-2.1, log4j-2.10.0, log4j-2.11.0, log4j-2.12.0, log4j-2.12.1, log4j-2.12.2, log4j-2.13.0, log4j-2.13.1, log4j-2.13.2, log4j-2.13.3, log4j-2.14.0, log4j-2.14.1, log4j-2.15.0, log4j-2.16.0, log4j-2.17.0, log4j-2.2, log4j-2.3, log4j-2.4, log4j-2.5, log4j-2.6, log4j-2.7, log4j-2.8.1, log4j-2.8.2, log4j-2.8, log4j-2.9.0
  #d2f0972e55db4f53aa5a696cbd152c1b log4j-2.0-beta8, log4j-2.0-beta9, log4j-2.0-rc1
  #da56f5233cff214fb69c7db106af5ccb log4j-2.0-beta7


  # UdpSocketServer.class
  # CVE-2017-5645 -  All versions from 2.0-alpha1 to 2.8.1
  # Apache Log4j socket receiver deserialization vulnerability
  #"d41d8cd98f00b204e9800998ecf8427e": ["BAD", ["CVE-2017-5645", ], "UdpSocketServer.class", "log4j-alpha1 - 2.0-rc1" ],
  "f150389cc35c093317d0de0c1d5232cc": ["BAD", ["CVE-2017-5645", ], "UdpSocketServer.class", "log4j-2.0-rc2 - 2.3" , ],
  "d6584344dc4c7b8e4262cab63913e77e": ["BAD", ["CVE-2017-5645", ], "UdpSocketServer.class", "log4j-2.4" , ],
  "f2a64847dbf26641b0b4aac6b409e019": ["BAD", ["CVE-2017-5645", ], "UdpSocketServer.class", "log4j-2.5 - 2.6", ],
  "e307ead3d56edd9cc231a474f8553cb1": ["BAD", ["CVE-2017-5645", ], "UdpSocketServer.class", "log4j-2.7" , ],
  "de8eff8b18c947e48b41f0ceef3cf0a8": ["BAD", ["CVE-2017-5645", ], "UdpSocketServer.class", "log4j-2.8 - 2.8.1" , ],
  "6a7e0c502d8060f24dd53ae3e706b2ea": ["GOOD", ["CVE-2017-5645", ], "UdpSocketServer.class", "log4j-2.8.2" , ],

  # UDPSocketServer.class
  # CVE-2017-5645 -  All versions from 2.0-alpha1 to 2.8.1
  # Apache Log4j socket receiver deserialization vulnerability
  #"d41d8cd98f00b204e9800998ecf8427e": ["UNK", ["CVE-2017-5645", ], "UDPSocketServer.class", "log4j-2.0-apha1 - 2.0-beta6, 2.0-rc2" , ],
  "da56f5233cff214fb69c7db106af5ccb": ["UNK", ["CVE-2017-5645", ], "UDPSocketServer.class", "log4j-2.0-beta7" , ],
  "d2f0972e55db4f53aa5a696cbd152c1b": ["UNK", ["CVE-2017-5645", ], "UDPSocketServer.class", "log4j2.0-beta8 - 2.0-rc1" , ],


  #./fingerprint.sh TcpSocketServer.class
  #org/apache/logging/log4j/core/net/server/TcpSocketServer.class:
  #d41d8cd98f00b204e9800998ecf8427e log4j-2.0-alpha1, log4j-2.0-alpha2, log4j-2.0-beta1, log4j-2.0-beta2, log4j-2.0-beta3, log4j-2.0-beta4, log4j-2.0-beta5, log4j-2.0-beta6, log4j-2.0-beta7, log4j-2.0-beta8, log4j-2.0-beta9, log4j-2.0-rc1, log4j-2.10.0, log4j-2.11.0, log4j-2.12.0, log4j-2.12.1, log4j-2.12.2, log4j-2.13.0, log4j-2.13.1, log4j-2.13.2, log4j-2.13.3, log4j-2.14.0, log4j-2.14.1, log4j-2.15.0, log4j-2.16.0, log4j-2.17.0, log4j-2.9.0
  #5956bfbe03694c03a49f475c463d9380 log4j-2.0-rc2, log4j-2.0.1, log4j-2.0.2, log4j-2.0, log4j-2.1, log4j-2.2, log4j-2.3
  #eeb0159da295e679ce1811cf9f242ea0 log4j-2.4
  #075c1d1c6ecb0990de54219b439bc265 log4j-2.5
  #dfdcbdc8b953334f56d88eb5ca3777c1 log4j-2.6
  #55d335f56a101ac89e7037738b0f21cc log4j-2.7
  #51f7dc33de85e108fafad10c4ac55d38 log4j-2.8.1, log4j-2.8
  #1b6f5039841948a1015e375f130d38f0 log4j-2.8.2

  # TcpSocketServer.class
  # CVE-2017-5645 -  All versions from 2.0-alpha1 to 2.8.1
  # Apache Log4j socket receiver deserialization vulnerability

  #"d41d8cd98f00b204e9800998ecf8427e": ["BAD", ["CVE-2017-5645", ], "TcpSocketServer.class", "log4j-alpha1 - 2.0-rc1" , ],
  "5956bfbe03694c03a49f475c463d9380": ["BAD", ["CVE-2017-5645", ], "TcpSocketServer.class", "log4j-2.0-rc2 - 2.3" , ],
  "eeb0159da295e679ce1811cf9f242ea0": ["BAD", ["CVE-2017-5645", ], "TcpSocketServer.class", "log4j-2.4" , ],
  "075c1d1c6ecb0990de54219b439bc265": ["BAD", ["CVE-2017-5645", ], "TcpSocketServer.class", "log4j-2.5" , ],
  "dfdcbdc8b953334f56d88eb5ca3777c1": ["BAD", ["CVE-2017-5645", ], "TcpSocketServer.class", "log4j-2.6" , ],
  "55d335f56a101ac89e7037738b0f21cc": ["BAD", ["CVE-2017-5645", ], "TcpSocketServer.class", "log4j-2.7" , ],
  "51f7dc33de85e108fafad10c4ac55d38": ["BAD", ["CVE-2017-5645", ], "TcpSocketServer.class", "log4j-2.8 - 2.8.1", ],
  "1b6f5039841948a1015e375f130d38f0": ["GOOD", ["CVE-2017-5645", ], "TcpSocketServer.class", "log4j-2.8.2" , ],

  #./fingerprint.sh AbstractSocketServer.class
  #org/apache/logging/log4j/core/net/server/AbstractSocketServer.class:
  #d41d8cd98f00b204e9800998ecf8427e log4j-2.0-alpha1, log4j-2.0-alpha2, log4j-2.0-beta1, log4j-2.0-beta2, log4j-2.0-beta3, log4j-2.0-beta4, log4j-2.0-beta5, log4j-2.0-beta6, log4j-2.0-beta7, log4j-2.0-beta8, log4j-2.0-beta9, log4j-2.0-rc1, log4j-2.10.0, log4j-2.11.0, log4j-2.11.1, log4j-2.11.2, log4j-2.12.0, log4j-2.12.1, log4j-2.12.2, log4j-2.13.0, log4j-2.13.1, log4j-2.13.2, log4j-2.13.3, log4j-2.14.0, log4j-2.14.1, log4j-2.15.0, log4j-2.16.0, log4j-2.17.0, log4j-2.9.0, log4j-2.9.1
  #b0d5fa430faa5b9c1bf8f43144a1068d log4j-2.0-rc2, log4j-2.0.1, log4j-2.0.2, log4j-2.0, log4j-2.1, log4j-2.2, log4j-2.3
  #64c39f57452c179d7c02f98b3af24deb log4j-2.4.1, log4j-2.4
  #db35da6307a413f2a6af7770a72378b5 log4j-2.5, log4j-2.6.1, log4j-2.6.2, log4j-2.6
  #6707deed38a55eebc49fa531a9270cf9 log4j-2.7
  #61cfc0baf9e27ba3c62c6c8da1d7aae5 log4j-2.8.1, log4j-2.8
  #3ed6e916801a18764d85fb20ec9c0237 log4j-2.8.2

  # AbstractSocketServer.class
  # CVE-2017-5645 -  All versions from 2.0-alpha1 to 2.8.1
  # Apache Log4j socket receiver deserialization vulnerability

 #"d41d8cd98f00b204e9800998ecf8427e": ["BAD",  ["CVE-2017-5645", ], "AbstractSocketServer.class", "log4j-2.0-alpha1 - 2.0-rc1" , ],
 "b0d5fa430faa5b9c1bf8f43144a1068d":  ["BAD",  ["CVE-2017-5645", ], "AbstractSocketServer.class", "log4j-2.0-rc2 - 2.3" , ],
 "64c39f57452c179d7c02f98b3af24deb":  ["BAD",  ["CVE-2017-5645", ], "AbstractSocketServer.class", "log4j-2.4" , ],
 "db35da6307a413f2a6af7770a72378b5":  ["BAD",  ["CVE-2017-5645", ], "AbstractSocketServer.class", "log4j-2.5 - 2.6" , ],
 "6707deed38a55eebc49fa531a9270cf9":  ["BAD",  ["CVE-2017-5645", ], "AbstractSocketServer.class", "log4j-2.7" , ],
 "61cfc0baf9e27ba3c62c6c8da1d7aae5":  ["BAD",  ["CVE-2017-5645", ], "AbstractSocketServer.class", "log4j-2.8 - 2.8.1", ],
 "3ed6e916801a18764d85fb20ec9c0237":  ["GOOD", ["CVE-2017-5645", ], "AbstractSocketServer.class", "log4j-2.8.2", ],


  #./fingerprint.sh ObjectInputStreamLogEventBridge.class
  #org/apache/logging/log4j/core/net/server/ObjectInputStreamLogEventBridge.class:
  #d41d8cd98f00b204e9800998ecf8427e log4j-2.0-alpha1, log4j-2.0-alpha2, log4j-2.0-beta1, log4j-2.0-beta2, log4j-2.0-beta3, log4j-2.0-beta4, log4j-2.0-beta5, log4j-2.0-beta6, log4j-2.0-beta7, log4j-2.0-beta8, log4j-2.0-beta9, log4j-2.0-rc1, log4j-2.10.0, log4j-2.11.0, log4j-2.11.1, log4j-2.11.2, log4j-2.12.0, log4j-2.12.1, log4j-2.12.2, log4j-2.13.0, log4j-2.13.1, log4j-2.13.2, log4j-2.13.3, log4j-2.14.0, log4j-2.14.1, log4j-2.15.0, log4j-2.16.0, log4j-2.17.0, log4j-2.9.0, log4j-2.9.1
  #f80255e901638c7b2c30af919d642d26 log4j-2.0-rc2, log4j-2.0.1, log4j-2.0.2, log4j-2.0, log4j-2.1, log4j-2.2, log4j-2.3
  #36915baed3c990403897704bcddfb94b log4j-2.4.1, log4j-2.4, log4j-2.5, log4j-2.6.1, log4j-2.6.2, log4j-2.6, log4j-2.7, log4j-2.8.1, log4j-2.8
  #a2368326af6b390e87cdd1e717b7c273 log4j-2.8.2

  # ObjectInputStreamLogEventBridge.class
  # TcpSocketServer.class
  # UdpSocketServer.class
  # CVE-2017-5645 -  All versions from 2.0-alpha1 to 2.8.1
  # Apache Log4j socket receiver deserialization vulnerability
  # https://github.com/pimps/CVE-2017-5645/blob/master/log4j%20advisory.txt

  #"d41d8cd98f00b204e9800998ecf8427e": ["BAD", ["CVE-2017-5645", ], "ObjectInputStreamLogEventBridge.class", "log4j-2.0-apha1 - 2.0-rc1, ..." , ],
  "f80255e901638c7b2c30af919d642d26": ["BAD", ["CVE-2017-5645", ], "ObjectInputStreamLogEventBridge.class", "log4j-2.0-rc2 - 2.3" , ],
  "36915baed3c990403897704bcddfb94b": ["BAD", ["CVE-2017-5645", ], "ObjectInputStreamLogEventBridge.class", "log4j-2.4 - 2.8.1" , ],
  "a2368326af6b390e87cdd1e717b7c273": ["GOOD", ["CVE-2017-5645",], "ObjectInputStreamLogEventBridge.class", "log4j-2.8.2" , ],

}

#ref: https://logging.apache.org/log4j/2.x/security.html#CVE-2021-45105
cve2issue_map = {
  "CVE-2021-45105" : ["LOG4J2-3230",],
  "CVE-2021-45046" : ["LOG4J2-3221",],
  "CVE-2021-44228" : ["LOG4J2-3201","LOG4J2-3198",],
  "CVE-2020-9488"  : ["LOG4J2-2819",],
  "CVE-2017-5645"  : ["LOG4J2-1863",]
}

cve2sev_map = {
  "CVE-2021-45105" : "High - https://nvd.nist.gov/vuln/detail/CVE-2021-45105",
  "CVE-2021-45046" : "Low - https://nvd.nist.gov/vuln/detail/CVE-2021-45046",
  "CVE-2021-44228" : "Critical - https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
  "CVE-2020-9488"  : "Low - https://nvd.nist.gov/vuln/detail/CVE-2020-9488",
  "CVE-2017-5645"  : "Critical - https://nvd.nist.gov/vuln/detail/CVE-2017-5645"
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

def check_vulnerable(fobj, path_chain, stats):
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

  empty_list = [ "UNK", ["unknown", ], "", "", ]
  v = MD5_HASHES.get(md5sum, empty_list)

  comment = v[3]
  color_map = {"vulnerable": red, "good": green, "patched": cyan, "unknown": yellow}
  d = { "UNK": "unknown", "GOOD" :"good", "BAD" : "vulnerable"}

  status = d.get(v[0], "vulnerable")

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
  args = parser.parse_args()
  logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
  )
  python_version = platform.python_version()
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
          if p.name.lower() in FILENAMES:
            check_vulnerable(fobj, [p], stats)
      if p.suffix.lower() in JAR_EXTENSIONS:
        try:
          log.info(f"Found jar file: {p}")
          stats["scanned"] += 1
          for (zinfo, zfile, zpath, parents) in iter_jarfile( 
            p.open("rb"), parents=[p] 
          ):
            log.info(f"Found zfile: {zinfo} ({parents}")
            with zfile.open(zinfo.filename) as zf:
              check_vulnerable(zf, parents + [zpath], stats)
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
