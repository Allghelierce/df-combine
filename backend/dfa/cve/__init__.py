"""Local CVE database: built from public feeds, queried at scan time.

* :mod:`dfa.cve.build`  - download NVD (fkie-cad mirror), CISA KEV and Exploit-DB and build SQLite
* :mod:`dfa.cve.store`  - read-only access to the built database
* :mod:`dfa.cve.match`  - component/version matching and finding generation

Only the public feeds are downloaded; nothing about scanned firmware leaves the host.
"""
SCHEMA_VERSION = 1
