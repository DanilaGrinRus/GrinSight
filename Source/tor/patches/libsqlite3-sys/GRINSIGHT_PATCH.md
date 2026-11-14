# libsqlite3-sys 0.37.0 with SQLite 3.54.1 (GrinSight patch)

Crate libsqlite3-sys 0.37.0 as published, with ONLY the bundled SQLite
amalgamation replaced (sqlite3/sqlite3.c, sqlite3.h, sqlite3ext.h) by the one
of libsqlite3-sys 0.39.1 (SQLite 3.54.1), which fixes CVE-2026-119375 /
RUSTSEC-2026-0459. Reason: arti's tor-dirmgr 0.43 accepts rusqlite < 0.40,
and only rusqlite 0.41 uses libsqlite3-sys 0.39. The Rust bindings of 0.37
are kept (SQLite keeps its C ABI backwards compatible). The `sqlcipher`
directory is removed (feature not used).

Checked by grinsight-tor test `bundled_sqlite_has_the_cve_fix`.
Remove this patch when arti allows rusqlite >= 0.41.
