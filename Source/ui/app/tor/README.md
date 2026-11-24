# Built-in Tor bridges

`pt_config.json` is the file of the same name from the official Tor Expert
Bundle 16.0.1 (`tor/pluggable_transports/pt_config.json`), unchanged: the
bridges Tor Browser itself offers as built-in. The window reads the lists
`bridges.obfs4` and `bridges.snowflake` from it and nothing else; the line
`pluggableTransports` is not used (the program for bridges is always the
`lyrebird` that stands next to the wallet's own programs).

The bundle is fetched and checked by `get-tor-bridge-programs.ps1`: its
SHA-256 against the published list, the list's signature against the key of
the Tor Browser developers (EF6E286DDA85EA2A4BA7DE684E2C6E8793298290).

To renew the lists, take the file from a newer bundle checked the same way
and put it here; the test `the_built_in_bridges_are_those_of_the_bundle`
names the size of the file and how many bridges of each kind it holds, and
has to be renewed with it. SHA-256 of this copy:
3f11d303c30191b3b1d382b9badd882d87fd87550d061f7d25a1b31226fc9b75
