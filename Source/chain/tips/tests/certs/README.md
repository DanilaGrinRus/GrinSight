Certificates and keys for the tests of this crate only. They were made for
a server that listens on this computer during a test, name nothing real and
protect nothing: the keys are public by being here. The keys of the two test
authorities were thrown away when the files were made.

- `ca.pem` - the authority the tests trust.
- `localhost` - a certificate of that authority for the name `localhost`.
- `elsewhere` - one of the same authority for another name.
- `stranger` - one for `localhost` from an authority the tests do not trust.
- `past` - one for `localhost` that ended on 1 February 2026.
