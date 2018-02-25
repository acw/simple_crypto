# Simple Crypto

A simple little Rust crypto library, to inspire competition.

This crate is being designed as a hobby project, because I enjoy the challenge
of writing good crypto, and it seems like a good way to get pretty deep into
Rust. Modules in the crate should include proper test cases, including both
positive and negative test cases against all critical code; this will suffice
as evidence of correctness until I can throw SAW and Cryptol at it to prove
functional equivalence to specification.

I will admit that I don't get terribly excited about timing attacks, and so
while I will try not to leave obvious timing holes, I may miss some. If you
see one, please create an issue or -- even better -- a pull request to fix it.

Documentation wanted! Particularly for beginners! If a library doesn't make
sense to you, or it's not clear where you should use it or what parameters
make sense, file an issue! I want to make sure that this library is usable by
people implementing crazy protocols -- I'm looking at you, Tor -- but I also
want to make sure there's an obvious path for beginners.

Patches always welcome! Constructive suggestions also very welcome. This
crate is a hobby project, but that doesn't mean it can't be useful.
