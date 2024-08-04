Rust sshidentify
================

The Rust `sshidentify` can be used to gain information about the
SSH key, that has been used for the current connection. There are
two different ways to get this:

1. `get_ssh_exposeauth_info()`

This is available when the crate is build with the "exposeauth"
feature. The function is only usable if OpenSSH has ExposeAuthInfo
enabled in `sshd_config`. Note, that the default of that option
is disabled. Using this way is usually preferred.

2. `get_ssh_journal_info()`

This is available when the crate is build with the "journal"
feature. The function will traverse through the process tree to
find the parent sshd PID. Once found the PID is being used to check
the systemd journal for the key fingerprint having been used for
the connection. Last but not least the `~/.ssh/authorized_keys` is
being examined to find the public key for the fingerprint.

NOTE: The resulting binary must be called with permissions to
access the system's systemd journal to be functional.

Examples
========

```rust
fn main() {
	let info = sshidentify::get_ssh_exposeauth_info().unwrap()
    println!("SSH Info: {:?}", info);
}
```

```rust
fn main() {
	let info = sshidentify::get_ssh_journal_info().unwrap()
    println!("SSH Info: {:?}", info);
}
```

License
=======

© 2018-2024 Sebastian Reichel

ISC License

Permission to use, copy, modify, and/or distribute this software for
any purpose with or without fee is hereby granted, provided that the
above copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
