# Rust-kpdb

A Rust library for reading and writing [KeePass 2](http://keepass.info/) and
[KeePassX](https://www.keepassx.org/) databases.


## Usage

To use `rust-kpdb`, add the following to your Cargo.toml:

```toml
[dependencies]
rust-kpdb = "0.2.0"
```

And the following to your crate root:

```rust
extern crate kpdb;
```


## Examples

Create a new database:

```rust
use kpdb::{CompositeKey, Database};

let key = CompositeKey::from_password("password");
let db = Database::new(&key);
```

Open the KeePass database passwords.kdbx using the password "password" and
print it:

```rust
use kpdb::{CompositeKey, Database};
use std::fs::File;

fn main() {
    let mut file = File::open("passwords.kdbx").unwrap();
    let key = CompositeKey::from_password("password");
    let db = Database::open(&mut file, &key).unwrap();
    println!("{:?}", db);
}
```

Open the KeePass database passwords.kdbx using both the password "password"
and the key file passwords.key and print it:

```rust
use kpdb::{CompositeKey, Database, KeyFile};
use std::fs::File;

fn main() {
    let mut file = File::open("passwords.key").unwrap();
    let key_file = KeyFile::open(&mut file).unwrap();
    let key = CompositeKey::from_both("password", key_file);

    let mut file = File::open("passwords.kdbx").unwrap();
    let db = Database::open(&mut file, &key).unwrap();
    println!("{:?}", db);
}
```

Save a new KeePass database to new.kdbx:

```rust
use kpdb::{CompositeKey, Database};
use std::fs::File;

fn main() {
    let key = CompositeKey::from_password("password");
    let db = Database::new(&key);
    let mut file = File::create("new.kdbx").unwrap();
    db.save(&mut file).unwrap();
}
```


## Not Implemented

The following features are currently not implemented:

- KeePass 1 databases.


## License

Rust-kpdb is dual licensed under the [MIT](LICENSE-MIT) and
[Apache 2.0](LICENSE-APACHE) licenses, the same licenses as the Rust compiler.


## Contributions

Contributions are welcome. By submitting a pull request you are agreeing to
make you work available under the license terms of the Rust-kpdb project.
