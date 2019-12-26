# Rust-kpdb

A Rust library for reading and writing [KeePass 2](http://keepass.info/) and
[KeePassX](https://www.keepassx.org/) databases.


## Usage

To use `rust-kpdb`, add the following to your Cargo.toml:

```toml
[dependencies]
rust-kpdb = "0.4"
```

And the following to your crate root:

```rust
extern crate kpdb;
```


## Examples

Create a new database adding two groups and two entries:

```rust
use kpdb::{CompositeKey, Database, Entry, Group};

// Create a new database.
let key = CompositeKey::from_password("password");
let mut db = Database::new(&key);

// Create a new group named Email.
let mut email_group = Group::new("Email");
let email_group_uuid = email_group.uuid;

// Create an entry for ProtonMail and add it to the Email group.
let mut protonmail = Entry::new();
let protonmail_uuid = protonmail.uuid;
protonmail.set_title("ProtonMail");
protonmail.set_username("mailuser");
protonmail.set_password("mailpass");
protonmail.set_url("https://mail.protonmail.com");
email_group.add_entry(protonmail);

// Create a new group named VPN.
let mut vpn_group = Group::new("VPN");

// Create an entry for ProtonVPN and add it to the VPN group.
let mut protonvpn = Entry::new();
protonvpn.set_title("ProtonVPN");
protonvpn.set_username("vpnuser");
protonvpn.set_password("vpnpass");
protonvpn.set_url("https://prontvpn.com");
vpn_group.add_entry(protonvpn);

// Add the Email and VPN groups to the Root group.
db.root_group.add_group(email_group);
db.root_group.add_group(vpn_group);

// Find groups matching "email".
let groups = db.find_groups("email");
assert_eq!(groups.len(), 1);

// Find entries matching "proton".
let entries = db.find_entries("proton");
assert_eq!(entries.len(), 2);

// Retrieve a group by its UUID.
let group = db.get_group(email_group_uuid).unwrap();
assert_eq!(group.name, "Email");

// Retrieve an entry by its UUID.
let entry = db.get_entry(protonmail_uuid).unwrap();
assert_eq!(entry.title(), Some("ProtonMail"));
assert_eq!(entry.username(), Some("mailuser"));
assert_eq!(entry.password(), Some("mailpass"));
assert_eq!(entry.url(), Some("https://mail.protonmail.com"));
assert_eq!(entry.notes(), None);
```

Open the existing KeePass database passwords.kdbx using the password
"password", print it and save it to new.kdbx:

```rust
use kpdb::{CompositeKey, Database};
use std::fs::File;

let mut file = File::open("passwords.kdbx").unwrap();
let key = CompositeKey::from_password("password");
let db = Database::open(&mut file, &key).unwrap();

println!("{:?}", db);

let mut file = File::create("new.kdbx").unwrap();
db.save(&mut file).unwrap();
```

Open the existing KeePass database passwords.kdbx using both the password
"password" and the key file passwords.key, print it and save it to new.kdbx:

```rust
use kpdb::{CompositeKey, Database, KeyFile};
use std::fs::File;

let mut file = File::open("passwords.key").unwrap();
let key_file = KeyFile::open(&mut file).unwrap();
let key = CompositeKey::from_both("password", key_file);

let mut file = File::open("passwords.kdbx").unwrap();
let db = Database::open(&mut file, &key).unwrap();

println!("{:?}", db);

let mut file = File::create("new.kdbx").unwrap();
db.save(&mut file).unwrap();
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
