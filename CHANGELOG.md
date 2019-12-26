ChangeLog for rust-kpdb
=======================

This documents all notable changes to
[rust-kpdb](https://github.com/sru-systems/rust-kpdb).


## 0.4.1

- Make internal XML parser more tolerant.


## 0.4.0

- Export Times trait.


## 0.3.0

- Entries are now stored directly inside their group.
- The history of an entry is now stored inside the entry itself.
- Groups are now stored directly inside their parent group.
- The database's root group is now mandatory and will be created when missing.
- The database struct now has methods to find entries and groups.
- The entry struct now has some getters and setters to improve usability.
- The group struct now has methods to add and remove entries.
- The group struct now has methods to add and remove sub groups.
- Stop creating a recycle bin group when creating a new database.


## 0.2.0

- Update chrono dependency to 0.4.0.
- Replace rustc-serialize dependency with base64 and hex.
