// Copyright (c) 2016-2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Module containing constants for the KeePass 2 database format.

/// The identifier of the AES cipher.
pub const AES_CIPHER_ID: [u8; 16] = [
    0x31, 0xc1, 0xf2, 0xe6, 0xbf, 0x71, 0x43, 0x50, 0xbe, 0x58, 0x05, 0x21, 0x6a, 0xfc, 0x5a, 0xff,
];

/// The hash of the final block.
pub const FINAL_BLOCK_HASH: [u8; 32] = [0; 32];

/// The identifier of the comment header.
pub const COMMENT_HID: u8 = 1;

/// The identifier of the compression header.
pub const COMPRESSION_HID: u8 = 3;

/// The size of the compression header data.
pub const COMPRESSION_SIZE: u16 = 4;

/// The identifier of the end header.
pub const END_HID: u8 = 0;

/// The identifier of the master cipher header.
pub const MASTER_CIPHER_HID: u8 = 2;

/// The size of the master cipher header data.
pub const MASTER_CIPHER_SIZE: u16 = 16;

/// The identifier of the master initialization vector header.
pub const MASTER_IV_HID: u8 = 7;

/// The size of the master initialization vector header data.
pub const MASTER_IV_SIZE: u16 = 16;

/// The identifier of the master seed header.
pub const MASTER_SEED_HID: u8 = 4;

/// The size of the master seed header data.
pub const MASTER_SEED_SIZE: u16 = 32;

/// The identifier of the protected stream key header.
pub const PROTECTED_STREAM_KEY_HID: u8 = 8;

/// The size of the protected stream key header data.
pub const PROTECTED_STREAM_KEY_SIZE: u16 = 32;

/// The identifier of the stream cipher header.
pub const STREAM_CIPHER_HID: u8 = 10;

/// The size of the stream cipher header data.
pub const STREAM_CIPHER_SIZE: u16 = 4;

/// The identifier of the stream start bytes header.
pub const STREAM_START_BYTES_HID: u8 = 9;

/// The size of the stream start bytes header data.
pub const STREAM_START_BYTES_SIZE: u16 = 32;

/// The identifier of the transform rounds header.
pub const TRANSFORM_ROUNDS_HID: u8 = 6;

/// The size of the transform rounds header data.
pub const TRANSFORM_ROUNDS_SIZE: u16 = 8;

/// The identifier of the transform seed header.
pub const TRANSFORM_SEED_HID: u8 = 5;

/// The size of the transform seed header data.
pub const TRANSFORM_SEED_SIZE: u16 = 32;

// Tags
pub const ASSOCIATION_TAG: &str = "Association";
pub const AUTO_TYPE_TAG: &str = "AutoType";
pub const BACKGROUND_COLOR_TAG: &str = "BackgroundColor";
pub const BINARIES_TAG: &str = "Binaries";
pub const BINARY_TAG: &str = "Binary";
pub const COLOR_TAG: &str = "Color";
pub const CREATION_TIME_TAG: &str = "CreationTime";
pub const CUSTOM_DATA_TAG: &str = "CustomData";
pub const CUSTOM_ICONS_TAG: &str = "CustomIcons";
pub const CUSTOM_ICON_UUID_TAG: &str = "CustomIconUUID";
pub const DATABASE_DESCRIPTION_CHANGED_TAG: &str = "DatabaseDescriptionChanged";
pub const DATABASE_DESCRIPTION_TAG: &str = "DatabaseDescription";
pub const DATABASE_NAME_CHANGED_TAG: &str = "DatabaseNameChanged";
pub const DATABASE_NAME_TAG: &str = "DatabaseName";
pub const DATA_TAG: &str = "Data";
pub const DATA_TRANSFER_OBFUSCATION_TAG: &str = "DataTransferObfuscation";
pub const DEFAULT_AUTO_TYPE_SEQUENCE_TAG: &str = "DefaultAutoTypeSequence";
pub const DEFAULT_SEQUENCE_TAG: &str = "DefaultSequence";
pub const DEFAULT_USERNAME_CHANGED_TAG: &str = "DefaultUserNameChanged";
pub const DEFAULT_USERNAME_TAG: &str = "DefaultUserName";
pub const ENABLED_TAG: &str = "Enabled";
pub const ENABLE_AUTO_TYPE_TAG: &str = "EnableAutoType";
pub const ENABLE_SEARCHING_TAG: &str = "EnableSearching";
pub const ENTRY_TAG: &str = "Entry";
pub const ENTRY_TEMPLATES_GROUP_CHANGED_TAG: &str = "EntryTemplatesGroupChanged";
pub const ENTRY_TEMPLATES_GROUP_TAG: &str = "EntryTemplatesGroup";
pub const EXPIRES_TAG: &str = "Expires";
pub const EXPIRY_TIME_TAG: &str = "ExpiryTime";
pub const FOREGROUND_COLOR_TAG: &str = "ForegroundColor";
pub const GENERATOR_TAG: &str = "Generator";
pub const GROUP_TAG: &str = "Group";
pub const HEADER_HASH_TAG: &str = "HeaderHash";
pub const HISTORY_MAX_ITEMS_TAG: &str = "HistoryMaxItems";
pub const HISTORY_MAX_SIZE_TAG: &str = "HistoryMaxSize";
pub const HISTORY_TAG: &str = "History";
pub const ICON_ID_TAG: &str = "IconID";
pub const ICON_TAG: &str = "Icon";
pub const IS_EXPANDED_TAG: &str = "IsExpanded";
pub const ITEM_TAG: &str = "Item";
pub const KEE_PASS_FILE_TAG: &str = "KeePassFile";
pub const KEYSTROKE_SEQUENCE_TAG: &str = "KeystrokeSequence";
pub const KEY_TAG: &str = "Key";
pub const LAST_ACCESS_TIME_TAG: &str = "LastAccessTime";
pub const LAST_MODIFICATION_TIME_TAG: &str = "LastModificationTime";
pub const LAST_SELECTED_GROUP_TAG: &str = "LastSelectedGroup";
pub const LAST_TOP_VISIBLE_ENTRY_TAG: &str = "LastTopVisibleEntry";
pub const LAST_TOP_VISIBLE_GROUP_TAG: &str = "LastTopVisibleGroup";
pub const LOCATION_CHANGED_TAG: &str = "LocationChanged";
pub const MAINTENANCE_HISTORY_DAYS_TAG: &str = "MaintenanceHistoryDays";
pub const MASTER_KEY_CHANGED_TAG: &str = "MasterKeyChanged";
pub const MASTER_KEY_CHANGE_FORCE_TAG: &str = "MasterKeyChangeForce";
pub const MASTER_KEY_CHANGE_REC_TAG: &str = "MasterKeyChangeRec";
pub const MEMORY_PROTECTION_TAG: &str = "MemoryProtection";
pub const META_TAG: &str = "Meta";
pub const NAME_TAG: &str = "Name";
pub const NOTES_TAG: &str = "Notes";
pub const OVERRIDE_URL_TAG: &str = "OverrideURL";
pub const PROTECT_NOTES_TAG: &str = "ProtectNotes";
pub const PROTECT_PASSWORD_TAG: &str = "ProtectPassword";
pub const PROTECT_TITLE_TAG: &str = "ProtectTitle";
pub const PROTECT_URL_TAG: &str = "ProtectURL";
pub const PROTECT_USERNAME_TAG: &str = "ProtectUserName";
pub const RECYCLE_BIN_CHANGED_TAG: &str = "RecycleBinChanged";
pub const RECYCLE_BIN_ENABLED_TAG: &str = "RecycleBinEnabled";
pub const RECYCLE_BIN_UUID_TAG: &str = "RecycleBinUUID";
pub const ROOT_TAG: &str = "Root";
pub const STRING_TAG: &str = "String";
pub const TAGS_TAG: &str = "Tags";
pub const TIMES_TAG: &str = "Times";
pub const USAGE_COUNT_TAG: &str = "UsageCount";
pub const UUID_TAG: &str = "UUID";
pub const VALUE_TAG: &str = "Value";
pub const WINDOW_TAG: &str = "Window";
