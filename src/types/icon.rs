// Copyright (c) 2016-2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::error;
use std::fmt;
use std::result::Result;

/// The icon of an entry or group.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub enum Icon {
    /// The key icon.
    Key,

    /// The world icon.
    World,

    /// The warning icon.
    Warning,

    /// The server icon.
    Server,

    /// The marked directory icon.
    MarkedDirectory,

    /// The user communication icon.
    UserCommunication,

    /// The parts icon.
    Parts,

    /// The notepad icon.
    Notepad,

    /// The world with socket icon.
    WorldSocket,

    /// The identity icon.
    Identity,

    /// The paper ready icon.
    PaperReady,

    /// The digicam icon.
    Digicam,

    /// The infrared communication icon.
    IRCommunication,

    /// The multiple keys icon.
    MultipleKeys,

    /// The energy icon.
    Energy,

    /// The scanner icon.
    Scanner,

    /// The world with star icon.
    WorldStar,

    /// The CD-ROM icon.
    CDRom,

    /// The monitor icon.
    Monitor,

    /// The email icon.
    Email,

    /// The configuration icon.
    Configuration,

    /// The clipboard ready icon.
    ClipboardReady,

    /// The new paper icon.
    PaperNew,

    /// The screen icon.
    Screen,

    /// The energy careful icon.
    EnergyCareful,

    /// The inbox icon.
    Inbox,

    /// The disk icon.
    Disk,

    /// The drive icon.
    Drive,

    /// The QuickTime icon.
    QuickTime,

    /// The encrypted terminal icon.
    EncryptedTerminal,

    /// The console icon.
    Console,

    /// The printer icon.
    Printer,

    /// The icons icon.
    Icons,

    /// The run icon.
    Run,

    /// The settings icon.
    Settings,

    /// The world with a computer icon.
    WorldComputer,

    /// The archive icon.
    Archive,

    /// The banking icon.
    Banking,

    /// The SMB icon (Windows networking).
    Smb,

    /// The clock icon.
    Clock,

    /// The email search icon.
    EmailSearch,

    /// The paper with flag icon.
    PaperFlag,

    /// The memory icon.
    Memory,

    /// The recycle bin icon.
    RecycleBin,

    /// The note icon.
    Note,

    /// The expired icon.
    Expired,

    /// The info icon.
    Info,

    /// The package icon.
    Package,

    /// The folder icon.
    Folder,

    /// The open folder icon.
    FolderOpen,

    /// The packaged folder icon.
    FolderPackage,

    /// The open lock icon.
    LockOpen,

    /// The paper with lock icon.
    PaperLocked,

    /// The checked icon.
    Checked,

    /// The pen icon.
    Pen,

    /// The thumbnail icon.
    Thumbnail,

    /// The book icon.
    Book,

    /// The listing icon.
    Listing,

    /// The user's key icon.
    UserKey,

    /// The tool icon.
    Tool,

    /// The home icon.
    Home,

    /// The star icon.
    Star,

    /// The Tux logo.
    Tux,

    /// The feather icon.
    Feather,

    /// The Apple logo.
    Apple,

    /// The Wikipedia logo.
    Wikipedia,

    /// The money icon.
    Money,

    /// The certificate icon.
    Certificate,

    /// The phone icon.
    Phone,
}

impl Icon {
    /// Attempts to convert an identifier to an icon.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use kpdb::Icon;
    /// # use kpdb::IconError;
    ///
    /// # fn from_i32_example() -> Result<Icon, IconError> {
    /// let icon = Icon::from_i32(0)?;
    /// # Ok(icon)
    /// # }
    /// ```
    pub fn from_i32(id: i32) -> Result<Icon, IconError> {
        match id {
            0 => Ok(Icon::Key),
            1 => Ok(Icon::World),
            2 => Ok(Icon::Warning),
            3 => Ok(Icon::Server),
            4 => Ok(Icon::MarkedDirectory),
            5 => Ok(Icon::UserCommunication),
            6 => Ok(Icon::Parts),
            7 => Ok(Icon::Notepad),
            8 => Ok(Icon::WorldSocket),
            9 => Ok(Icon::Identity),
            10 => Ok(Icon::PaperReady),
            11 => Ok(Icon::Digicam),
            12 => Ok(Icon::IRCommunication),
            13 => Ok(Icon::MultipleKeys),
            14 => Ok(Icon::Energy),
            15 => Ok(Icon::Scanner),
            16 => Ok(Icon::WorldStar),
            17 => Ok(Icon::CDRom),
            18 => Ok(Icon::Monitor),
            19 => Ok(Icon::Email),
            20 => Ok(Icon::Configuration),
            21 => Ok(Icon::ClipboardReady),
            22 => Ok(Icon::PaperNew),
            23 => Ok(Icon::Screen),
            24 => Ok(Icon::EnergyCareful),
            25 => Ok(Icon::Inbox),
            26 => Ok(Icon::Disk),
            27 => Ok(Icon::Drive),
            28 => Ok(Icon::QuickTime),
            29 => Ok(Icon::EncryptedTerminal),
            30 => Ok(Icon::Console),
            31 => Ok(Icon::Printer),
            32 => Ok(Icon::Icons),
            33 => Ok(Icon::Run),
            34 => Ok(Icon::Settings),
            35 => Ok(Icon::WorldComputer),
            36 => Ok(Icon::Archive),
            37 => Ok(Icon::Banking),
            38 => Ok(Icon::Smb),
            39 => Ok(Icon::Clock),
            40 => Ok(Icon::EmailSearch),
            41 => Ok(Icon::PaperFlag),
            42 => Ok(Icon::Memory),
            43 => Ok(Icon::RecycleBin),
            44 => Ok(Icon::Note),
            45 => Ok(Icon::Expired),
            46 => Ok(Icon::Info),
            47 => Ok(Icon::Package),
            48 => Ok(Icon::Folder),
            49 => Ok(Icon::FolderOpen),
            50 => Ok(Icon::FolderPackage),
            51 => Ok(Icon::LockOpen),
            52 => Ok(Icon::PaperLocked),
            53 => Ok(Icon::Checked),
            54 => Ok(Icon::Pen),
            55 => Ok(Icon::Thumbnail),
            56 => Ok(Icon::Book),
            57 => Ok(Icon::Listing),
            58 => Ok(Icon::UserKey),
            59 => Ok(Icon::Tool),
            60 => Ok(Icon::Home),
            61 => Ok(Icon::Star),
            62 => Ok(Icon::Tux),
            63 => Ok(Icon::Feather),
            64 => Ok(Icon::Apple),
            65 => Ok(Icon::Wikipedia),
            66 => Ok(Icon::Money),
            67 => Ok(Icon::Certificate),
            68 => Ok(Icon::Phone),
            _ => Err(IconError::InvalidIconId),
        }
    }

    /// Gets the icon's identifier.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use kpdb::Icon;
    ///
    /// let icon = Icon::Key;
    /// let icon_id = icon.to_i32();
    /// ```
    pub fn to_i32(self) -> i32 {
        self as i32
    }
}

/// Error type for icon conversion errors.
#[derive(Debug, PartialEq)]
pub enum IconError {
    /// Invalid icon identifier.
    InvalidIconId,
}

impl IconError {
    fn msg(&self) -> &str {
        match *self {
            IconError::InvalidIconId => "invalid icon identifier",
        }
    }
}

impl fmt::Display for IconError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            IconError::InvalidIconId => write!(f, "Icon error: {}", self.msg()),
        }
    }
}

impl error::Error for IconError {
    fn description(&self) -> &str {
        self.msg()
    }

    fn cause(&self) -> Option<&dyn error::Error> {
        None
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_from_i32_with_valid_i32_returns_icon() {
        assert_eq!(Icon::from_i32(0), Ok(Icon::Key));
        assert_eq!(Icon::from_i32(68), Ok(Icon::Phone));
    }

    #[test]
    fn test_from_i32_with_invalid_i32_returns_error() {
        assert_eq!(Icon::from_i32(-1), Err(IconError::InvalidIconId));
        assert_eq!(Icon::from_i32(69), Err(IconError::InvalidIconId));
    }

    #[test]
    fn test_to_i32_returns_correct_i32() {
        assert_eq!(Icon::Key.to_i32(), 0);
        assert_eq!(Icon::Phone.to_i32(), 68);
    }

    #[test]
    fn test_to_i32_inverses_from_i32() {
        for i in 0..69 {
            let icon = Icon::from_i32(i).unwrap();
            let icon_id = icon.to_i32();
            assert_eq!(icon_id, i);
        }
    }
}
