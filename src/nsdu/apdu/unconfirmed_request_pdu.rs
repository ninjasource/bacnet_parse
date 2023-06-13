use super::{tag::Tag, APDU};
use crate::nsdu::parse_unsigned;
use crate::Error;

#[derive(Debug)]
pub enum UnconfirmedServiceChoice {
    IAm, // src/iam.c:77
    IHave,
    WhoHas,
    WhoIs(Option<WhoIsLimits>), // src/whois.c:69
    Unknown,
}

impl UnconfirmedServiceChoice {
    pub fn parse(apdu: &APDU) -> Result<Self, Error> {
        let bytes = apdu.bytes;
        if bytes.len() < 2 {
            return Err(Error::Length("wrong len for UnconfirmedServiceChoice"));
        }
        Ok(match bytes[1] {
            0x00 => Self::IAm,
            0x01 => Self::IHave,
            0x07 => Self::WhoHas,
            0x08 => Self::WhoIs(WhoIsLimits::parse(apdu)?),
            _ => Self::Unknown,
        })
    }
}

#[derive(Debug)]
pub struct WhoIsLimits {
    pub low_limit: u32,
    pub high_limit: u32,
}

impl WhoIsLimits {
    /// Attempt to parse WhoIsLimits from an APDU payload.
    fn parse(apdu: &APDU) -> Result<Option<Self>, Error> {
        match apdu.bytes.len() {
            // Safety:
            // This must called from UnconfirmedServiceChoice which validates that this must be an
            // APDU frame with at least 2 payload bytes available.
            0 | 1 => unsafe { core::hint::unreachable_unchecked() },
            2 => Ok(None),
            _ => {
                // 1. parse a tag, starting from after the pdu type and service choice
                // 2. parse an unsigned value. The tag's value here is the length of the unsigned
                //    integer. This is the low value.
                // 3. parse another tag
                // 4. parse another unsigned value. This is the high value.
                let (bytes, tag) = Tag::parse(&apdu.bytes[2..])?;
                if tag.number != 0 {
                    return Err(Error::InvalidValue("Non-zero tag number in WhoIs"));
                }
                let (bytes, low_limit) = parse_unsigned(bytes, tag.value)?;
                let (bytes, tag) = Tag::parse(bytes)?;
                let (_, high_limit) = parse_unsigned(bytes, tag.value)?;
                Ok(Some(Self {
                    low_limit,
                    high_limit,
                }))
            }
        }
    }
}

#[derive(Debug)]
pub struct IAmData {}

impl IAmData {
    /// Attempt to parse WhoIsLimits from an APDU payload.
    fn parse(apdu: &APDU) -> Result<Option<Self>, Error> {
        match apdu.bytes.len() {
            // Safety:
            // This must called from UnconfirmedServiceChoice which validates that this must be an
            // APDU frame with at least 2 payload bytes available.
            0 | 1 => unsafe { core::hint::unreachable_unchecked() },
            _ => {
                // 1. parse a tag, type should be ObjectId
                // 2. decode an object ID - this is the device id
                // 3. parse a tag, type should be UnsignedInt
                // 4. decode an unsigned int - this is "Max APDU" - TODO: what does that mean?
                // 5. parse a tag, type should be enumerated
                // 6. decode an enumerated value - this is segmentation support
                // 7. parse a tag, type should be UnsignedInt
                // 8. decode an enumerated value - this is the vendor ID
                unimplemented!("TODO");
            }
        }
    }
}
