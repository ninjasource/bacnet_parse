use super::{tag::Tag, APDU};
use crate::nsdu::apdu::tag::TagType;
use crate::nsdu::object_type::ObjectType;
use crate::nsdu::{parse_object_id, parse_unsigned};
use crate::Error;

#[derive(Debug)]
pub enum UnconfirmedServiceChoice {
    IAm(Option<IAmData>), // src/iam.c:77
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
            0x00 => Self::IAm(IAmData::parse(apdu)?),
            0x01 => Self::IHave,
            0x07 => Self::WhoHas,
            0x08 => Self::WhoIs(WhoIsLimits::parse(apdu)?),
            _ => Self::Unknown,
        })
    }
}

#[derive(Debug)]
#[repr(u32)]
pub enum Segmentation {
    Both = 0,
    Transmit = 1,
    Receive = 2,
    None = 3,
    Max = 4,
}

impl TryFrom<u32> for Segmentation {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Both),
            1 => Ok(Segmentation::Transmit),
            2 => Ok(Segmentation::Receive),
            3 => Ok(Segmentation::None),
            4 => Ok(Segmentation::Max),
            _ => Err(Error::InvalidValue("invalid segmentation value")),
        }
    }
}

#[derive(Debug)]
pub struct ObjectId {
    pub object_type: ObjectType,
    pub id: u32,
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
pub struct IAmData {
    device_id: ObjectId,
    max_apdu: usize,
    segmentation: Segmentation,
    vendor_id: u16,
}

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

                // parse a tag, starting from after the pdu type and service choice, then the object_id
                let (bytes, tag) = Tag::parse(&apdu.bytes[2..])?;
                if tag.tag_type() != TagType::ObjectId {
                    return Err(Error::InvalidValue(
                        "expected object_id tag type for IAm device_id field",
                    ));
                }
                let (bytes, device_id) = parse_object_id(bytes, tag.value)?;
                if device_id.object_type != ObjectType::ObjectDevice {
                    return Err(Error::InvalidValue(
                        "expected device object type for IAm device_id field",
                    ));
                }

                // parse a tag then max_apgu
                let (bytes, tag) = Tag::parse(bytes)?;
                if tag.tag_type() != TagType::UnsignedInt {
                    return Err(Error::InvalidValue(
                        "expected unsigned_int tag type for IAm max_apdu field",
                    ));
                }
                let (bytes, max_apdu) = parse_unsigned(bytes, tag.value)?;
                let max_apdu = max_apdu as usize;

                // parse a tag then segmentation
                let (bytes, tag) = Tag::parse(bytes)?;
                if tag.tag_type() != TagType::Enumerated {
                    return Err(Error::InvalidValue(
                        "expected enumerated tag type for IAm segmentation field",
                    ));
                }
                let (bytes, segmentation) = parse_unsigned(bytes, tag.value)?;
                let segmentation = segmentation.try_into()?;

                // parse a tag then vendor_id
                let (bytes, tag) = Tag::parse(bytes)?;
                if tag.tag_type() != TagType::UnsignedInt {
                    return Err(Error::InvalidValue(
                        "expected unsigned_int type for IAm vendor_id field",
                    ));
                }
                let (_, vendor_id) = parse_unsigned(bytes, tag.value)?;
                if vendor_id > u16::MAX as u32 {
                    return Err(Error::InvalidValue("vendor_id out of range for IAm"));
                }
                let vendor_id = vendor_id as u16;

                Ok(Some(Self {
                    device_id,
                    max_apdu,
                    segmentation,
                    vendor_id,
                }))
            }
        }
    }
}
