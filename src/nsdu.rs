pub mod apdu;
pub mod object_type;
pub mod property_id;
pub mod rpdu;
use crate::Error;
pub use apdu::parse_apdu;
use arrayref::array_ref;
pub use rpdu::parse_rpdu;

use self::{apdu::unconfirmed_request_pdu::ObjectId, object_type::ObjectType};

const BACNET_MAX_INSTANCE: u32 = 0x3FFFFF;
const BACNET_INSTANCE_BITS: u32 = 22;
const BACNET_MAX_OBJECT: u32 = 0x3FF;

// DONT use this, it has an unwrap!
fn parse_enumerated<T, E>(bytes: &[u8], sz: u32) -> Result<(&[u8], T), T::Error>
where
    T: TryFrom<u32>,
{
    let (bytes, value) = parse_unsigned(bytes, sz).unwrap();
    let value = T::try_from(value)?;
    Ok((bytes, value))
}

fn parse_unsigned(bytes: &[u8], sz: u32) -> Result<(&[u8], u32), Error> {
    let sz = sz as usize;
    if sz > 4 || sz == 0 {
        return Err(Error::InvalidValue(
            "unsigned len value is 0 or greater than 4",
        ));
    }
    if bytes.len() < sz {
        return Err(Error::Length(
            "unsigned len value greater than remaining bytes",
        ));
    }
    let val = match sz {
        1 => bytes[0] as u32,
        2 => u16::from_be_bytes(*array_ref!(bytes, 0, 2)) as u32,
        3 => (bytes[0] as u32) << 16 | (bytes[1] as u32) << 8 | bytes[2] as u32,
        4 => u32::from_be_bytes(*array_ref!(bytes, 0, 4)),
        // Safety: this value is checked at the beginning of the fn.
        _ => unsafe { core::hint::unreachable_unchecked() },
    };
    Ok((&bytes[sz..], val))
}

fn parse_object_id(bytes: &[u8], sz: u32) -> Result<(&[u8], ObjectId), Error> {
    let (bytes, value) = parse_unsigned(bytes, sz)?;
    let object_type = value >> BACNET_INSTANCE_BITS & BACNET_MAX_OBJECT;
    let object_type = ObjectType::from(object_type);
    let id = value & BACNET_MAX_INSTANCE;
    let object_id = ObjectId { object_type, id };
    Ok((bytes, object_id))
}
