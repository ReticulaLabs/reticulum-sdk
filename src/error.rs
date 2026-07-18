#[derive(Debug)]
pub enum RnsError {
    OutOfMemory,
    InvalidArgument,
    IncorrectSignature,
    IncorrectHash,
    CryptoError,
    PacketError,
    ConnectionError,
    LinkClosed,
    ChannelError,
    ChannelLinkNotReady,
    ChannelMessageTooBig,
    ChannelUnknownMessageType,
}

impl core::fmt::Display for RnsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::OutOfMemory => f.write_str("out of memory"),
            Self::InvalidArgument => f.write_str("invalid argument"),
            Self::IncorrectSignature => f.write_str("incorrect signature"),
            Self::IncorrectHash => f.write_str("incorrect hash"),
            Self::CryptoError => f.write_str("cryptographic error"),
            Self::PacketError => f.write_str("packet error"),
            Self::ConnectionError => f.write_str("connection error"),
            Self::LinkClosed => f.write_str("link is closed"),
            Self::ChannelError => f.write_str("channel error"),
            Self::ChannelLinkNotReady => f.write_str("channel link not ready"),
            Self::ChannelMessageTooBig => f.write_str("channel message too big"),
            Self::ChannelUnknownMessageType => f.write_str("unknown channel message type"),
        }
    }
}

impl std::error::Error for RnsError {}

#[cfg(test)]
mod tests {
    use super::RnsError;

    #[test]
    fn rns_error_converts_to_std_error() {
        fn convert() -> Result<(), Box<dyn std::error::Error>> {
            Err(RnsError::InvalidArgument)?;
            Ok(())
        }

        let error = convert().expect_err("RnsError should convert to std error");
        assert_eq!(error.to_string(), "invalid argument");
    }
}
