//! Types for the DKG/reshare protocol.

use bytes::{Buf, BufMut};
use commonware_codec::{varint::UInt, EncodeSize, RangeCfg, Read, ReadExt, Write};
use commonware_cryptography::{
    bls12381::primitives::{group::Share, poly::Public, variant::MinSig},
    ed25519::{PrivateKey, PublicKey, Signature},
    Signer,
};
use commonware_utils::quorum;

/// The namespace used when signing [ReshareOutcome]s.
pub const OUTCOME_NAMESPACE: &[u8] = b"RESHARE_OUTCOME";

/// The result of a resharing operation from the local dealer.
#[derive(Clone)]
pub struct ReshareOutcome {
    /// The public key of the dealer.
    pub dealer: PublicKey,
    /// The dealer's signature over the resharing round, commitment, acks, and reveals.
    pub dealer_signature: Signature,
    /// The round of the resharing operation.
    pub round: u64,
    /// The new group public key polynomial.
    pub commitment: Public<MinSig>,
    /// All signed acknowledgements from participants.
    pub acks: Vec<(u32, Signature)>,
    /// Any revealed secret shares.
    pub reveals: Option<Vec<Share>>,
}

impl ReshareOutcome {
    /// Creates a new [ReshareOutcome], signing its inner payload with the dealer's [PrivateKey].
    pub fn new(
        dealer: &PrivateKey,
        round: u64,
        commitment: Public<MinSig>,
        acks: Vec<(u32, Signature)>,
        reveals: Option<Vec<Share>>,
    ) -> ReshareOutcome {
        // Sign the resharing outcome
        let payload = Self::signature_payload_from_parts(round, &commitment, &acks, &reveals);
        let dealer_signature = dealer.sign(Some(OUTCOME_NAMESPACE), payload.as_ref());

        ReshareOutcome {
            dealer: dealer.public_key(),
            dealer_signature,
            round,
            commitment,
            acks,
            reveals,
        }
    }

    /// Returns the payload that was signed by the dealer.
    pub fn signature_payload(&self) -> Vec<u8> {
        Self::signature_payload_from_parts(self.round, &self.commitment, &self.acks, &self.reveals)
    }

    /// Returns the payload that was signed by the dealer, formed from raw parts.
    fn signature_payload_from_parts(
        round: u64,
        commitment: &Public<MinSig>,
        acks: &[(u32, Signature)],
        reveals: &Option<Vec<Share>>,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            UInt(round).encode_size()
                + commitment.encode_size()
                + acks.encode_size()
                + reveals.encode_size(),
        );
        UInt(round).write(&mut buf);
        commitment.write(&mut buf);
        acks.write(&mut buf);
        reveals.write(&mut buf);
        buf
    }
}

impl Write for ReshareOutcome {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.dealer.write(buf);
        self.dealer_signature.write(buf);
        UInt(self.round).write(buf);
        self.commitment.write(buf);
        self.acks.write(buf);
        self.reveals.write(buf);
    }
}

impl EncodeSize for ReshareOutcome {
    fn encode_size(&self) -> usize {
        self.dealer.encode_size()
            + self.dealer_signature.encode_size()
            + UInt(self.round).encode_size()
            + self.commitment.encode_size()
            + self.acks.encode_size()
            + self.reveals.encode_size()
    }
}

impl Read for ReshareOutcome {
    type Cfg = usize;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            dealer: PublicKey::read(buf)?,
            dealer_signature: Signature::read(buf)?,
            round: UInt::read(buf)?.into(),
            commitment: Public::<MinSig>::read_cfg(buf, cfg)?,
            acks: Vec::<(u32, Signature)>::read_cfg(
                buf,
                &(RangeCfg::from(0..=usize::MAX), ((), ())),
            )?,
            reveals: Option::<Vec<Share>>::read_cfg(buf, &(RangeCfg::from(0..=usize::MAX), ()))?,
        })
    }
}

/// Represents a top-level message for the Distributed Key Generation (DKG) protocol,
/// typically sent over a dedicated DKG communication channel.
///
/// It encapsulates a specific round number and a payload containing the actual
/// DKG protocol message content.
#[derive(Clone, Debug, PartialEq)]
pub struct Dkg {
    pub round: u64,
    pub payload: Payload,
}

impl Write for Dkg {
    fn write(&self, buf: &mut impl BufMut) {
        UInt(self.round).write(buf);
        self.payload.write(buf);
    }
}

impl Read for Dkg {
    type Cfg = usize;

    fn read_cfg(buf: &mut impl Buf, num_players: &usize) -> Result<Self, commonware_codec::Error> {
        let round = UInt::read(buf)?.into();
        let payload = Payload::read_cfg(buf, num_players)?;
        Ok(Self { round, payload })
    }
}

impl EncodeSize for Dkg {
    fn encode_size(&self) -> usize {
        UInt(self.round).encode_size() + self.payload.encode_size()
    }
}

/// Defines the different types of messages exchanged during the DKG protocol.
///
/// This enum is used as the `payload` field within the [Dkg] message struct.
/// The generic parameter `Sig` represents the type used for signatures in acknowledgments.
#[derive(Clone, Debug, PartialEq)]
pub enum Payload {
    /// Message sent by a dealer node to a player node.
    ///
    /// Contains the dealer's public commitment to their polynomial and the specific
    /// share calculated for the receiving player.
    Share {
        /// The dealer's public commitment (coefficients of the polynomial).
        commitment: Public<MinSig>,
        /// The secret share evaluated for the recipient player.
        share: Share,
    },

    /// Message sent by a player node back to the dealer node.
    ///
    /// Acknowledges the receipt and verification of a [Payload::Share] message.
    /// Includes a signature to authenticate the acknowledgment.
    Ack {
        /// The public key identifier of the player sending the acknowledgment.
        public_key: u32,
        /// A signature covering the DKG round, dealer ID, and the dealer's commitment.
        /// This confirms the player received and validated the correct share.
        signature: Signature,
    },
}

impl Write for Payload {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Payload::Share { commitment, share } => {
                buf.put_u8(0);
                commitment.write(buf);
                share.write(buf);
            }
            Payload::Ack {
                public_key,
                signature,
            } => {
                buf.put_u8(1);
                UInt(*public_key).write(buf);
                signature.write(buf);
            }
        }
    }
}

impl Read for Payload {
    type Cfg = usize;

    fn read_cfg(buf: &mut impl Buf, p: &usize) -> Result<Self, commonware_codec::Error> {
        let tag = u8::read(buf)?;
        let t = quorum(u32::try_from(*p).unwrap()) as usize;
        let result = match tag {
            0 => Payload::Share {
                commitment: Public::<MinSig>::read_cfg(buf, &t)?,
                share: Share::read(buf)?,
            },
            1 => Payload::Ack {
                public_key: UInt::read(buf)?.into(),
                signature: Signature::read(buf)?,
            },
            _ => return Err(commonware_codec::Error::InvalidEnum(tag)),
        };
        Ok(result)
    }
}
impl EncodeSize for Payload {
    fn encode_size(&self) -> usize {
        1 + match self {
            Payload::Share { commitment, share } => commitment.encode_size() + share.encode_size(),
            Payload::Ack {
                public_key,
                signature,
            } => UInt(*public_key).encode_size() + signature.encode_size(),
        }
    }
}
