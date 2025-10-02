//! Types for the `commonware-reshare` example

use crate::dkg::ReshareOutcome;
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt, Write};
use commonware_consensus::Block as ConsensusBlock;
use commonware_cryptography::{
    bls12381::primitives::variant::{MinSig, Variant},
    Committable, Digestible, Hasher, Sha256,
};

pub type H = Sha256;
pub type D = <H as Hasher>::Digest;
pub type B = Block<H>;

pub type Identity = <MinSig as Variant>::Public;
pub type Evaluation = Identity;
pub type Signature = <MinSig as Variant>::Signature;

/// A block in the reshare chain.
#[derive(Clone)]
pub struct Block<H: Hasher> {
    /// The parent digest.
    pub parent: H::Digest,
    /// The current height.
    pub height: u64,
    /// An optional outcome of a resharing operation.
    pub reshare_outcome: Option<ReshareOutcome>,
}

impl<H: Hasher> Block<H> {
    /// Create a new [Block].
    pub fn new(parent: H::Digest, height: u64, reshare_outcome: Option<ReshareOutcome>) -> Self {
        Self {
            parent,
            height,
            reshare_outcome,
        }
    }
}

impl<H: Hasher> Write for Block<H> {
    fn write(&self, buf: &mut impl BufMut) {
        self.parent.write(buf);
        self.height.write(buf);
        self.reshare_outcome.write(buf);
    }
}

impl<H: Hasher> EncodeSize for Block<H> {
    fn encode_size(&self) -> usize {
        self.parent.encode_size() + self.height.encode_size() + self.reshare_outcome.encode_size()
    }
}

impl<H: Hasher> Read for Block<H> {
    type Cfg = usize;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            parent: H::Digest::read(buf)?,
            height: u64::read(buf)?,
            reshare_outcome: Option::<ReshareOutcome>::read_cfg(buf, cfg)?,
        })
    }
}

impl<H: Hasher> Digestible for Block<H> {
    type Digest = H::Digest;

    fn digest(&self) -> H::Digest {
        let mut hasher = H::new();
        hasher.update(&self.parent);
        hasher.update(&self.height.to_le_bytes());
        hasher.finalize()
    }
}

impl<H: Hasher> Committable for Block<H> {
    type Commitment = H::Digest;

    fn commitment(&self) -> H::Digest {
        self.digest()
    }
}

impl<H: Hasher> ConsensusBlock for Block<H> {
    fn parent(&self) -> Self::Commitment {
        self.parent
    }

    fn height(&self) -> u64 {
        self.height
    }
}
