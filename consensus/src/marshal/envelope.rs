//! An envelope type for an erasure coded [Block].

use crate::Block;
use commonware_codec::{EncodeSize, Read, Write};
use commonware_coding::reed_solomon;
use commonware_cryptography::{Committable, Digestible, Hasher};

/// An envelope type for an erasure coded [Block].
#[derive(Debug, Clone)]
pub struct CodedBlock<B, H>
where
    B: Block<Digest = H::Digest, Commitment = H::Digest>,
    H: Hasher,
{
    /// The inner block type.
    inner: B,
    /// The erasure coding configuration.
    config: (u16, u16),
    /// The erasure coding commitment.
    commitment: H::Digest,
}

impl<B, H> CodedBlock<B, H>
where
    B: Block<Digest = H::Digest, Commitment = H::Digest>,
    H: Hasher,
{
    /// Erasure codes the block to create the commitment.
    fn commit(inner: &B, config: (u16, u16)) -> H::Digest {
        let mut buf = Vec::with_capacity(config.encode_size() + inner.encode_size());
        inner.write(&mut buf);
        config.write(&mut buf);

        let (commitment, _) =
            reed_solomon::encode::<H>(config.0, config.1, buf).expect("failed to commit to block");
        commitment
    }

    /// Create a new [CodedBlock] from a [Block] and a configuration.
    pub fn new(inner: B, config: (u16, u16)) -> Self {
        let commitment = Self::commit(&inner, config);
        Self {
            inner,
            config,
            commitment,
        }
    }

    /// Returns a reference to the inner [Block].
    pub fn inner(&self) -> &B {
        &self.inner
    }
}

impl<B, H> Write for CodedBlock<B, H>
where
    B: Block<Digest = H::Digest, Commitment = H::Digest>,
    H: Hasher,
{
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.inner.write(buf);
        self.config.write(buf);
    }
}

impl<B, H> Read for CodedBlock<B, H>
where
    B: Block<Digest = H::Digest, Commitment = H::Digest>,
    H: Hasher,
{
    type Cfg = B::Cfg;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let inner = B::read_cfg(buf, cfg)?;
        let config = <(u16, u16)>::read_cfg(buf, &((), ()))?;
        let commitment = Self::commit(&inner, config);

        Ok(Self {
            inner,
            config,
            commitment,
        })
    }
}

impl<B, H> EncodeSize for CodedBlock<B, H>
where
    B: Block<Digest = H::Digest, Commitment = H::Digest>,
    H: Hasher,
{
    fn encode_size(&self) -> usize {
        self.inner.encode_size() + self.config.encode_size()
    }
}

impl<B, H> Digestible for CodedBlock<B, H>
where
    B: Block<Digest = H::Digest, Commitment = H::Digest>,
    H: Hasher,
{
    type Digest = B::Digest;

    fn digest(&self) -> Self::Digest {
        self.inner.digest()
    }
}

impl<B, H> Committable for CodedBlock<B, H>
where
    B: Block<Digest = H::Digest, Commitment = H::Digest>,
    H: Hasher,
{
    type Commitment = B::Commitment;

    fn commitment(&self) -> Self::Commitment {
        self.commitment
    }
}

impl<B, H> Block for CodedBlock<B, H>
where
    B: Block<Digest = H::Digest, Commitment = H::Digest>,
    H: Hasher,
{
    fn height(&self) -> u64 {
        self.inner.height()
    }

    fn parent(&self) -> Self::Commitment {
        self.inner.parent()
    }
}

impl<B, H> PartialEq for CodedBlock<B, H>
where
    B: Block<Digest = H::Digest, Commitment = H::Digest> + PartialEq,
    H: Hasher,
{
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
            && self.config == other.config
            && self.commitment == other.commitment
    }
}

impl<B, H> Eq for CodedBlock<B, H>
where
    B: Block<Digest = H::Digest, Commitment = H::Digest> + PartialEq,
    H: Hasher,
{
}

#[cfg(test)]
mod test {
    use crate::marshal::{envelope::CodedBlock, mocks::block::Block};
    use commonware_codec::{Decode, Encode};
    use commonware_cryptography::{sha256::Digest as Sha256Digest, Hasher, Sha256};

    #[test]
    fn test_codec_roundtrip() {
        const MOCK_BLOCK_DATA: &[u8] = b"commonware bit twiddling club";
        const CONFIG: (u16, u16) = (4, 2);

        let inner = Block::new::<Sha256>(Sha256::hash(MOCK_BLOCK_DATA), 0xFE, 0xFF);
        let block = CodedBlock::<_, Sha256>::new(inner, CONFIG);

        let encoded = block.encode().to_vec();
        let decoded =
            CodedBlock::<Block<Sha256Digest>, Sha256>::decode_cfg(&mut encoded.as_ref(), &())
                .unwrap();

        assert_eq!(block, decoded);
    }
}
