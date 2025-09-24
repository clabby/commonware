//! Erasure coding layer for [Block]s.
//!
//! A layer between [marshal::Actor](super::super::Actor) and consensus that handles broadcasting erasure coded
//! [Block]s, as well as the reassembly of [Block]s from [Shard]s received from peers.
//!
//! ## TODO
//! - [ ] Make layer + [Shard] generic over coding scheme
//!   (dep: https://github.com/commonwarexyz/monorepo/pull/1657)

use crate::Block;
use commonware_broadcast::{buffered, Broadcaster};
use commonware_codec::{EncodeSize, Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_coding::reed_solomon::{self, decode, Chunk, Error as ReedSolomonError};
use commonware_cryptography::{Committable, Digestible, Hasher, PublicKey};
use commonware_p2p::Recipients;
use futures::channel::oneshot;
use std::{
    collections::{btree_map::Entry, BTreeMap},
    fmt::Debug,
    ops::Deref,
};
use thiserror::Error;
use tracing::{debug, info};

const MAX_SHARD_SIZE: usize = 1024 * 1024; // 1 MiB - tune? seems reasonable.

/// An error that can occur during reconstruction of a [Block] from [Shard]s.
#[derive(Debug, Error)]
pub enum ReconstructionError {
    #[error(transparent)]
    CodingRecovery(#[from] ReedSolomonError),

    #[error(transparent)]
    Codec(#[from] CodecError),
}

/// A subscription for a block by its commitment.
struct BlockSubscription<B: Block> {
    subscribers: Vec<oneshot::Sender<B>>,
}

/// A layer that handles receiving erasure coded [Block]s from the [Actor](super::super::actor::Actor),
/// broadcasting them to peers, and reassembling them from received [Shard]s.
pub struct ShardLayer<P, B, H>
where
    P: PublicKey,
    B: Block<Digest = H::Digest, Commitment = H::Digest>,
    H: Hasher,
{
    /// Inner [`buffered::Mailbox`] for broadcasting and receiving erasure coded chunks.
    mailbox: buffered::Mailbox<P, Shard<B, H>>,

    /// [`Read`] configuration for the block type.
    block_codec_cfg: B::Cfg,

    /// Open subscriptions for blocks by commitment.
    block_subscriptions: BTreeMap<B::Commitment, BlockSubscription<B>>,
}

impl<P, B, H> ShardLayer<P, B, H>
where
    P: PublicKey,
    B: Block<Digest = H::Digest, Commitment = H::Digest>,
    H: Hasher,
{
    /// Create a new [ShardLayer] with the given buffered mailbox.
    pub fn new(mailbox: buffered::Mailbox<P, Shard<B, H>>, block_codec_cfg: B::Cfg) -> Self {
        Self {
            mailbox,
            block_codec_cfg,
            block_subscriptions: BTreeMap::new(),
        }
    }

    /// Broadcasts [Shard]s of a [Block] to a pre-determined set of peers.
    pub async fn broadcast_chunks(
        &mut self,
        coding_commitment: B::Commitment,
        config: (u16, u16),
        chunks: Vec<(P, Chunk<H>)>,
    ) {
        for (peer, chunk) in chunks {
            let message = Shard::new(coding_commitment, config, chunk);
            let _peers = self.mailbox.broadcast(Recipients::One(peer), message).await;
        }
    }

    /// Broadcasts a local [Shard] of a block to all peers, if the shard is present.
    pub async fn try_broadcast_shard(&mut self, commitment: B::Commitment, index: u16) {
        let shard = self
            .mailbox
            .get(None, commitment, None)
            .await
            .iter()
            .find(|c| c.chunk.index == index)
            .cloned();

        if let Some(shard) = shard {
            debug!(%commitment, index, "broadcasted local shard to all peers");
            let _peers = self.mailbox.broadcast(Recipients::All, shard).await;
        } else {
            debug!(%commitment, index, "no local shard to broadcast" );
        }
    }

    /// Attempts to retrieve and reconstruct a [Block] by its coding commitment from a set of [Shard]s
    /// received from peers.
    ///
    /// This function is best-effort; if peers haven't sent enough [Shard]s to reconstruct the
    /// block, it will return `Ok(None)`.
    ///
    /// If there was an error during reconstruction, a [ReconstructionError] will be returned.
    pub async fn try_reconstruct(
        &mut self,
        commitment: B::Commitment,
    ) -> Result<Option<B>, ReconstructionError> {
        let available_chunks = self.mailbox.get(None, commitment, None).await;

        let Some((total, min)) = available_chunks.first().map(|c| c.config) else {
            // No chunks available.
            return Ok(None);
        };
        let coded_chunks = available_chunks
            .iter()
            .cloned()
            .map(|c| c.chunk)
            .collect::<Vec<_>>();

        // TODO: Make sure min is all valid chunks
        // TODO: If we do encounter a block that's invalid, block the peer.

        if coded_chunks.len() < min as usize {
            // Not enough chunks to recover the block yet.
            debug!(
                %commitment,
                have = coded_chunks.len(),
                need = min,
                "not enough chunks to reconstruct block",
            );
            return Ok(None);
        }

        // Attempt to recover the block from the available chunks. This process will also
        // check the chunks' inclusion within the commitment.
        let recovered = decode(total, min, &commitment, coded_chunks)?;

        // Attempt to decode the block from the recovered data.
        let block = B::decode_cfg(&mut recovered.as_slice(), &self.block_codec_cfg)?;

        // Notify any subscribers that have been waiting for this block.
        if let Some(mut sub) = self.block_subscriptions.remove(&commitment) {
            for sub in sub.subscribers.drain(..) {
                let _ = sub.send(block.clone());
            }
        }

        info!(
            %commitment,
            digest = %block.digest(),
            height = block.height(),
            "successfully reconstructed block"
        );

        Ok(Some(block))
    }

    /// Subscribes to a block by commitment with an externally prepared responder.
    ///
    /// The responder will be sent the block when it is available; either instantly (if cached)
    /// or when it is received from the network. The request can be canceled by dropping the
    /// responder.
    pub async fn subscribe_block(
        &mut self,
        commitment: B::Commitment,
        responder: oneshot::Sender<B>,
    ) -> Result<(), ReconstructionError> {
        match self.block_subscriptions.entry(commitment) {
            Entry::Vacant(entry) => {
                entry.insert(BlockSubscription {
                    subscribers: vec![responder],
                });
            }
            Entry::Occupied(mut entry) => {
                entry.get_mut().subscribers.push(responder);
            }
        }

        // Try to reconstruct the block immediately in case we already have enough chunks.
        self.try_reconstruct(commitment).await?;

        Ok(())
    }

    pub async fn get_chunk(
        &mut self,
        commitment: B::Commitment,
        index: u16,
    ) -> Option<Shard<B, H>> {
        let index_hash = shard_uuid::<B, H>(commitment, index);
        self.mailbox
            .get(None, commitment, Some(index_hash))
            .await
            .iter()
            .cloned()
            .next()
    }

    /// Subscribes to a chunk by commitment and index with an externally prepared responder.
    ///
    /// The responder will be sent the chunk when it is available; either instantly (if cached)
    /// or when it is received from the network. The request can be canceled by dropping the
    /// responder.
    pub async fn subscribe_chunk(
        &mut self,
        commitment: B::Commitment,
        index: u16,
        responder: oneshot::Sender<Shard<B, H>>,
    ) {
        let index_hash = shard_uuid::<B, H>(commitment, index);
        self.mailbox
            .subscribe_prepared(None, commitment, Some(index_hash), responder)
            .await;
    }
}

/// A broadcastable, erasure coded [Chunk] of a [Block].
///
/// Each chunk is associated with a commitment to the full block's
/// erasure coded data. This allows recipients to verify the integrity of the chunk
/// (to varying degrees; For reed-solomon which is currently hard-coded, no guarantee
/// of the chunk's correctness is possible without additional chunks.)
#[derive(Debug, Clone)]
pub struct Shard<B, H>
where
    B: Block<Digest = H::Digest, Commitment = H::Digest>,
    H: Hasher,
{
    commitment: B::Commitment,
    config: (u16, u16),
    chunk: Chunk<H>,
}

impl<B, H> Shard<B, H>
where
    B: Block<Digest = H::Digest, Commitment = H::Digest>,
    H: Hasher,
{
    /// Create a new [Shard] from a block's hash, coding commitment, and a chunk
    /// of the coded block.
    ///
    /// ## Panics
    ///
    /// Panics if the chunk's shard size exceeds `MAX_SHARD_SIZE`.
    pub fn new(commitment: B::Commitment, config: (u16, u16), chunk: Chunk<H>) -> Self {
        if chunk.shard.len() > MAX_SHARD_SIZE {
            panic!(
                "Chunk shard size {} exceeds maximum allowed size of {}",
                chunk.shard.len(),
                MAX_SHARD_SIZE
            );
        }

        Self {
            commitment,
            config,
            chunk,
        }
    }

    /// Return a reference to the contained [`Chunk`].
    pub fn chunk(&self) -> &Chunk<H> {
        &self.chunk
    }
}

impl<B, H> PartialEq for Shard<B, H>
where
    B: Block<Digest = H::Digest, Commitment = H::Digest>,
    H: Hasher,
{
    fn eq(&self, other: &Self) -> bool {
        self.commitment == other.commitment
            && self.config == other.config
            && self.chunk == other.chunk
    }
}

impl<B, H> Eq for Shard<B, H>
where
    B: Block<Digest = H::Digest, Commitment = H::Digest>,
    H: Hasher,
{
}

impl<B, H> Committable for Shard<B, H>
where
    B: Block<Digest = H::Digest, Commitment = H::Digest>,
    H: Hasher,
{
    type Commitment = B::Commitment;

    fn commitment(&self) -> Self::Commitment {
        self.commitment
    }
}

impl<B, H> Digestible for Shard<B, H>
where
    B: Block<Digest = H::Digest, Commitment = H::Digest>,
    H: Hasher,
{
    type Digest = H::Digest;

    fn digest(&self) -> Self::Digest {
        shard_uuid::<B, H>(self.commitment, self.chunk.index)
    }
}

impl<B, H> EncodeSize for Shard<B, H>
where
    B: Block<Digest = H::Digest, Commitment = H::Digest>,
    H: Hasher,
{
    fn encode_size(&self) -> usize {
        let (total, min) = &self.config;

        self.commitment.encode_size()
            + total.encode_size()
            + min.encode_size()
            + self.chunk.encode_size()
    }
}

impl<B, H> Write for Shard<B, H>
where
    B: Block<Digest = H::Digest, Commitment = H::Digest>,
    H: Hasher,
{
    fn write(&self, buf: &mut impl bytes::BufMut) {
        let (total, min) = &self.config;

        self.commitment.write(buf);
        total.write(buf);
        min.write(buf);
        self.chunk.write(buf);
    }
}

impl<B, H> Read for Shard<B, H>
where
    B: Block<Digest = H::Digest, Commitment = H::Digest>,
    H: Hasher,
{
    type Cfg = ();

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        _cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let commitment = B::Commitment::read(buf)?;
        let total = u16::read(buf)?;
        let min = u16::read(buf)?;
        let chunk = Chunk::read_cfg(buf, &MAX_SHARD_SIZE)?;

        Ok(Self {
            commitment,
            config: (total, min),
            chunk,
        })
    }
}

impl<B, H> Deref for Shard<B, H>
where
    B: Block<Digest = H::Digest, Commitment = H::Digest>,
    H: Hasher,
{
    type Target = Chunk<H>;

    fn deref(&self) -> &Self::Target {
        &self.chunk
    }
}

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
    /// The coded chunks.
    chunks: Vec<Chunk<H>>,
}

impl<B, H> CodedBlock<B, H>
where
    B: Block<Digest = H::Digest, Commitment = H::Digest>,
    H: Hasher,
{
    /// Erasure codes the block.
    fn encode(inner: &B, config: (u16, u16)) -> (H::Digest, Vec<Chunk<H>>) {
        let mut buf = Vec::with_capacity(config.encode_size() + inner.encode_size());
        inner.write(&mut buf);
        config.write(&mut buf);

        reed_solomon::encode::<H>(config.0, config.1, buf).expect("failed to commit to block")
    }

    /// Create a new [CodedBlock] from a [Block] and a configuration.
    pub fn new(inner: B, config: (u16, u16)) -> Self {
        let (commitment, chunks) = Self::encode(&inner, config);
        Self {
            inner,
            config,
            commitment,
            chunks,
        }
    }

    /// Returns a reference to the inner [Block].
    pub fn inner(&self) -> &B {
        &self.inner
    }

    /// Takes the inner [Block] out of the [CodedBlock].
    pub fn take_inner(self) -> B {
        self.inner
    }

    /// Returns the erasure coding configuration.
    pub fn config(&self) -> (u16, u16) {
        self.config
    }

    /// Returns a reference to the coded chunks.
    pub fn chunks(&self) -> &[Chunk<H>] {
        self.chunks.as_slice()
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
        let (commitment, chunks) = Self::encode(&inner, config);

        Ok(Self {
            inner,
            config,
            commitment,
            chunks,
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
    type Commitment = H::Digest;

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

/// Creates a unique identifier for a shard based on the block commitment and shard index.
fn shard_uuid<B, H>(commitment: B::Commitment, index: u16) -> H::Digest
where
    B: Block<Digest = H::Digest, Commitment = H::Digest>,
    H: Hasher,
{
    let mut buf = vec![0u8; H::Digest::SIZE + u16::SIZE];
    buf[..H::Digest::SIZE].copy_from_slice(commitment.as_ref());
    buf[H::Digest::SIZE..].copy_from_slice(index.to_le_bytes().as_ref());
    H::hash(buf.as_ref())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::marshal::mocks::block::Block;
    use commonware_codec::{DecodeExt, Encode};
    use commonware_coding::reed_solomon::encode;
    use commonware_cryptography::{sha256::Digest as Sha256Digest, Hasher, Sha256};

    type MockChunk = Shard<Block<<Sha256 as Hasher>::Digest>, Sha256>;

    #[test]
    #[should_panic]
    fn test_shard_chunk_too_large() {
        const LARGE_BLOCK: &[u8] = &[0u8; MAX_SHARD_SIZE + 1];
        const CONFIG: (u16, u16) = (2, 1);

        let (commitment, chunks) =
            encode::<Sha256>(CONFIG.0, CONFIG.1, LARGE_BLOCK.to_vec()).unwrap();
        MockChunk::new(commitment, CONFIG, chunks[0].clone());
    }

    #[test]
    fn test_shard_codec_roundtrip() {
        const MOCK_BLOCK_DATA: &[u8] = b"commonware supremacy";
        const CONFIG: (u16, u16) = (2, 1);

        let (commitment, chunks) =
            encode::<Sha256>(CONFIG.0, CONFIG.1, MOCK_BLOCK_DATA.to_vec()).unwrap();
        let broadcast_chunk = MockChunk::new(commitment, CONFIG, chunks[0].clone());

        let encoded = broadcast_chunk.encode();
        let decoded = MockChunk::decode(&mut &encoded[..]).unwrap();
        assert_eq!(broadcast_chunk, decoded);
    }

    #[test]
    fn test_coded_block_codec_roundtrip() {
        const MOCK_BLOCK_DATA: &[u8] = b"commonware bit twiddling club";
        const CONFIG: (u16, u16) = (4, 2);

        let inner = Block::new::<Sha256>(Sha256::hash(MOCK_BLOCK_DATA), 0xFE, 0xFF);
        let block = CodedBlock::<_, Sha256>::new(inner, CONFIG);

        let encoded = block.encode().to_vec();
        let decoded =
            CodedBlock::<Block<Sha256Digest>, Sha256>::decode(&mut encoded.as_ref()).unwrap();

        assert_eq!(block, decoded);
    }
}
