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
use commonware_codec::{Encode, EncodeSize, Error as CodecError, Read, ReadExt, Write};
use commonware_coding::reed_solomon::{decode, Chunk, Error as ReedSolomonError};
use commonware_cryptography::{Committable, Digestible, Hasher, PublicKey};
use commonware_p2p::Recipients;
use futures::channel::oneshot;
use std::{fmt::Debug, ops::Deref};
use thiserror::Error;
use tracing::debug;

const MAX_SHARD_SIZE: usize = 1024 * 1024; // 1 MiB - tune? seems reasonable.

/// An error that can occur during reconstruction of a [Block] from [Shard]s.
#[derive(Debug, Error)]
pub enum ReconstructionError {
    #[error(transparent)]
    CodingRecovery(#[from] ReedSolomonError),

    #[error(transparent)]
    Codec(#[from] CodecError),
}

/// A layer that handles receiving erasure coded [Block]s from the [Actor](super::super::actor::Actor),
/// broadcasting them to peers, and reassembling them from received [Shard]s.
#[derive(Clone)]
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
}

impl<P, B, H> ShardLayer<P, B, H>
where
    P: PublicKey,
    B: Block<Digest = H::Digest, Commitment = H::Digest> + Debug,
    H: Hasher,
{
    /// Create a new [ShardLayer] with the given buffered mailbox.
    pub fn new(mailbox: buffered::Mailbox<P, Shard<B, H>>, cfg: B::Cfg) -> Self {
        Self {
            mailbox,
            block_codec_cfg: cfg,
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
            let _peers = self.broadcast(Recipients::One(peer), message).await;
        }
    }

    /// Broadcasts the local erasure coded [Chunk] of a block to all peers.
    pub async fn try_broadcast_mine(&mut self, commitment: B::Commitment) {
        let available_shards = self.mailbox.get(None, commitment, None).await;

        // if let Some(chunk) = available_chunks.into_iter().next() {
        //     let _peers = self.broadcast(Recipients::All, chunk).await;
        // }

        // DEBUG: Send all available shards to all peers.
        for shard in available_shards {
            let _peers = self.broadcast(Recipients::All, shard).await;
        }
    }

    /// Attempts to retrieve and reconstruct a [Block] by its coding commitment from a set of [Shard]s
    /// received from peers.
    ///
    /// This function is best-effort; if peers haven't sent enough [Shard]s to reconstruct the
    /// block, it will return `Ok(None)`.
    ///
    /// If there was an error during reconstruction, a [ReconstructionError] will be returned.
    pub async fn get(
        &mut self,
        commitment: B::Commitment,
    ) -> Result<Option<B>, ReconstructionError> {
        // Request all available chunks for the given commitment from peers.
        let available_chunks = self.mailbox.get(None, commitment, None).await;

        let Some((total, min)) = available_chunks.first().map(|c| c.config) else {
            // No chunks available.
            return Ok(None);
        };
        let coded_chunks = available_chunks.iter().cloned().map(|c| c.chunk).collect();

        // Attempt to reconstruct the block from the available chunks.
        let block = self.try_reconstruct_block(commitment, coded_chunks, total, min);

        // ---- dbg
        if let Ok(Some(ref blk)) = block {
            tracing::error!(?blk, "successfully reconstructed block");
        }
        // ----

        block
    }

    /// Subscribes to a block by commitment with an externally prepared responder.
    ///
    /// The responder will be sent the first message for a commitment when it is available; either
    /// instantly (if cached) or when it is received from the network. The request can be canceled
    /// by dropping the responder.
    pub async fn subscribe_prepared(
        &mut self,
        _commitment: B::Commitment,
        _responder: oneshot::Sender<B>,
    ) -> Result<(), ReconstructionError> {
        todo!("Subscribe to all chunks, reconstruct block when enough are available.");
    }

    /// Attempts to reconstruct a [Block] from the given [Chunk]s and coding configuration.
    fn try_reconstruct_block(
        &mut self,
        block_commitment: B::Commitment,
        chunks: Vec<Chunk<H>>,
        total: u16,
        min: u16,
    ) -> Result<Option<B>, ReconstructionError> {
        if chunks.len() < min as usize {
            // Not enough chunks to recover the block.
            debug!(
                have = chunks.len(),
                need = min,
                "not enough chunks to reconstruct block",
            );
            return Ok(None);
        }

        // Attempt to recover the block from the available chunks. This process will also
        // check the chunks' inclusion within the commitment.
        let recovered = decode(total, min, &block_commitment, chunks)?;

        // Attempt to decode the block from the recovered data.
        let block = B::decode_cfg(&mut recovered.as_slice(), &self.block_codec_cfg)?;

        Ok(Some(block))
    }
}

impl<P, B, H> Broadcaster for ShardLayer<P, B, H>
where
    P: PublicKey,
    B: Block<Digest = H::Digest, Commitment = H::Digest>,
    H: Hasher,
{
    type Recipients = Recipients<P>;
    type Message = Shard<B, H>;
    type Response = Vec<P>;

    async fn broadcast(
        &mut self,
        recipients: Self::Recipients,
        message: Self::Message,
    ) -> oneshot::Receiver<Self::Response> {
        // Direct broadcasts of individual chunks to the underlying mailbox.
        self.mailbox.broadcast(recipients, message).await
    }
}

/// A broadcastable, erasure coded chunk of a [Block].
///
/// Each chunk is associated with a block hash and a commitment to the full block's
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
    type Digest = B::Digest;

    fn digest(&self) -> Self::Digest {
        // TODO: This is a lil weird; only doing this to differentiate the broadcast chunk within
        // the buffered mailbox, such that chunks from separate validators can be enqueued without
        // replacing each other.
        //
        // The abstraction there is a bit weird for what I'm trying to do here.
        H::hash(self.chunk.encode().as_ref())
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::marshal::mocks::block::Block;
    use commonware_codec::{Encode, ReadExt};
    use commonware_coding::reed_solomon::encode;
    use commonware_cryptography::Sha256;

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
        let decoded = MockChunk::read(&mut &encoded[..]).unwrap();
        assert_eq!(broadcast_chunk, decoded);
    }
}
