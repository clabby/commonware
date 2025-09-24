use crate::{
    marshal::ingress::coding::{CodedBlock, Shard},
    threshold_simplex::types::{Activity, Finalization, Finalize, Notarization, Notarize},
    types::Round,
    Block, Reporter,
};
use commonware_coding::reed_solomon::Chunk;
use commonware_cryptography::{bls12381::primitives::variant::Variant, Hasher, PublicKey};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};
use tracing::error;

/// Messages sent to the marshal [Actor](super::super::actor::Actor).
///
/// These messages are sent from the consensus engine and other parts of the
/// system to drive the state of the marshal.
pub(crate) enum Message<
    V: Variant,
    B: Block<Digest = H::Digest, Commitment = H::Digest>,
    P: PublicKey,
    H: Hasher,
> {
    // -------------------- Application Messages --------------------
    /// A request to retrieve a block by its commitment.
    Get {
        /// The commitment of the block to retrieve.
        commitment: B::Commitment,
        /// A channel to send the retrieved block.
        response: oneshot::Sender<Option<B>>,
    },
    /// A request to retrieve a block by its commitment.
    Subscribe {
        /// The view in which the block was notarized. This is an optimization
        /// to help locate the block.
        round: Option<Round>,
        /// The coding commitment of the block to retrieve.
        commitment: B::Commitment,
        /// A channel to send the retrieved block.
        response: oneshot::Sender<B>,
    },
    /// A request to retrieve an erasure coded chunk by its commitment and index.
    SubscribeChunk {
        /// The commitment of the chunk to retrieve.
        commitment: B::Commitment,
        /// The index of the chunk to retrieve.
        index: u16,
        /// A channel to send the retrieved chunk.
        response: oneshot::Sender<Shard<CodedBlock<B, H>, H>>,
    },
    /// A request to broadcast an erasure coded block to all peers.
    Broadcast {
        /// The coding commitment of the block.
        coding_commitment: B::Commitment,
        /// The erasure coding configuration.
        config: (u16, u16),
        /// The chunks and their corresponding participants.
        chunks: Vec<(P, Chunk<H>)>,
    },

    // -------------------- Consensus Engine Messages --------------------
    /// A single notarize vote from the consensus engine.
    Notarize {
        /// The notarization vote.
        notarization: Notarize<V, B::Commitment>,
    },
    /// A notarization from the consensus engine.
    Notarization {
        /// The notarization.
        notarization: Notarization<V, B::Commitment>,
    },
    /// A single finalization vote from the consensus engine.
    Finalize {
        /// The finalization vote.
        finalization: Finalize<V, B::Commitment>,
    },
    /// A finalization from the consensus engine.
    Finalization {
        /// The finalization.
        finalization: Finalization<V, B::Commitment>,
    },
}

/// A mailbox for sending messages to the marshal [Actor](super::super::actor::Actor).
#[derive(Clone)]
pub struct Mailbox<
    V: Variant,
    B: Block<Digest = H::Digest, Commitment = H::Digest>,
    P: PublicKey,
    H: Hasher,
> {
    sender: mpsc::Sender<Message<V, B, P, H>>,
}

impl<V: Variant, B: Block<Digest = H::Digest, Commitment = H::Digest>, P: PublicKey, H: Hasher>
    Mailbox<V, B, P, H>
{
    /// Creates a new mailbox.
    pub(crate) fn new(sender: mpsc::Sender<Message<V, B, P, H>>) -> Self {
        Self { sender }
    }

    /// Get is a best-effort attempt to retrieve a given block from local
    /// storage. It is not an indication to go fetch the block from the network.
    pub async fn get(&mut self, commitment: B::Commitment) -> oneshot::Receiver<Option<B>> {
        let (tx, rx) = oneshot::channel();
        if self
            .sender
            .send(Message::Get {
                commitment,
                response: tx,
            })
            .await
            .is_err()
        {
            error!("failed to send get message to actor: receiver dropped");
        }
        rx
    }

    /// Subscribe is a request to retrieve a block by its commitment.
    ///
    /// If the block is found available locally, the block will be returned immediately.
    ///
    /// If the block is not available locally, the request will be registered and the caller will
    /// be notified when the block is available. If the block is not finalized, it's possible that
    /// it may never become available.
    ///
    /// The oneshot receiver should be dropped to cancel the subscription.
    pub async fn subscribe(
        &mut self,
        round: Option<Round>,
        commitment: B::Commitment,
    ) -> oneshot::Receiver<B> {
        let (tx, rx) = oneshot::channel();
        if self
            .sender
            .send(Message::Subscribe {
                round,
                commitment,
                response: tx,
            })
            .await
            .is_err()
        {
            error!("failed to send subscribe message to actor: receiver dropped");
        }
        rx
    }

    /// Subscribe chunk is a request to receive an erasure coded chunk by its commitment and index.
    ///
    /// If the chunk is found available locally, the chunk will be returned immediately.
    ///
    /// If the chunk is not available locally, the request will be registered and the caller will
    /// be notified when the chunk is available. If the chunk is not part of a finalized block, it's
    /// possible that it may never become available.
    ///
    /// The oneshot receiver should be dropped to cancel the subscription.
    pub async fn subscribe_chunk(
        &mut self,
        commitment: B::Commitment,
        index: u16,
    ) -> oneshot::Receiver<Shard<CodedBlock<B, H>, H>> {
        let (tx, rx) = oneshot::channel();
        if self
            .sender
            .send(Message::SubscribeChunk {
                commitment,
                index,
                response: tx,
            })
            .await
            .is_err()
        {
            error!("failed to send subscribe chunk message to actor: receiver dropped");
        }
        rx
    }

    /// Broadcast indicates that a block should be sent to all peers.
    pub async fn broadcast(
        &mut self,
        coding_commitment: B::Commitment,
        config: (u16, u16),
        chunks: Vec<(P, Chunk<H>)>,
    ) {
        if self
            .sender
            .send(Message::Broadcast {
                coding_commitment,
                config,
                chunks,
            })
            .await
            .is_err()
        {
            error!("failed to send broadcast message to actor: receiver dropped");
        }
    }
}

impl<V: Variant, B: Block<Digest = H::Digest, Commitment = H::Digest>, P: PublicKey, H: Hasher>
    Reporter for Mailbox<V, B, P, H>
{
    type Activity = Activity<V, B::Commitment>;

    async fn report(&mut self, activity: Self::Activity) {
        let message = match activity {
            Activity::Notarize(notarization) => Message::Notarize { notarization },
            Activity::Notarization(notarization) => Message::Notarization { notarization },
            Activity::Finalize(finalization) => Message::Finalize { finalization },
            Activity::Finalization(finalization) => Message::Finalization { finalization },
            _ => {
                // Ignore other activity types
                return;
            }
        };
        if self.sender.send(message).await.is_err() {
            error!("failed to report activity to actor: receiver dropped");
        }
    }
}
