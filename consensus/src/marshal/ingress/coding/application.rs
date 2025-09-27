//! A wrapper around an [Application] that intercepts messages from consensus and marshal,
//! hiding details of erasure coded broadcast and shard verification.

use crate::{
    marshal::{self, ingress::coding::types::CodedBlock},
    threshold_simplex::types::Context,
    types::Round,
    Application, Automaton, Block, Epochable, Relay, Reporter, Supervisor,
};
use commonware_coding::{Config as CodingConfig, Scheme};
use commonware_cryptography::{bls12381::primitives::variant::Variant, Committable, PublicKey};
use commonware_runtime::{Clock, Metrics, Spawner};
use futures::channel::oneshot;
use rand::Rng;
use std::sync::{Arc, Mutex};
use tracing::{debug, info, warn};

/// An [Application] adapter that handles erasure coding and shard verification for consensus.
#[derive(Clone)]
pub struct CodingAdapter<E, A, V, B, S, P, Z>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application,
    V: Variant,
    B: Block<Commitment = S::Commitment>,
    S: Scheme,
    P: PublicKey,
    Z: Supervisor<Index = Round, PublicKey = P>,
{
    context: E,
    application: A,
    marshal: marshal::Mailbox<V, B, S, P>,
    identity: P,
    supervisor: Z,
    last_built: Arc<Mutex<Option<(Round, CodedBlock<B, S>)>>>,
}

impl<E, A, V, B, S, P, Z> Automaton for CodingAdapter<E, A, V, B, S, P, Z>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<Block = B, Context = Context<B::Commitment>>,
    V: Variant,
    B: Block<Commitment = S::Commitment>,
    S: Scheme,
    P: PublicKey,
    Z: Supervisor<Index = Round, PublicKey = P>,
{
    type Digest = B::Commitment;
    type Context = A::Context;

    async fn genesis(&mut self, epoch: <Self::Context as Epochable>::Epoch) -> Self::Digest {
        self.application.genesis(epoch).await.commitment()
    }

    async fn propose(&mut self, context: Context<Self::Digest>) -> oneshot::Receiver<Self::Digest> {
        let (parent_view, parent_commitment) = context.parent;
        let genesis = self.application.genesis(context.epoch()).await;
        let mut marshal = self.marshal.clone();
        let mut application = self.application.clone();
        let last_built = self.last_built.clone();

        let participants = self
            .supervisor
            .participants(context.round)
            .expect("failed to get participants for round");
        let coding_config = CodingConfig {
            minimum_shards: (participants.len() / 2) as u16,
            extra_shards: (participants.len() / 2) as u16,
        };

        let (tx, rx) = oneshot::channel();
        self.context
            .with_label("propose")
            .spawn(move |_| async move {
                let parent_block = if parent_commitment == genesis.commitment() {
                    genesis
                } else {
                    let block_request = marshal
                        .subscribe(
                            Some(Round::new(context.epoch(), parent_view)),
                            parent_commitment,
                        )
                        .await
                        .await;

                    if let Ok(block) = block_request {
                        block
                    } else {
                        warn!("propose job aborted");
                        return;
                    }
                };

                let built_block = application.build(parent_commitment, parent_block).await;
                let coded_block = CodedBlock::new(built_block, coding_config);
                let commitment = coded_block.commitment();

                // Update the latest built block.
                let mut lock = last_built.lock().expect("failed to lock last_built mutex");
                *lock = Some((context.round, coded_block));

                let result = tx.send(commitment);
                info!(
                    round = %context.round,
                    ?commitment,
                    success = result.is_ok(),
                    "proposed new block"
                );
            });
        rx
    }

    async fn verify(
        &mut self,
        context: Context<Self::Digest>,
        payload: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        let mut marshal = self.marshal.clone();
        let self_index = self
            .supervisor
            .is_participant(context.round, &self.identity)
            .expect("failed to get self index among participants");
        self.context
            .with_label("verify")
            .spawn(move |_| async move { marshal.verify_shard(payload, self_index as usize).await })
            .await
            .expect("failed to spawn verify task")
    }
}

impl<E, A, V, B, S, P, Z> Relay for CodingAdapter<E, A, V, B, S, P, Z>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<Block = B, Context = Context<B::Commitment>>,
    V: Variant,
    B: Block<Commitment = S::Commitment>,
    S: Scheme,
    P: PublicKey,
    Z: Supervisor<Index = Round, PublicKey = P>,
{
    type Digest = B::Commitment;

    async fn broadcast(&mut self, _commitment: Self::Digest) {
        let Some((round, block)) = self.last_built.lock().unwrap().clone() else {
            warn!("missing block to broadcast");
            return;
        };

        let participants = self
            .supervisor
            .participants(round)
            .cloned()
            .expect("failed to get participants for round");

        debug!(
            round = %round,
            commitment = %block.commitment(),
            height = block.height(),
            "requested broadcast of built block"
        );
        self.marshal.broadcast(block.clone(), participants).await;
    }
}

impl<E, A, V, B, S, P, Z> Reporter for CodingAdapter<E, A, V, B, S, P, Z>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<Block = B, Context = Context<B::Commitment>>,
    V: Variant,
    B: Block<Commitment = S::Commitment>,
    S: Scheme,
    P: PublicKey,
    Z: Supervisor<Index = Round, PublicKey = P>,
{
    type Activity = B;

    async fn report(&mut self, block: Self::Activity) {
        self.application.finalize(block).await
    }
}
