//! Ordered delivery of finalized blocks.
//!
//! # Architecture
//!
//! The core of the module is the [actor::Actor]. It marshals the finalized blocks into order by:
//!
//! - Receiving uncertified blocks from a broadcast mechanism
//! - Receiving notarizations and finalizations from consensus
//! - Reconstructing a total order of finalized blocks
//! - Providing a backfill mechanism for missing blocks
//!
//! The actor interacts with four main components:
//! - [crate::Reporter]: Receives ordered, finalized blocks at-least-once
//! - [crate::threshold_simplex]: Provides consensus messages
//! - Application: Provides verified blocks
//! - [commonware_broadcast::buffered]: Provides uncertified blocks received from the network
//! - [commonware_resolver::Resolver]: Provides a backfill mechanism for missing blocks
//!
//! # Design
//!
//! ## Delivery
//!
//! The actor will deliver a block to the reporter at-least-once. The reporter should be prepared to
//! handle duplicate deliveries. However the blocks will be in order.
//!
//! ## Finalization
//!
//! The actor uses a view-based model to track the state of the chain. Each view corresponds
//! to a potential block in the chain. The actor will only finalize a block (and its ancestors)
//! if it has a corresponding finalization from consensus.
//!
//! ## Backfill
//!
//! The actor provides a backfill mechanism for missing blocks. If the actor notices a gap in its
//! knowledge of finalized blocks, it will request the missing blocks from its peers. This ensures
//! that the actor can catch up to the rest of the network if it falls behind.
//!
//! ## Storage
//!
//! The actor uses a combination of prunable and immutable storage to store blocks and
//! finalizations. Prunable storage is used to store data that is only needed for a short
//! period of time, such as unverified blocks or notarizations. Immutable storage is used to
//! store data that needs to be persisted indefinitely, such as finalized blocks. This allows
//! the actor to keep its storage footprint small while still providing a full history of the
//! chain.
//!
//! ## Limitations and Future Work
//!
//! - Only works with [crate::threshold_simplex] rather than general consensus.
//! - Assumes at-most one notarization per view, incompatible with some consensus protocols.
//! - No state sync supported. Will attempt to sync every block in the history of the chain.
//! - Stores the entire history of the chain, which requires indefinite amounts of disk space.
//! - Uses [`broadcast::buffered`](`commonware_broadcast::buffered`) for broadcasting and receiving
//!   uncertified blocks from the network.

pub mod actor;
pub use actor::Actor;
pub mod cache;
pub mod config;
pub use config::Config;
pub mod finalizer;
pub use finalizer::Finalizer;
pub mod ingress;
pub use ingress::mailbox::Mailbox;
pub mod resolver;

#[cfg(test)]
pub mod mocks;

#[cfg(test)]
mod tests {
    use super::{
        actor,
        config::Config,
        mocks::{application::Application, block::Block},
        resolver::p2p as resolver,
    };
    use crate::{
        marshal::ingress::coding::{CodedBlock, ShardLayer},
        threshold_simplex::types::{
            finalize_namespace, notarize_namespace, seed_namespace, Activity, Finalization,
            Notarization, Notarize, Proposal,
        },
        types::Round,
        Block as _, Reporter,
    };
    use commonware_broadcast::buffered;
    use commonware_codec::Encode;
    use commonware_coding::reed_solomon::{self, Chunk};
    use commonware_cryptography::{
        bls12381::{
            dkg::ops::generate_shares,
            primitives::{
                group::Share,
                ops::{partial_sign_message, threshold_signature_recover},
                poly,
                variant::{MinPk, Variant},
            },
        },
        ed25519::{PrivateKey, PublicKey},
        sha256::Sha256,
        Committable, Digestible, Hasher, PrivateKeyExt as _, Signer as _,
    };
    use commonware_macros::test_traced;
    use commonware_p2p::{
        simulated::{self, Link, Network, Oracle},
        utils::requester,
    };
    use commonware_resolver::p2p;
    use commonware_runtime::{buffer::PoolRef, deterministic, Clock, Metrics, Runner};
    use commonware_utils::{NZUsize, NZU64};
    use governor::Quota;
    use rand::Rng;
    use std::{
        collections::BTreeMap,
        num::{NonZeroU32, NonZeroUsize},
        time::Duration,
    };

    type H = Sha256;
    type D = <H as Hasher>::Digest;
    type B = CodedBlock<Block<D>, Sha256>;
    type P = PublicKey;
    type V = MinPk;
    type Sh = Share;
    type E = PrivateKey;

    const PAGE_SIZE: NonZeroUsize = NZUsize!(1024);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);
    const NAMESPACE: &[u8] = b"test";
    const NUM_VALIDATORS: u32 = 4;
    const QUORUM: u32 = 3;
    const NUM_BLOCKS: u64 = 160;
    const BLOCKS_PER_EPOCH: u64 = 20;
    const LINK: Link = Link {
        latency: Duration::from_millis(10),
        jitter: Duration::from_millis(1),
        success_rate: 1.0,
    };
    const UNRELIABLE_LINK: Link = Link {
        latency: Duration::from_millis(200),
        jitter: Duration::from_millis(50),
        success_rate: 0.7,
    };

    async fn setup_validator(
        context: deterministic::Context,
        oracle: &mut Oracle<P>,
        coordinator: p2p::mocks::Coordinator<P>,
        secret: E,
        identity: <V as Variant>::Public,
    ) -> (
        Application<B>,
        crate::marshal::ingress::mailbox::Mailbox<V, B, P, H>,
    ) {
        let config = Config {
            identity,
            mailbox_size: 100,
            namespace: NAMESPACE.to_vec(),
            view_retention_timeout: 10,
            max_repair: 10,
            codec_config: (),
            partition_prefix: format!("validator-{}", secret.public_key()),
            prunable_items_per_section: NZU64!(10),
            replay_buffer: NZUsize!(1024),
            write_buffer: NZUsize!(1024),
            freezer_table_initial_size: 64,
            freezer_table_resize_frequency: 10,
            freezer_table_resize_chunk_size: 10,
            freezer_journal_target_size: 1024,
            freezer_journal_compression: None,
            freezer_journal_buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            immutable_items_per_section: NZU64!(10),
        };

        // Create the resolver
        let backfill = oracle.register(secret.public_key(), 1).await.unwrap();
        let resolver_cfg = resolver::Config {
            public_key: secret.public_key(),
            coordinator,
            mailbox_size: config.mailbox_size,
            requester_config: requester::Config {
                public_key: secret.public_key(),
                rate_limit: Quota::per_second(NonZeroU32::new(5).unwrap()),
                initial: Duration::from_secs(1),
                timeout: Duration::from_secs(2),
            },
            fetch_retry_timeout: Duration::from_millis(100),
            priority_requests: false,
            priority_responses: false,
        };
        let resolver = resolver::init(&context, resolver_cfg, backfill);

        // Create a buffered broadcast engine and get its mailbox
        let broadcast_config = buffered::Config {
            public_key: secret.public_key(),
            mailbox_size: config.mailbox_size,
            deque_size: 10,
            priority: false,
            codec_config: (),
        };
        let (broadcast_engine, buffer) = buffered::Engine::new(context.clone(), broadcast_config);
        let network = oracle.register(secret.public_key(), 2).await.unwrap();
        broadcast_engine.start(network);

        let shards = ShardLayer::new(buffer, ());

        let (actor, mailbox) = actor::Actor::init(context.clone(), config).await;
        let application = Application::<B>::default();

        // Start the application
        actor.start(application.clone(), shards, resolver);

        (application, mailbox)
    }

    fn make_finalization(proposal: Proposal<D>, shares: &[Sh], quorum: u32) -> Finalization<V, D> {
        let proposal_msg = proposal.encode();

        // Generate proposal signature
        let proposal_partials: Vec<_> = shares
            .iter()
            .take(quorum as usize)
            .map(|s| {
                partial_sign_message::<V>(s, Some(&finalize_namespace(NAMESPACE)), &proposal_msg)
            })
            .collect();
        let proposal_signature =
            threshold_signature_recover::<V, _>(quorum, &proposal_partials).unwrap();

        // Generate seed signature (for the view number)
        let seed_msg = proposal.round.encode();
        let seed_partials: Vec<_> = shares
            .iter()
            .take(quorum as usize)
            .map(|s| partial_sign_message::<V>(s, Some(&seed_namespace(NAMESPACE)), &seed_msg))
            .collect();
        let seed_signature = threshold_signature_recover::<V, _>(quorum, &seed_partials).unwrap();

        Finalization {
            proposal,
            proposal_signature,
            seed_signature,
        }
    }

    fn make_notarization_vote(proposal: Proposal<D>, share: &Sh) -> Notarize<V, D> {
        let proposal_msg = proposal.encode();

        // Generate proposal signature
        let proposal_partial =
            partial_sign_message::<V>(share, Some(&notarize_namespace(NAMESPACE)), &proposal_msg);

        // Generate seed signature (for the view number)
        let seed_msg = proposal.round.encode();
        let seed_partial =
            partial_sign_message::<V>(share, Some(&seed_namespace(NAMESPACE)), &seed_msg);

        Notarize {
            proposal,
            proposal_signature: proposal_partial,
            seed_signature: seed_partial,
        }
    }

    fn make_notarization(proposal: Proposal<D>, shares: &[Sh], quorum: u32) -> Notarization<V, D> {
        let proposal_msg = proposal.encode();

        // Generate proposal signature
        let proposal_partials: Vec<_> = shares
            .iter()
            .take(quorum as usize)
            .map(|s| {
                partial_sign_message::<V>(s, Some(&notarize_namespace(NAMESPACE)), &proposal_msg)
            })
            .collect();
        let proposal_signature =
            threshold_signature_recover::<V, _>(quorum, &proposal_partials).unwrap();

        // Generate seed signature (for the view number)
        let seed_msg = proposal.round.encode();
        let seed_partials: Vec<_> = shares
            .iter()
            .take(quorum as usize)
            .map(|s| partial_sign_message::<V>(s, Some(&seed_namespace(NAMESPACE)), &seed_msg))
            .collect();
        let seed_signature = threshold_signature_recover::<V, _>(quorum, &seed_partials).unwrap();

        Notarization {
            proposal,
            proposal_signature,
            seed_signature,
        }
    }

    fn setup_network(context: deterministic::Context) -> Oracle<P> {
        let (network, oracle) = Network::new(
            context.with_label("network"),
            simulated::Config {
                max_size: 1024 * 1024,
                disconnect_on_block: true,
            },
        );
        network.start();
        oracle
    }

    fn setup_validators_and_shares(
        context: &mut deterministic::Context,
    ) -> (Vec<E>, Vec<P>, <V as Variant>::Public, Vec<Sh>) {
        let mut schemes = (0..NUM_VALIDATORS)
            .map(|i| PrivateKey::from_seed(i as u64))
            .collect::<Vec<_>>();
        schemes.sort_by_key(|s| s.public_key());
        let peers: Vec<PublicKey> = schemes.iter().map(|s| s.public_key()).collect();

        let (identity, shares) = generate_shares::<_, V>(context, None, NUM_VALIDATORS, QUORUM);
        let identity = *poly::public::<V>(&identity);

        (schemes, peers, identity, shares)
    }

    async fn setup_network_links(oracle: &mut Oracle<P>, peers: &[P], link: Link) {
        for p1 in peers.iter() {
            for p2 in peers.iter() {
                if p2 == p1 {
                    continue;
                }
                oracle
                    .add_link(p1.clone(), p2.clone(), link.clone())
                    .await
                    .unwrap();
            }
        }
    }

    #[allow(clippy::type_complexity)]
    fn shard(block: &B, peers: &[P]) -> (D, (u16, u16), Vec<(P, Chunk<H>)>) {
        let (total, min) = (peers.len() as u16, peers.len() as u16 / 2);
        let (commitment, chunks) =
            reed_solomon::encode::<H>(total, min, block.encode().into()).unwrap();
        (
            commitment,
            (total, min),
            peers.iter().cloned().zip(chunks).collect(),
        )
    }

    #[test_traced("DEBUG")]
    fn test_finalize_good_links() {
        for seed in 0..5 {
            let result1 = finalize(seed, LINK);
            let result2 = finalize(seed, LINK);

            // Ensure determinism
            assert_eq!(result1, result2);
        }
    }

    #[test_traced("DEBUG")]
    fn test_finalize_bad_links() {
        for seed in 0..5 {
            let result1 = finalize(seed, UNRELIABLE_LINK);
            let result2 = finalize(seed, UNRELIABLE_LINK);

            // Ensure determinism
            assert_eq!(result1, result2);
        }
    }

    fn finalize(seed: u64, link: Link) -> String {
        let runner = deterministic::Runner::new(
            deterministic::Config::new()
                .with_timeout(Some(Duration::from_secs(300)))
                .with_seed(seed),
        );
        runner.start(|mut context| async move {
            let mut oracle = setup_network(context.clone());
            let (schemes, peers, identity, shares) = setup_validators_and_shares(&mut context);

            // Initialize applications and actors
            let mut applications = BTreeMap::new();
            let mut actors = Vec::new();
            let coordinator = p2p::mocks::Coordinator::new(peers.clone());

            for (i, secret) in schemes.iter().enumerate() {
                let (application, actor) = setup_validator(
                    context.with_label(&format!("validator-{i}")),
                    &mut oracle,
                    coordinator.clone(),
                    secret.clone(),
                    identity,
                )
                .await;
                applications.insert(peers[i].clone(), application);
                actors.push(actor);
            }

            // Add links between all peers
            setup_network_links(&mut oracle, &peers, link.clone()).await;

            // Generate blocks, skipping the genesis block.
            let mut blocks = Vec::<B>::new();
            let mut parent = Sha256::hash(b"");
            for i in 1..=NUM_BLOCKS {
                let inner = Block::new::<Sha256>(parent, i, i);
                let block = B::new(inner, (peers.len() as u16, (peers.len() / 2) as u16));
                parent = block.commitment();
                blocks.push(block);
            }

            // Broadcast and finalize blocks in random order
            // blocks.shuffle(&mut context);
            for block in blocks.iter() {
                // Skip genesis block
                let height = block.height();
                assert!(height > 0, "genesis block should not have been generated");

                // Calculate the epoch and round for the block
                let epoch = height / BLOCKS_PER_EPOCH;
                let round = Round::new(epoch, height);

                // Broadcast block by one validator
                let actor_index: usize = (height % (NUM_VALIDATORS as u64)) as usize;
                let mut actor = actors[actor_index].clone();

                let (commitment, config, chunks) = shard(block, &peers);
                actor.broadcast(commitment, config, chunks).await;

                // Wait for the block chunks to be delivered; Before making notarization votes,
                // the chunks must be present.
                context.sleep(link.latency + link.jitter).await;

                let proposal = Proposal {
                    round,
                    parent: height.checked_sub(1).unwrap(),
                    payload: commitment,
                };

                // All validators send a notarization for the block.
                for (i, actor) in actors.iter_mut().enumerate() {
                    let notarization_vote = make_notarization_vote(proposal.clone(), &shares[i]);
                    actor
                        .report(Activity::Notarize(notarization_vote.clone()))
                        .await;
                }

                // Wait for the block chunks to be delivered; Before making a notarization,
                // the chunks must be present.
                context.sleep(link.latency + link.jitter).await;

                // Notarize block by the validator that broadcasted it
                let notarization = make_notarization(proposal.clone(), &shares, QUORUM);
                actor
                    .report(Activity::Notarization(notarization.clone()))
                    .await;

                // Finalize block by all validators
                let fin = make_finalization(proposal.clone(), &shares, QUORUM);
                for actor in actors.iter_mut() {
                    // Always finalize 1) the last block in each epoch 2) the last block in the chain.
                    // Otherwise, finalize randomly.
                    if height == NUM_BLOCKS
                        || height % BLOCKS_PER_EPOCH == 0
                        || context.gen_bool(0.2)
                    // 20% chance to finalize randomly
                    {
                        actor.report(Activity::Finalization(fin.clone())).await;
                    }
                }
            }

            // Check that all applications received all blocks.
            let mut blocks = Vec::with_capacity(actors.len());
            let mut finished = false;
            while !finished {
                // Avoid a busy loop
                context.sleep(Duration::from_secs(1)).await;

                // If not all validators have finished, try again
                if applications.len() != NUM_VALIDATORS as usize {
                    continue;
                }
                finished = true;
                for app in applications.values() {
                    if app.blocks().len() != NUM_BLOCKS as usize {
                        finished = false;
                        break;
                    } else {
                        blocks.push(app.blocks());
                    }
                }
            }

            // Ensure all apps have the same chain.
            let first = blocks.first().cloned().unwrap();
            blocks.iter().skip(1).all(|b| b == &first);

            // Return state
            context.auditor().state()
        })
    }

    #[test_traced("DEBUG")]
    fn test_subscribe_basic_block_delivery() {
        let runner = deterministic::Runner::timed(Duration::from_secs(60));
        runner.start(|mut context| async move {
            let mut oracle = setup_network(context.clone());
            let (schemes, peers, identity, shares) = setup_validators_and_shares(&mut context);
            let coordinator = p2p::mocks::Coordinator::new(peers.clone());

            let mut actors = Vec::new();
            for (i, secret) in schemes.iter().enumerate() {
                let (_application, actor) = setup_validator(
                    context.with_label(&format!("validator-{i}")),
                    &mut oracle,
                    coordinator.clone(),
                    secret.clone(),
                    identity,
                )
                .await;
                actors.push(actor);
            }
            let mut actor = actors[0].clone();

            setup_network_links(&mut oracle, &peers, LINK).await;

            let parent = Sha256::hash(b"");
            let inner = Block::new::<Sha256>(parent, 1, 1);
            let block = B::new(inner, (peers.len() as u16, (peers.len() / 2) as u16));

            let (commitment, config, chunks) = shard(&block, &peers);
            actor.broadcast(commitment, config, chunks).await;

            let subscription_rx = actors[1]
                .subscribe(Some(Round::from((0, 1))), commitment)
                .await;

            let proposal = Proposal {
                round: Round::new(0, 1),
                parent: 0,
                payload: commitment,
            };

            // All validators send a notarization for the block.
            for (i, actor) in actors.iter_mut().enumerate() {
                let notarization_vote = make_notarization_vote(proposal.clone(), &shares[i]);
                actor
                    .report(Activity::Notarize(notarization_vote.clone()))
                    .await;
            }

            let notarization = make_notarization(proposal.clone(), &shares, QUORUM);
            actor.report(Activity::Notarization(notarization)).await;

            let finalization = make_finalization(proposal, &shares, QUORUM);
            actor.report(Activity::Finalization(finalization)).await;

            let received_block = subscription_rx.await.unwrap();
            assert_eq!(received_block.digest(), block.digest());
            assert_eq!(received_block.height(), 1);
        })
    }

    #[test_traced("DEBUG")]
    fn test_subscribe_multiple_subscriptions() {
        let runner = deterministic::Runner::timed(Duration::from_secs(60));
        runner.start(|mut context| async move {
            let mut oracle = setup_network(context.clone());
            let (schemes, peers, identity, shares) = setup_validators_and_shares(&mut context);
            let coordinator = p2p::mocks::Coordinator::new(peers.clone());

            let mut actors = Vec::new();
            for (i, secret) in schemes.iter().enumerate() {
                let (_application, actor) = setup_validator(
                    context.with_label(&format!("validator-{i}")),
                    &mut oracle,
                    coordinator.clone(),
                    secret.clone(),
                    identity,
                )
                .await;
                actors.push(actor);
            }
            let mut actor = actors[0].clone();

            setup_network_links(&mut oracle, &peers, LINK).await;

            let (total, min) = (peers.len() as u16, (peers.len() / 2) as u16);

            let parent = Sha256::hash(b"");
            let inner1 = Block::new::<Sha256>(parent, 1, 1);
            let block1 = B::new(inner1, (total, min));
            let inner2 = Block::new::<Sha256>(block1.digest(), 2, 2);
            let block2 = B::new(inner2, (total, min));

            let (commitment1, config1, chunks1) = shard(&block1, &peers);
            let (commitment2, config2, chunks2) = shard(&block2, &peers);

            let sub1_rx = actor
                .subscribe(Some(Round::from((0, 1))), commitment1)
                .await;
            let sub2_rx = actor
                .subscribe(Some(Round::from((0, 2))), commitment2)
                .await;
            let sub3_rx = actor
                .subscribe(Some(Round::from((0, 1))), commitment1)
                .await;

            actor.broadcast(commitment1, config1, chunks1).await;
            actor.broadcast(commitment2, config2, chunks2).await;

            for (view, block) in [(1, block1.clone()), (2, block2.clone())] {
                let proposal = Proposal {
                    round: Round::new(0, view),
                    parent: view.checked_sub(1).unwrap(),
                    payload: block.commitment(),
                };

                // Send notarization votes from all validators
                for (i, actor) in actors.iter_mut().enumerate() {
                    let notarization_vote = make_notarization_vote(proposal.clone(), &shares[i]);
                    actor
                        .report(Activity::Notarize(notarization_vote.clone()))
                        .await;
                }

                let notarization = make_notarization(proposal.clone(), &shares, QUORUM);
                actor.report(Activity::Notarization(notarization)).await;

                let finalization = make_finalization(proposal, &shares, QUORUM);
                actor.report(Activity::Finalization(finalization)).await;
            }

            let received1_sub1 = sub1_rx.await.unwrap();
            let received2 = sub2_rx.await.unwrap();
            let received1_sub3 = sub3_rx.await.unwrap();

            assert_eq!(received1_sub1.digest(), block1.digest());
            assert_eq!(received2.digest(), block2.digest());
            assert_eq!(received1_sub3.digest(), block1.digest());
            assert_eq!(received1_sub1.height(), 1);
            assert_eq!(received2.height(), 2);
            assert_eq!(received1_sub3.height(), 1);
        })
    }

    #[test_traced("WARN")]
    fn test_subscribe_canceled_subscriptions() {
        let runner = deterministic::Runner::timed(Duration::from_secs(60));
        runner.start(|mut context| async move {
            let mut oracle = setup_network(context.clone());
            let (schemes, peers, identity, shares) = setup_validators_and_shares(&mut context);
            let coordinator = p2p::mocks::Coordinator::new(peers.clone());

            let mut actors = Vec::new();
            for (i, secret) in schemes.iter().enumerate() {
                let (_application, actor) = setup_validator(
                    context.with_label(&format!("validator-{i}")),
                    &mut oracle,
                    coordinator.clone(),
                    secret.clone(),
                    identity,
                )
                .await;
                actors.push(actor);
            }
            let mut actor = actors[0].clone();

            setup_network_links(&mut oracle, &peers, LINK).await;

            let (total, min) = (peers.len() as u16, (peers.len() / 2) as u16);

            let parent = Sha256::hash(b"");
            let inner1 = Block::new::<Sha256>(parent, 1, 1);
            let block1 = B::new(inner1, (total, min));
            let inner2 = Block::new::<Sha256>(block1.digest(), 2, 2);
            let block2 = B::new(inner2, (total, min));
            let (commitment1, config1, chunks1) = shard(&block1, &peers);
            let (commitment2, config2, chunks2) = shard(&block2, &peers);

            actor.broadcast(commitment1, config1, chunks1).await;
            actor.broadcast(commitment2, config2, chunks2).await;

            let sub1_rx = actor
                .subscribe(Some(Round::from((0, 1))), commitment1)
                .await;
            let sub2_rx = actor
                .subscribe(Some(Round::from((0, 2))), commitment2)
                .await;

            drop(sub1_rx);

            for (view, block) in [(1, block1.clone()), (2, block2.clone())] {
                let proposal = Proposal {
                    round: Round::new(0, view),
                    parent: view.checked_sub(1).unwrap(),
                    payload: block.commitment(),
                };

                // Send notarization votes from all validators
                for (i, actor) in actors.iter_mut().enumerate() {
                    let notarization_vote = make_notarization_vote(proposal.clone(), &shares[i]);
                    actor
                        .report(Activity::Notarize(notarization_vote.clone()))
                        .await;
                }

                let notarization = make_notarization(proposal.clone(), &shares, QUORUM);
                actor.report(Activity::Notarization(notarization)).await;

                let finalization = make_finalization(proposal, &shares, QUORUM);
                actor.report(Activity::Finalization(finalization)).await;
            }

            let received2 = sub2_rx.await.unwrap();
            assert_eq!(received2.digest(), block2.digest());
            assert_eq!(received2.height(), 2);
        })
    }

    #[test_traced("DEBUG")]
    fn test_subscribe_blocks_from_different_sources() {
        let runner = deterministic::Runner::default();
        runner.start(|mut context| async move {
            let mut oracle = setup_network(context.clone());
            let (schemes, peers, identity, shares) = setup_validators_and_shares(&mut context);
            let coordinator = p2p::mocks::Coordinator::new(peers.clone());

            let mut actors = Vec::new();
            for (i, secret) in schemes.iter().enumerate() {
                let (_application, actor) = setup_validator(
                    context.with_label(&format!("validator-{i}")),
                    &mut oracle,
                    coordinator.clone(),
                    secret.clone(),
                    identity,
                )
                .await;
                actors.push(actor);
            }
            let mut actor = actors[0].clone();

            setup_network_links(&mut oracle, &peers, LINK).await;

            let (total, min) = (peers.len() as u16, (peers.len() / 2) as u16);

            let parent = Sha256::hash(b"");
            let inner1 = Block::new::<Sha256>(parent, 1, 1);
            let block1 = B::new(inner1, (total, min));
            let inner2 = Block::new::<Sha256>(block1.digest(), 2, 2);
            let block2 = B::new(inner2, (total, min));

            let (commitment1, config1, chunks1) = shard(&block1, &peers);
            let (commitment2, config2, chunks2) = shard(&block2, &peers);

            // Block1: Broadcasted by self
            actor.broadcast(commitment1, config1, chunks1).await;
            context.sleep(Duration::from_millis(20)).await;

            let sub1_rx = actor
                .subscribe(Some(Round::from((0, 1))), commitment1)
                .await;

            let proposal1 = Proposal {
                round: Round::new(0, 1),
                parent: 0,
                payload: block1.commitment(),
            };
            for (i, actor) in actors.iter_mut().enumerate() {
                let notarization_vote = make_notarization_vote(proposal1.clone(), &shares[i]);
                actor
                    .report(Activity::Notarize(notarization_vote.clone()))
                    .await;
            }

            context.sleep(Duration::from_millis(20)).await;

            let notarization1 = make_notarization(proposal1.clone(), &shares, QUORUM);
            actor.report(Activity::Notarization(notarization1)).await;

            // Block1: delivered
            let received1 = sub1_rx.await.unwrap();
            assert_eq!(received1.digest(), block1.digest());
            assert_eq!(received1.height(), 1);

            // Block2: Broadcasted by a remote node (different actor)
            let remote_actor = &mut actors[1].clone();
            remote_actor.broadcast(commitment2, config2, chunks2).await;
            context.sleep(Duration::from_millis(20)).await;

            let sub2_rx = actor
                .subscribe(Some(Round::from((0, 1))), commitment2)
                .await;

            let proposal2 = Proposal {
                round: Round::new(0, 1),
                parent: 0,
                payload: block2.commitment(),
            };
            for (i, actor) in actors.iter_mut().enumerate() {
                let notarization_vote = make_notarization_vote(proposal2.clone(), &shares[i]);
                actor
                    .report(Activity::Notarize(notarization_vote.clone()))
                    .await;
            }

            context.sleep(Duration::from_millis(20)).await;

            let notarization2 = make_notarization(proposal2.clone(), &shares, QUORUM);
            actor.report(Activity::Notarization(notarization2)).await;

            // Block2: delivered
            let received2 = sub2_rx.await.unwrap();
            assert_eq!(received2.digest(), block2.digest());
            assert_eq!(received2.height(), 2);
        })
    }
}
