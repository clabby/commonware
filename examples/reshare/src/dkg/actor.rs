use super::{Mailbox, Message};
use crate::{
    application::B,
    dkg::{Dkg, Payload, ReshareOutcome, OUTCOME_NAMESPACE},
};
use commonware_codec::{Decode, Encode, EncodeSize, FixedSize, Write};
use commonware_cryptography::{
    bls12381::{
        dkg::{Arbiter, Dealer, Player},
        primitives::{group::Share, poly::Public, variant::MinSig},
    },
    ed25519::{PrivateKey, PublicKey, Signature},
    Signer, Verifier,
};
use commonware_macros::select;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{tokio, Clock, Handle, Metrics, Spawner};
use futures::{channel::mpsc, lock::Mutex, SinkExt, StreamExt};
use std::{
    collections::HashMap,
    ops::Deref,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tracing::{info, warn};

const ACK_NAMESPACE: &[u8] = b"COMMONWARE_DKG_ACK";
const CONCURRENCY: usize = 1;

/// Configuration for a DKG [Actor].
pub struct Config {
    /// The signer for this DKG participant.
    pub signer: PrivateKey,

    /// The contributors to the DKG.
    pub contributors: Vec<PublicKey>,

    /// The starting polynomial.
    pub polynomial: Public<MinSig>,

    /// The starting share.
    pub share: Share,

    /// The mailbox size.
    pub mailbox_size: usize,
}

pub struct Actor {
    context: tokio::Context,
    mailbox: mpsc::Receiver<Message>,

    signer: PrivateKey,
    contributors: Arc<Vec<PublicKey>>,
    contributors_ordered: HashMap<PublicKey, u32>,
    polynomial: Arc<Mutex<Public<MinSig>>>,
    share: Arc<Mutex<Share>>,

    round: Arc<AtomicU64>,
    round_outcome: Arc<Mutex<Option<ReshareOutcome>>>,
}

impl Actor {
    /// Create a new DKG [Actor] and its associated [Mailbox].
    pub fn new(context: tokio::Context, mut config: Config) -> (Self, Mailbox) {
        config.contributors.sort();
        let contributors_ordered: HashMap<PublicKey, u32> = config
            .contributors
            .iter()
            .enumerate()
            .map(|(idx, pk)| (pk.clone(), idx as u32))
            .collect();

        let (sender, mailbox) = mpsc::channel(config.mailbox_size);
        (
            Self {
                context,
                mailbox,
                signer: config.signer,
                contributors: Arc::new(config.contributors),
                contributors_ordered,
                polynomial: Arc::new(Mutex::new(config.polynomial)),
                share: Arc::new(Mutex::new(config.share)),
                round: Arc::new(AtomicU64::new(0)),
                round_outcome: Arc::new(Mutex::new(None)),
            },
            Mailbox::new(sender),
        )
    }

    /// Start the DKG actor.
    pub fn start(
        mut self,
        (sender, receiver): (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
    ) -> Handle<()> {
        self.context.spawn_ref()(async move {
            let receiver = Arc::new(Mutex::new(receiver));

            let mut round_sender = None;

            while let Some(message) = self.mailbox.next().await {
                match message {
                    Message::Act { response } => {
                        // Post an outcome as soon as it's available.
                        let outcome = self.round_outcome.lock().await.take();
                        if outcome.is_some() {
                            info!("posting round outcome to log");
                        }

                        let _ = response.send(outcome);
                    }
                    Message::Finalized { block } => {
                        if round_sender.is_none()
                            || round_sender
                                .as_ref()
                                .map(|b: &mpsc::UnboundedSender<B>| b.is_closed())
                                .unwrap_or(false)
                        {
                            self.context.sleep(Duration::from_secs(1)).await;
                            round_sender = Some(self.run_round(sender.clone(), receiver.clone()));
                        }

                        if let Some(ref mut tx) = round_sender {
                            if let Err(e) = tx.send(block).await {
                                warn!(error = ?e, "failed to send block to round handler");
                            }
                        }
                    }
                }
            }

            info!(target: "dkg", "mailbox closed, exiting.");
        })
    }

    fn run_round(
        &mut self,
        mut sender: impl Sender<PublicKey = PublicKey>,
        receiver: Arc<Mutex<impl Receiver<PublicKey = PublicKey>>>,
    ) -> mpsc::UnboundedSender<B> {
        let me_idx = *self
            .contributors_ordered
            .get(&self.signer.public_key())
            .unwrap();
        let me = self.signer.clone();
        let round = self.round.load(Ordering::Relaxed);
        let round_a = self.round.clone();
        let contributors = self.contributors.clone();
        let round_outcome = self.round_outcome.clone();

        // Create participants and arbiter
        let (mut dealer, commitment, shares) = Dealer::<_, MinSig>::new(
            &mut self.context,
            Some(self.share.try_lock().unwrap().deref().clone()),
            self.contributors.as_ref().clone(),
        );
        let mut acks: HashMap<u32, Signature> = HashMap::new();
        let mut player = Player::<_, MinSig>::new(
            self.signer.public_key(),
            Some(self.polynomial.try_lock().unwrap().deref().clone()),
            self.contributors.as_ref().clone(),
            self.contributors.as_ref().clone(),
            CONCURRENCY,
        );
        let mut arbiter = Arbiter::<_, MinSig>::new(
            Some(self.polynomial.try_lock().unwrap().deref().clone()),
            self.contributors.as_ref().clone(),
            self.contributors.as_ref().clone(),
            CONCURRENCY,
        );

        let polynomial = self.polynomial.clone();
        let share = self.share.clone();

        let (blocks_tx, mut blocks_rx) = mpsc::unbounded::<B>();
        self.context
            .with_label("dkg_round")
            .spawn(move |context| async move {
                info!(round, "starting new reshare round");

                Self::distribute_shares(
                    round,
                    &me,
                    me_idx,
                    &contributors,
                    &commitment,
                    &shares,
                    &mut sender,
                    &mut dealer,
                    &mut player,
                    &mut acks,
                )
                .await;

                Self::process_messages(
                    &context,
                    round,
                    &me,
                    me_idx,
                    &contributors,
                    &commitment,
                    &mut sender,
                    receiver,
                    &mut player,
                    &mut dealer,
                    &mut acks,
                )
                .await;

                // After processing messages, any contributors that did not acknowledge their share
                // have theirs revealed.
                let mut reveals = Vec::new();
                for idx in 0..contributors.len() as u32 {
                    if !acks.contains_key(&idx) {
                        reveals.push(shares[idx as usize].clone());
                    }
                }

                // Register the local dealer's outcome.
                let ack_keys = acks.keys().copied().collect::<Vec<_>>();
                arbiter
                    .commitment(
                        me.public_key(),
                        commitment.clone(),
                        ack_keys,
                        reveals.clone(),
                    )
                    .unwrap();

                // Store the reshare outcome for inclusion within our next proposed block.
                {
                    let mut lock = round_outcome.lock().await;
                    *lock = Some(ReshareOutcome::new(
                        &me,
                        round,
                        commitment,
                        acks.into_iter().collect::<Vec<_>>(),
                        Some(reveals),
                    ));
                }

                Self::process_blocks(
                    round,
                    &me,
                    me_idx,
                    &mut blocks_rx,
                    &contributors,
                    arbiter,
                    player,
                    polynomial,
                    share,
                    round_a,
                )
                .await
            });

        blocks_tx
    }

    /// Distributes shares generated by the local [Dealer] to all contributors over encrypted p2p,
    /// including the local [Player].
    ///
    /// Because we trust the local [Dealer], we can immediately consume the share for the local
    /// [Player].
    async fn distribute_shares(
        round: u64,
        me: &PrivateKey,
        me_idx: u32,
        contributors: &[PublicKey],
        commitment: &Public<MinSig>,
        shares: &[Share],
        sender: &mut impl Sender<PublicKey = PublicKey>,
        dealer: &mut Dealer<PublicKey, MinSig>,
        player: &mut Player<PublicKey, MinSig>,
        acks: &mut HashMap<u32, Signature>,
    ) {
        for (idx, player_public) in contributors.iter().enumerate() {
            let share = shares[idx].clone();
            if idx == me_idx as usize {
                player
                    .share(me.public_key(), commitment.clone(), share)
                    .expect("failed to share");
                dealer.ack(me.public_key()).expect("failed to ack");

                let payload = payload(round, &me.public_key(), &commitment);
                let signature = me.sign(Some(ACK_NAMESPACE), &payload);
                acks.insert(me_idx, signature);
                continue;
            }

            let payload = Dkg {
                round,
                payload: Payload::Share {
                    commitment: commitment.clone(),
                    share,
                },
            };
            let success = sender
                .send(
                    Recipients::One(player_public.clone()),
                    payload.encode().freeze(),
                    true,
                )
                .await
                .expect("could not send share");

            if success.is_empty() {
                warn!(round, player = ?player_public, "failed to send share");
            } else {
                info!(round, player = ?player_public, "sent share");
            }
        }
    }

    /// Processes incoming messages from other contributors.
    ///
    /// - [Payload::Ack] messages come from other [Player]s acknowledging receipt of their share.
    /// - [Payload::Share] messages come from other [Dealer]s distributing shares to the local [Player].
    async fn process_messages(
        context: &tokio::Context,
        round: u64,
        me: &PrivateKey,
        me_idx: u32,
        contributors: &[PublicKey],
        commitment: &Public<MinSig>,
        sender: &mut impl Sender<PublicKey = PublicKey>,
        receiver: Arc<Mutex<impl Receiver<PublicKey = PublicKey>>>,
        player: &mut Player<PublicKey, MinSig>,
        dealer: &mut Dealer<PublicKey, MinSig>,
        acks: &mut HashMap<u32, Signature>,
    ) {
        let mut receiver = receiver.lock().await;
        loop {
            select! {
                // TODO: Wait a certain # of blocks, rather than a fixed time?
                _ = context.sleep(Duration::from_secs(10)) => {
                    tracing::warn!("! DBG ! ABORTING MESSAGE PROCESSING");
                    break;
                },
                message = receiver.recv() => {
                    let (peer, message) = message.expect("receiver closed");

                    let msg = Dkg::decode_cfg(message, &contributors.len()).unwrap();
                    if msg.round != round {
                        warn!("Received invalid message from peer");
                        continue;
                    }

                    match msg.payload {
                        Payload::Ack {
                            public_key,
                            signature,
                        } => {
                            // Verify index matches
                            let Some(player) = contributors.get(public_key as usize) else {
                                warn!(round, index = public_key, "invalid ack index");
                                continue;
                            };

                            if player != &peer {
                                warn!(round, index = public_key, "mismatched ack index");
                                continue;
                            }

                            // Verify signature on incoming ack
                            let payload = payload(round, &me.public_key(), &commitment);
                            if !peer.verify(Some(ACK_NAMESPACE), &payload, &signature) {
                                warn!(round, index = public_key, "invalid ack signature");
                                continue;
                            }

                            // Store ack
                            if let Err(e) = dealer.ack(peer) {
                                warn!(round, index = public_key, error = ?e, "failed to store ack");
                                continue;
                            }
                            acks.insert(public_key, signature);

                            info!(round, index = public_key, "stored ack");
                        }
                        Payload::Share { commitment, share } => {
                            // Store share
                            if let Err(e) = player.share(peer.clone(), commitment.clone(), share) {
                                warn!(round, error = ?e, "failed to store share");
                                continue;
                            }

                            // Send ack
                            let payload = payload(round, &peer, &commitment);
                            let signature = me.sign(Some(ACK_NAMESPACE), &payload);
                            let ack = Dkg {
                                round,
                                payload: Payload::Ack {
                                    public_key: me_idx,
                                    signature: signature.clone(),
                                },
                            };
                            sender
                                .send(Recipients::One(peer), ack.encode().freeze(), true)
                                .await
                                .expect("could not send ack");
                        }
                    }
                }
            }
        }
    }

    async fn process_blocks(
        round: u64,
        me: &PrivateKey,
        me_idx: u32,
        blocks_rx: &mut mpsc::UnboundedReceiver<B>,
        contributors: &[PublicKey],
        mut arbiter: Arbiter<PublicKey, MinSig>,
        player: Player<PublicKey, MinSig>,
        polynomial: Arc<Mutex<Public<MinSig>>>,
        share: Arc<Mutex<Share>>,
        round_a: Arc<AtomicU64>,
    ) {
        while let Some(block) = blocks_rx.next().await {
            if let Some(outcome) = block.reshare_outcome {
                //dbg
                tracing::info!(round = outcome.round, dealer = ?outcome.dealer, "processing block reshare outcome");

                if outcome.round != round {
                    warn!(
                        outcome_round = outcome.round,
                        current_round = round,
                        "observed mismatched round in finalized block"
                    );
                    return;
                }

                if outcome.dealer == me.public_key() {
                    // We've already processed our own outcome.
                    continue;
                }

                // Verify the dealer signature before considering processing the outcome.
                let outcome_payload = outcome.signature_payload();
                if !outcome.dealer.verify(
                    Some(OUTCOME_NAMESPACE),
                    &outcome_payload,
                    &outcome.dealer_signature,
                ) {
                    warn!(round, "invalid dealer signature; ignoring outcome");
                    return;
                }

                // Verify all ack signatures
                let payload = payload(round, &outcome.dealer, &outcome.commitment);
                if !outcome.acks.iter().all(|(i, sig)| {
                    contributors
                        .get(*i as usize)
                        .map(|public_key| public_key.verify(Some(ACK_NAMESPACE), &payload, sig))
                        .unwrap_or(false)
                }) {
                    warn!(round, "invalid ack signatures; disqualifying dealer");
                    arbiter.disqualify(outcome.dealer);
                    return;
                }

                // Check dealer commitment
                let ack_indices = outcome
                    .acks
                    .iter()
                    .map(|(i, _)| i)
                    .copied()
                    .collect::<Vec<_>>();
                if let Err(e) = arbiter.commitment(
                    outcome.dealer,
                    outcome.commitment,
                    ack_indices,
                    outcome.reveals.unwrap_or_default(),
                ) {
                    warn!(round, error = ?e, "failed to process commitment");
                    return;
                }

                if arbiter.ready() {
                    let (result, _disqualified) = arbiter.finalize();
                    let output = result.unwrap();

                    let mut commitments = HashMap::new();
                    for (dealer_idx, commitment) in output.commitments {
                        commitments.insert(dealer_idx, commitment);
                    }
                    let mut reveals = HashMap::new();
                    for (dealer_idx, shares) in output.reveals {
                        for share in shares {
                            reveals
                                .entry(share.index)
                                .or_insert_with(HashMap::new)
                                .insert(dealer_idx, share);
                        }
                    }

                    let output = player
                        .finalize(commitments, reveals.remove(&me_idx).unwrap_or_default())
                        .unwrap();
                    tracing::info!(output = ?output.share, commitment = ?output.public, "finalized reshare");

                    round_a.fetch_add(1, Ordering::SeqCst);
                    // let mut lock = polynomial.lock().await;
                    // *lock = output.public;
                    // let mut lock = share.lock().await;
                    // *lock = output.share;
                    break;
                }
            }
        }
    }
}

/// Create a payload for acking a secret.
pub fn payload(round: u64, dealer: &PublicKey, commitment: &Public<MinSig>) -> Vec<u8> {
    let mut payload = Vec::with_capacity(u64::SIZE + PublicKey::SIZE + commitment.encode_size());
    round.write(&mut payload);
    dealer.write(&mut payload);
    commitment.write(&mut payload);
    payload
}
