//! DKG [Actor] ingress (mailbox and messages)
//!
//! [Actor]: super::Actor

use crate::{application::B, dkg::ReshareOutcome};
use commonware_consensus::Reporter;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};

/// A message that can be sent to the [Actor].
///
/// [Actor]: super::Actor
pub enum Message {
    /// A request for the [Actor]'s next [ReshareOutcome] for inclusion within a block.
    ///
    /// [Actor]: super::Actor
    Act {
        response: oneshot::Sender<Option<ReshareOutcome>>,
    },
    /// A new block has been finalized.
    Finalized { block: B },
}

/// Inbox for sending messages to the DKG [Actor].
///
/// [Actor]: super::Actor
#[derive(Clone)]
pub struct Mailbox {
    sender: mpsc::Sender<Message>,
}

impl Mailbox {
    /// Create a new mailbox.
    pub fn new(sender: mpsc::Sender<Message>) -> Self {
        Self { sender }
    }

    /// Request the [Actor]'s next payload for inclusion within a block.
    ///
    /// [Actor]: super::Actor
    pub async fn act(&mut self) -> Option<ReshareOutcome> {
        let (response_tx, response_rx) = oneshot::channel();
        let message = Message::Act {
            response: response_tx,
        };
        self.sender.send(message).await.expect("mailbox closed");

        response_rx.await.expect("response channel closed")
    }
}

impl Reporter for Mailbox {
    type Activity = B;

    async fn report(&mut self, block: Self::Activity) {
        self.sender
            .send(Message::Finalized { block })
            .await
            .expect("mailbox closed");
    }
}
