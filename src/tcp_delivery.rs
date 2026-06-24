use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures::{Sink, SinkExt, Stream, StreamExt};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::sleep;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};

use round_based::{Incoming, MessageDestination, MessageType, MsgId, Outgoing, PartyIndex};

// ── Wire format ────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct WireMsg<M> {
    sender: PartyIndex,
    msg_type: WireMsgType,
    msg: M,
}

#[derive(Serialize, Deserialize)]
enum WireMsgType {
    Broadcast { reliable: bool },
    P2P,
}

// ── TcpDelivery ────────────────────────────────────────────────────────

pub struct TcpDelivery<M> {
    my_index: PartyIndex,
    incoming: mpsc::UnboundedReceiver<std::io::Result<Incoming<M>>>,
    peer_tx: Vec<mpsc::UnboundedSender<Bytes>>,
    pending: VecDeque<(Bytes, Vec<usize>)>,
    closed: bool,
}

impl<M: serde::Serialize + serde::de::DeserializeOwned + Unpin + Send + 'static> TcpDelivery<M> {
    fn new(
        my_index: PartyIndex,
        incoming: mpsc::UnboundedReceiver<std::io::Result<Incoming<M>>>,
        peer_tx: Vec<mpsc::UnboundedSender<Bytes>>,
    ) -> Self {
        Self {
            my_index,
            incoming,
            peer_tx,
            pending: VecDeque::new(),
            closed: false,
        }
    }
}

impl<M: serde::Serialize + serde::de::DeserializeOwned + Unpin + Send + 'static> Stream
    for TcpDelivery<M>
{
    type Item = std::io::Result<Incoming<M>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.incoming.poll_recv(cx)
    }
}

impl<M: serde::Serialize + serde::de::DeserializeOwned + Unpin + Send + 'static> Sink<Outgoing<M>>
    for TcpDelivery<M>
{
    type Error = std::io::Error;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(mut self: Pin<&mut Self>, item: Outgoing<M>) -> Result<(), Self::Error> {
        if self.closed {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "delivery closed",
            ));
        }
        let msg_type = match item.recipient {
            MessageDestination::AllParties { reliable } => WireMsgType::Broadcast { reliable },
            MessageDestination::OneParty(_) => WireMsgType::P2P,
        };
        let wire = WireMsg {
            sender: self.my_index,
            msg_type,
            msg: item.msg,
        };
        let bytes = bincode::serialize(&wire)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let recipients: Vec<usize> = match item.recipient {
            MessageDestination::AllParties { .. } => (0..self.peer_tx.len())
                .filter(|j| !self.peer_tx[*j].is_closed())
                .collect(),
            MessageDestination::OneParty(j) => vec![usize::from(j)],
        };
        self.pending.push_back((Bytes::from(bytes), recipients));
        Ok(())
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        while let Some((bytes, recipients)) = self.pending.pop_front() {
            for &j in &recipients {
                if let Some(tx) = self.peer_tx.get(j) {
                    let _ = tx.send(bytes.clone());
                }
            }
        }
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.closed = true;
        self.poll_flush(cx)
    }
}

// ──── Connect ──────────────────────────────────────────────────────────

/// Connects all parties via TCP.
///
/// Party `i` listens on `0.0.0.0:<port of addrs[i]>`. Higher-index parties
/// dial lower-index parties. Each dialer sends their party index as a 2-byte
/// handshake so the acceptor knows who connected.
pub async fn connect_tcp<M>(
    my_index: PartyIndex,
    addrs: &[std::net::SocketAddr],
) -> std::io::Result<TcpDelivery<M>>
where
    M: serde::Serialize + serde::de::DeserializeOwned + Unpin + Send + 'static,
{
    let n = addrs.len() as u16;
    let (incoming_tx, incoming_rx) = mpsc::unbounded_channel();
    let mut peer_tx: Vec<Option<mpsc::UnboundedSender<Bytes>>> = (0..n).map(|_| None).collect();
    // Dummy sender for self — never used but keeps slot occupied
    let (self_tx, _self_rx) = mpsc::unbounded_channel();
    peer_tx[usize::from(my_index)] = Some(self_tx);

    let listen_addr = format!("0.0.0.0:{}", addrs[usize::from(my_index)].port());
    // SO_REUSEADDR avoids TIME_WAIT conflict when reconnecting for signing
    let socket = tokio::net::TcpSocket::new_v4()?;
    socket.set_reuseaddr(true)?;
    socket.bind(listen_addr.parse().unwrap())?;
    let listener = Arc::new(socket.listen(1024)?);

    // Accept connections from lower-index parties (they dial us)
    let mut accept_handles = Vec::new();
    for _ in 0..my_index {
        let inc_tx = incoming_tx.clone();
        let listener = Arc::clone(&listener);
        accept_handles.push(tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let (reader, writer) = stream.into_split();
            let mut reader = reader;
            let sender = reader.read_u16().await?;
            let (tx, rx) = mpsc::unbounded_channel();
            Ok::<_, std::io::Error>((sender, tx, reader, writer, rx, inc_tx))
        }));
    }

    // Dial higher-index parties (they listen), with retries
    let mut dial_handles = Vec::new();
    for j in (my_index + 1)..n {
        let addr = addrs[usize::from(j)];
        let inc_tx = incoming_tx.clone();
        dial_handles.push(tokio::spawn(async move {
            let mut stream = loop {
                match TcpStream::connect(addr).await {
                    Ok(s) => break s,
                    Err(e) => {
                        eprintln!("[dial {j}] connection failed: {e}, retrying in 500ms...");
                        sleep(Duration::from_millis(500)).await;
                    }
                }
            };
            stream.write_u16(my_index).await?;
            let (reader, writer) = stream.into_split();
            let (tx, rx) = mpsc::unbounded_channel();
            Ok::<_, std::io::Error>((j, tx, reader, writer, rx, inc_tx))
        }));
    }

    // Drop listener — all expected connections are established
    drop(listener);

    // Collect results
    let mut results = Vec::new();
    for h in accept_handles {
        results.push(h.await.unwrap()?);
    }
    for h in dial_handles {
        results.push(h.await.unwrap()?);
    }

    // Set up peer_tx and spawn read/write tasks
    for (sender, tx, reader, writer, mut rx, inc_tx) in results {
        peer_tx[usize::from(sender)] = Some(tx);

        // Read task: framed reads → deserialize → push to incoming channel
        tokio::spawn(async move {
            let mut framed = FramedRead::new(reader, LengthDelimitedCodec::new());
            let mut next_id: MsgId = 0;
            while let Some(Ok(buf)) = framed.next().await {
                match bincode::deserialize::<WireMsg<M>>(&buf) {
                    Ok(wire) => {
                        let msg_type = match wire.msg_type {
                            WireMsgType::Broadcast { reliable } => {
                                MessageType::Broadcast { reliable }
                            }
                            WireMsgType::P2P => MessageType::P2P,
                        };
                        let _ = inc_tx.send(Ok(Incoming {
                            id: next_id,
                            sender: wire.sender,
                            msg_type,
                            msg: wire.msg,
                        }));
                        next_id += 1;
                    }
                    Err(e) => {
                        let _ = inc_tx
                            .send(Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e)));
                    }
                }
            }
        });

        // Write task: channel receives bytes → framed write to TCP
        tokio::spawn(async move {
            let mut framed = FramedWrite::new(writer, LengthDelimitedCodec::new());
            while let Some(bytes) = rx.recv().await {
                if framed.send(bytes).await.is_err() {
                    break;
                }
            }
        });
    }

    let peer_tx = peer_tx.into_iter().map(|o| o.unwrap()).collect();
    Ok(TcpDelivery::new(my_index, incoming_rx, peer_tx))
}
