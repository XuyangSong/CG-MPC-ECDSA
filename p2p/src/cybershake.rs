//! ```ascii
//! ┌──────────────────────────────────────────────────────────────────────────────────────┐
//! │    _______ __   __ ______  _______  ______ _______ _     _ _______ _     _ _______   │
//! │    |         \_/   |_____] |______ |_____/ |______ |_____| |_____| |____/  |______   │
//! │    |_____     |    |_____] |______ |    \_ ______| |     | |     | |    \_ |______   │
//! │                                                                                      │
//! └──────────────────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # C Y B E R S H A K E
//!
//! Yet Another Handshake Protocol for p2p sessions.
//!
//! You start with a local private key, remote public key (optional),
//! and a pair of `AsyncRead` and `AsyncWrite` interfaces.
//!
//! The protocol performs mutual authentication and, if it succeeded,
//! returns a pair of wrappers around these interfaces,
//! that keep track of the encryption keys.
//!
//! ## Features
//!
//! * **Symmetric and low-latency.** Handshake is performed by both ends simultaneously.
//! * **Mutual-authentication.** Each party receives other's long-term public key by the end of handshake.
//! * **Key blinding.** Long-term identity keys are never transmitted in the clear.
//! * **Foward secrecy.** Keys are rotated on each sent message.
//! * **Robust encryption.** cipher AES-SIV-PMAC-128 provides high speed and resistance to nonce-misuse.
//!
//! ## TODO
//!
//! * Add custom header to be sent in the first encrypted frame:
//!   users can put the protocol version there, certificate info etc.

use byteorder::{ByteOrder, LittleEndian};
use core::marker::Unpin;
use miscreant::{generic_array::GenericArray, Aes128PmacSiv};
use rand_core::{CryptoRng, RngCore};

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
// use curve25519_dalek::traits::VartimeMultiscalarMul;
use merlin::Transcript; // TODO: change for raw Strobe.

use tokio::io;
use tokio::prelude::*;

use futures::task::{Context, Poll};
use std::pin::Pin;

/// The current version of the protocol is 0.
/// In the future we may add more versions, version bits or whatever.
const ONLY_SUPPORTED_VERSION: u64 = 0;
const PT_BUF_SIZE: usize = 4096;
const CT_LEN_SIZE: usize = 2; // 16-bit length prefix for ciphertext chunks
const CT_TAG_SIZE: usize = 16; // 128-bit auth tag
const CT_SIZE: usize = CT_TAG_SIZE + PT_BUF_SIZE;
const PT_OFFSET: usize = CT_LEN_SIZE + CT_TAG_SIZE; // offset of the plaintext in the outgoing buffer

/// Private key for encrypting and authenticating connection.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct PrivateKey {
    secret: Scalar,
    pubkey: PublicKey,
}

/// Public key for authenticating connection.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct PublicKey {
    point: CompressedRistretto,
}

/// An endpoint for sending messages to remote party.
/// All messages are ordered and encryption key is ratcheted after each sent message.
pub struct Outgoing<W: io::AsyncWrite + Unpin> {
    writer: Pin<Box<W>>,
    seq: u64,
    kdf: Transcript,
    buf: Vec<u8>,
    flushing: bool,
    ciphertext_sent: usize,
}

/// An endpoint for receiving messages from a remote party.
/// All messages are ordered and encryption key is ratcheted after each received message.
/// Recipient's incoming.seq corresponds to the sender's outgoing.seq.
pub struct Incoming<R: io::AsyncRead + Unpin> {
    reader: Pin<Box<R>>,
    seq: u64,
    kdf: Transcript,
    buf: Vec<u8>,
    state: ReadState,
}

enum ReadState {
    Len(usize),
    ReadCt(usize, usize),
    ReadPt(usize, usize),
}

/// Performs the key exchange with a remote end using byte-oriented read- and write- interfaces
/// (e.g. TcpSocket halves).
/// Returns the identity key of the remote peer, along with read- and write- interfaces
/// that perform encryption and authentication behind the scenes.
/// If you need to verify the identity per local policy or certificates, use the returned public key.
pub async fn cybershake<R, W, RNG>(
    local_identity: &PrivateKey,
    mut reader: Pin<Box<R>>,
    mut writer: Pin<Box<W>>,
    mut rng: RNG,
) -> Result<(PublicKey, Outgoing<W>, Incoming<R>), io::Error>
where
    R: io::AsyncRead + Unpin,
    W: io::AsyncWrite + Unpin,
    RNG: RngCore + CryptoRng,
{
    // We are going to need an additional ephemeral D-H key,
    // and a salt for blinding the reusable identity key.

    let mut keygen_rng = Transcript::new(b"Cybershake.randomness")
        .build_rng()
        .rekey_with_witness_bytes(b"local_privkey", local_identity.as_secret_bytes())
        .finalize(&mut rng);

    const SALT_LEN: usize = 16;
    let mut local_salt = [0u8; SALT_LEN];
    keygen_rng.fill_bytes(&mut local_salt[..]);
    let local_blinded_identity = local_identity.blind(&local_salt[..]);

    // Now we send our first, unencrypted, message:
    //
    // [version] [blinded local identity pubkey] [local ephemeral pubkey]
    // u64-le     32 bytes                        32 bytes
    writer
        .write(&encode_u64le(ONLY_SUPPORTED_VERSION)[..])
        .await?;
    writer
        .write(local_blinded_identity.pubkey.as_bytes())
        .await?;
    writer.flush().await?;

    // Receive the similar message from the other end (that was sent simultaneously).
    let mut remote_version_buf = [0u8; 8];
    reader.read_exact(&mut remote_version_buf[..]).await?;
    let remote_version = LittleEndian::read_u64(&remote_version_buf);
    if remote_version != ONLY_SUPPORTED_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Incompatible cybershake version",
        ));
    }
    let remote_blinded_identity = PublicKey::read_from(&mut reader).await?;

    // Now, perform a triple Diffie-Hellman shared key generation.
    let t = cybershake_dh(&local_blinded_identity, &remote_blinded_identity)?;

    // We will have two independent derivations of the shared key:
    // one for the outgoing messages, and another one for incoming messages.
    let mut kdf_outgoing = t.clone();
    let mut kdf_incoming = t;
    kdf_outgoing.append_message(b"src", local_blinded_identity.pubkey.as_bytes());
    kdf_incoming.append_message(b"src", remote_blinded_identity.as_bytes());

    // Now we prepare endpoints for reading and writing messages,
    // but don't give them to the user until we authenticate the connection.
    let mut out_buf = Vec::with_capacity(CT_SIZE as usize + CT_LEN_SIZE);
    out_buf.extend_from_slice(&[0; PT_OFFSET]);
    let mut outgoing = Outgoing {
        writer,
        seq: 0,
        kdf: kdf_outgoing,
        buf: out_buf,
        flushing: false,
        ciphertext_sent: 0,
    };
    let mut incoming = Incoming {
        reader,
        seq: 0,
        kdf: kdf_incoming,
        buf: vec![0u8; CT_SIZE as usize], // TODO: allow user redefine this parameter
        state: ReadState::Len(0),
    };

    // In order to authenticate the session, we send our first encrypted message
    // in which we show the salt and the root pubkey.
    // If the transmission was successful (authenticated decryption succeeded),
    // we check the blinded key and then let user continue using the session.

    // Prepare and send the message: salt and local identity pubkey.
    outgoing.write_all(&local_salt[..]).await?;
    outgoing.write_all(local_identity.pubkey.as_bytes()).await?;
    outgoing.flush().await?;

    // Receive the message from another end: their salt and their identity pubkey.
    let mut remote_salt_and_id = [0u8; SALT_LEN + 32];
    incoming.read_exact(&mut remote_salt_and_id).await?;
    let received_remote_identity =
        PublicKey::read_from(&mut &remote_salt_and_id[SALT_LEN..]).await?;

    // Blinded key is also a secure commitment to the underlying key.
    // Here we check that the remote party has sent us the correct identity key
    // matching the blinded key they used for X3DH.
    let received_remote_id_blinded = received_remote_identity
        .blind(&remote_salt_and_id[0..SALT_LEN])
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Failed to decode Ristretto point",
            )
        })?;

    if received_remote_id_blinded != remote_blinded_identity {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Remote identity key mismatch",
        ));
    }

    Ok((received_remote_identity, outgoing, incoming))
}

macro_rules! ready {
    ($($tokens:tt)*) => {
        match $($tokens)* {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Ok(n)) => { n }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
        }
    };
}

impl<W: AsyncWrite + Unpin> Outgoing<W> {
    fn cipher_buf(&mut self) {
        self.kdf.append_u64(b"seq", self.seq);
        let mut key = [0u8; 32];
        self.kdf.challenge_bytes(b"key", &mut key);

        let ad = encode_u64le(self.seq);

        let tag = Aes128PmacSiv::new(GenericArray::clone_from_slice(&key))
            .encrypt_in_place_detached(&[&ad], &mut self.buf[PT_OFFSET..])
            .expect("never fails because we have just one header");

        let ct_len = (self.buf.len() - 2) as u16;
        LittleEndian::write_u16(&mut self.buf[..2], ct_len);
        self.buf.as_mut_slice()[CT_LEN_SIZE..PT_OFFSET].copy_from_slice(tag.as_slice());

        self.seq += 1;
        self.flushing = true;
    }

    fn flush_pending_ciphertext(&mut self, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        if !self.flushing {
            return Poll::Ready(Ok(()));
        }
        while self.ciphertext_sent < self.buf.len() {
            let poll = self
                .writer
                .as_mut()
                .poll_write(cx, &self.buf[self.ciphertext_sent..]);
            let n = ready!(poll);
            self.ciphertext_sent += n;
        }
        ready!(self.writer.as_mut().poll_flush(cx));
        self.ciphertext_sent = 0;
        self.flushing = false;
        self.buf.truncate(PT_OFFSET);
        Poll::Ready(Ok(()))
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for Outgoing<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let me = self.get_mut();

        ready!(me.flush_pending_ciphertext(cx));

        if me.buf.len() + buf.len() >= PT_BUF_SIZE + CT_LEN_SIZE {
            // plaintext_buf has BUF_SIZE size, so subtract with overflow will be never.
            let size_to_write = PT_BUF_SIZE + CT_LEN_SIZE - me.buf.len();
            me.buf.extend_from_slice(&buf[..size_to_write]);
            me.cipher_buf();
            ready!(me.flush_pending_ciphertext(cx));
            Poll::Ready(Ok(size_to_write))
        } else {
            me.buf.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let me = self.get_mut();
        if !me.flushing {
            if me.buf.is_empty() {
                return Poll::Ready(Ok(()));
            }
            me.cipher_buf();
        }
        me.flush_pending_ciphertext(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let me = self.get_mut();
        if !me.flushing {
            me.cipher_buf();
        }
        ready!(me.flush_pending_ciphertext(cx));
        me.writer.as_mut().poll_shutdown(cx)
    }
}

impl<W: AsyncWrite + Unpin> Outgoing<W> {
    /// Send a message of any length.
    /// This is a temporary. We'll replace this with Tokio Codecs.
    pub async fn send_message(&mut self, msg: &[u8]) -> Result<(), io::Error> {
        self.write_all(&msg).await?;
        self.flush().await?;
        Ok(())
    }
}

impl<R: AsyncRead + Unpin> Incoming<R> {
    fn decipher_buf(&mut self, ciphertext_length: usize) -> Result<usize, io::Error> {
        let seq = self.seq;
        self.seq += 1;

        self.kdf.append_u64(b"seq", seq);
        let mut key = [0u8; 32];
        self.kdf.challenge_bytes(b"key", &mut key);

        let ad = encode_u64le(seq);

        let siv_tag = GenericArray::clone_from_slice(&self.buf[..16]);
        Aes128PmacSiv::new(GenericArray::clone_from_slice(&key))
            .decrypt_in_place_detached(&[&ad], &mut self.buf[16..ciphertext_length], &siv_tag)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "An error was occured when try to decipher data.",
                )
            })?;

        let pt_len = ciphertext_length - 16;

        Ok(pt_len)
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for Incoming<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, io::Error>> {
        let me = self.get_mut();

        loop {
            match me.state {
                ReadState::Len(mut already_read) => {
                    let poll = me
                        .reader
                        .as_mut()
                        .poll_read(cx, &mut me.buf[already_read..2]);
                    let n = ready!(poll);
                    if n == 0 {
                        return Poll::Ready(Ok(0));
                    }
                    already_read += n;
                    me.state = ReadState::Len(already_read);
                    if already_read == 2 {
                        let length = LittleEndian::read_u16(&me.buf[..2]) as usize;
                        if length < 16 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("length prefix: {} < 16", length),
                            )));
                        }
                        me.buf.resize(length, 0);
                        me.state = ReadState::ReadCt(length, 0);
                    }
                }
                ReadState::ReadCt(len, mut already_read) => {
                    let poll = me
                        .reader
                        .as_mut()
                        .poll_read(cx, &mut me.buf[already_read..len]);
                    let n = ready!(poll);
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WouldBlock,
                            format!("Expected length {}, but found {}.", len, already_read),
                        )));
                    }
                    already_read += n;
                    if already_read == len {
                        match me.decipher_buf(len) {
                            Ok(pt_len) => me.state = ReadState::ReadPt(pt_len, 0),
                            Err(e) => return Poll::Ready(Err(e)),
                        }
                    } else {
                        me.state = ReadState::ReadCt(len, already_read);
                    }
                }
                ReadState::ReadPt(pt_len, already_read) => {
                    let read_now = usize::min(buf.len(), pt_len - already_read);
                    buf[..read_now]
                        .copy_from_slice(&me.buf[CT_TAG_SIZE + already_read..][..read_now]);
                    me.state = ReadState::ReadPt(pt_len, already_read + read_now);
                    if already_read + read_now == pt_len {
                        me.state = ReadState::Len(0);
                    }
                    return Poll::Ready(Ok(read_now));
                }
            }
        }
    }
}

fn cybershake_dh(id1: &PrivateKey, id2: &PublicKey) -> Result<Transcript, io::Error> {
    let mut t = Transcript::new(b"Cybershake.DH");
    let keep_order = id1.pubkey.as_bytes() < id2.as_bytes();
    {
        let (id1, id2) = if keep_order {
            (&id1.pubkey, id2)
        } else {
            (id2, &id1.pubkey)
        };
        t.append_message(b"id1", id1.as_bytes());
        t.append_message(b"id2", id2.as_bytes());
    }

    let id2_point = id2.as_point().decompress().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Failed to decode pubkey of a remote party (invalid ristretto255 format)",
        )
    })?;

    let shared_secret = id1.as_scalar() * id2_point;
    t.append_message(b"dh", shared_secret.compress().as_bytes());

    Ok(t)
}

impl From<Scalar> for PrivateKey {
    fn from(secret: Scalar) -> Self {
        PrivateKey {
            secret,
            pubkey: PublicKey::from(secret * RISTRETTO_BASEPOINT_POINT),
        }
    }
}

impl From<CompressedRistretto> for PublicKey {
    fn from(point: CompressedRistretto) -> Self {
        PublicKey { point }
    }
}

impl From<RistrettoPoint> for PublicKey {
    fn from(point: RistrettoPoint) -> Self {
        PublicKey::from(point.compress())
    }
}

impl PrivateKey {
    /// Converts the private key to an underlying Ristretto scalar.
    pub fn as_scalar(&self) -> &Scalar {
        &self.secret
    }

    /// Converts the private key to its binary encoding.
    pub fn as_secret_bytes(&self) -> &[u8] {
        &self.secret.as_bytes()[..]
    }

    /// Converts the private key to its public counterpart.
    pub fn to_public_key(&self) -> PublicKey {
        self.pubkey
    }

    /// Blinds the private key.
    fn blind(&self, salt: &[u8]) -> Self {
        PrivateKey::from(self.secret + keyblinding_factor(&self.pubkey.point, salt))
    }
}

impl PublicKey {
    /// Converts the public key to an underlying compressed Ristretto point.
    pub fn as_point(&self) -> &CompressedRistretto {
        &self.point
    }

    /// Converts the public key to its binary encoding.
    pub fn as_bytes(&self) -> &[u8] {
        &self.point.as_bytes()[..]
    }

    /// Blinds the public key.
    fn blind(&self, salt: &[u8]) -> Option<Self> {
        self.point.decompress().map(|p| {
            PublicKey::from(p + keyblinding_factor(&self.point, salt) * RISTRETTO_BASEPOINT_POINT)
        })
    }

    /// Reads pubkey from a reader.
    async fn read_from<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self, io::Error> {
        let mut buf = [0u8; 32];
        reader.read_exact(&mut buf[..]).await?;
        Ok(Self::from(CompressedRistretto(buf)))
    }
}

fn keyblinding_factor(pubkey: &CompressedRistretto, salt: &[u8]) -> Scalar {
    let mut t = Transcript::new(b"Cybershake.keyblinding");
    t.append_message(b"key", pubkey.as_bytes());
    t.append_message(b"salt", &salt[..]);
    challenge_scalar(b"factor", &mut t)
}

fn challenge_scalar(label: &'static [u8], transcript: &mut Transcript) -> Scalar {
    let mut buf = [0u8; 64];
    transcript.challenge_bytes(label, &mut buf);
    Scalar::from_bytes_mod_order_wide(&buf)
}

fn encode_u64le(i: u64) -> [u8; 8] {
    let mut buf = [0u8; 8];
    LittleEndian::write_u64(&mut buf, i);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn light_message_poll_function() {
        let alice_private_key = PrivateKey::from(Scalar::from(1u8));
        let bob_private_key = PrivateKey::from(Scalar::from(2u8));

        let mut alice_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut bob_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let alice_addr = alice_listener.local_addr().unwrap();
        let bob_addr = bob_listener.local_addr().unwrap();

        let alice = tokio::spawn(async move {
            let (alice_reader, _) = alice_listener.accept().await.unwrap();
            let alice_writer = TcpStream::connect(bob_addr).await.unwrap();
            let (received_key, mut alice_out, mut alice_inc) = cybershake(
                &alice_private_key,
                Box::pin(alice_reader),
                Box::pin(alice_writer),
                StdRng::from_entropy(),
            )
            .await
            .unwrap();

            assert_eq!(received_key, bob_private_key.to_public_key());

            // Alice send message to bob
            let alice_message: Vec<u8> = "Hello, Bob".bytes().collect();
            alice_out.write(&alice_message).await.unwrap();
            alice_out.shutdown().await.unwrap();

            // Then Alice receive message from bob
            let mut buf = vec![0u8; 4096];
            let message_len = alice_inc.read(&mut buf).await.unwrap();
            buf.truncate(message_len);
            assert_eq!("Hello, Alice", String::from_utf8(buf).unwrap());
        });

        let bob = tokio::spawn(async move {
            let bob_writer = TcpStream::connect(alice_addr).await.unwrap();
            let (bob_reader, _) = bob_listener.accept().await.unwrap();
            let (received_key, mut bob_out, mut bob_inc) = cybershake(
                &bob_private_key,
                Box::pin(bob_reader),
                Box::pin(bob_writer),
                StdRng::from_entropy(),
            )
            .await
            .unwrap();

            assert_eq!(received_key, alice_private_key.to_public_key());

            // Bob receive message from Alice
            let mut buf = vec![0u8; 4096];
            let message_len = bob_inc.read(&mut buf).await.unwrap();
            buf.truncate(message_len);
            assert_eq!("Hello, Bob", String::from_utf8(buf).unwrap());

            // Then bob send message to Alice
            let bob_message: Vec<u8> = "Hello, Alice".bytes().collect();
            bob_out.write(&bob_message).await.unwrap();
            bob_out.flush().await.unwrap();
        });

        assert!(alice.await.is_ok());
        assert!(bob.await.is_ok());
    }

    #[tokio::test]
    async fn large_message() {
        let alice_private_key = PrivateKey::from(Scalar::from(1u64));
        let bob_private_key = PrivateKey::from(Scalar::from(2u64));

        let mut alice_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut bob_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let alice_addr = alice_listener.local_addr().unwrap();
        let bob_addr = bob_listener.local_addr().unwrap();

        let alice = tokio::spawn(async move {
            let (alice_reader, _) = alice_listener
                .accept()
                .await
                .expect("alice: listener.accept");
            let alice_writer = TcpStream::connect(bob_addr)
                .await
                .expect("alice: connect to bob");
            let (_, mut alice_out, _) = cybershake(
                &alice_private_key,
                Box::pin(alice_reader),
                Box::pin(alice_writer),
                StdRng::from_entropy(),
            )
            .await
            .expect("alice: should handshake correctly");

            // Alice send message to bob
            let alice_message: Vec<u8> = vec![10u8; 6000];
            alice_out.send_message(&alice_message).await.unwrap();
        });

        let bob = tokio::spawn(async move {
            let bob_writer = TcpStream::connect(alice_addr)
                .await
                .expect("bob: connect to alice");
            let (bob_reader, _) = bob_listener.accept().await.expect("bob: listener.accept");
            let (_, _, mut bob_inc) = cybershake(
                &bob_private_key,
                Box::pin(bob_reader),
                Box::pin(bob_writer),
                StdRng::from_entropy(),
            )
            .await
            .expect("bob: should handshake correctly");

            // Bob receive message from Alice
            let mut len = 0;
            let mut buf = vec![0; 4096];
            loop {
                let read = bob_inc
                    .read(&mut buf)
                    .await
                    .expect("bob should receive msg");
                len += read;
                if read == 0 {
                    break;
                }
            }
            assert_eq!(len, 6000);
        });

        assert!(alice.await.is_ok());
        assert!(bob.await.is_ok());
    }
}
