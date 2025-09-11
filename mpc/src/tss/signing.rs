use ed25519_dalek::{Signer as Ed25519Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{pubkey::Pubkey, signature::Signature};

use crate::{
    error::Error,
    mpc::{create_mpc_signer_from_secret_key, TSSSigner},
    solana::transaction::create_transaction_from_details,
    tss::types::{
        AggSignStepOneData, AggSignStepTwoData, AggregateWallet, AggregatedThresholdSignature,
        CompleteSignature, EnhancedTSSKeypair, MPCSession, PartialSignature as TSSPartialSignature,
        TSSConfig, TSSTransactionDetails, ThresholdSignatureShare,
    },
};

/// TSS Signing implementation for multi-party signature aggregation
/// Equivalent to TSSSigningService class in TypeScript
pub struct TSSSigningService {
    rpc_client: RpcClient,
}

impl TSSSigningService {
    /// Create a new TSS signing service
    /// Equivalent to new TSSSigningService(connection) in TypeScript
    pub fn new(rpc_client: RpcClient) -> Self {
        Self { rpc_client }
    }

    /// Create a new TSS signing service from a reference
    pub fn new_with_ref(rpc_client: &RpcClient) -> Self {
        Self {
            rpc_client: RpcClient::new(rpc_client.url().to_string()),
        }
    }

    /// Send a transaction using a single private key (non-TSS)
    /// Equivalent to: solana-tss send-single
    pub async fn send_single(
        &self,
        from_secret_key: [u8; 32],
        to: Pubkey,
        amount: f64,
        memo: Option<String>,
    ) -> Result<String, Error> {
        // Create MPC signer from the provided secret key (like TypeScript)
        let mpc_signer = create_mpc_signer_from_secret_key(from_secret_key)?;

        let tx = create_transaction_from_details(
            &self.rpc_client,
            &TSSTransactionDetails {
                amount,
                to,
                from: mpc_signer.public_key,
                network: crate::tss::types::SolanaNetwork::Devnet,
                memo,
                recent_blockhash: self
                    .rpc_client
                    .get_latest_blockhash()
                    .map_err(Error::RecentHashFailed)?
                    .to_string(),
            },
        )
        .await?;

        let message = tx.message.serialize();
        let signature = mpc_signer.sign(&message)?;

        let mut signed_tx = tx;
        signed_tx.signatures.push(signature);

        let tx_id = self
            .rpc_client
            .send_and_confirm_transaction(&signed_tx)
            .map_err(Error::SendTransactionFailed)?;

        Ok(tx_id.to_string())
    }

    /// Step 1 of aggregate signing: Generate nonce and commitment
    /// Equivalent to: solana-tss agg-send-step-one
    pub fn aggregate_sign_step_one(
        &self,
        participant_secret_key: [u8; 32],
        _transaction_details: &TSSTransactionDetails,
    ) -> Result<AggSignStepOneData, Error> {
        // Generate random nonce for this signing session (like TypeScript nacl.randomBytes(32))
        let mut secret_nonce = [0u8; 32];
        OsRng.fill_bytes(&mut secret_nonce);

        // Create public nonce commitment (like TypeScript nacl.hash(secretNonce).slice(0, 32))
        let mut hasher = Sha256::new();
        hasher.update(&secret_nonce);
        let hash_result = hasher.finalize();
        let mut public_nonce = [0u8; 32];
        public_nonce.copy_from_slice(&hash_result[..32]);

        // Derive participant's public key (like TypeScript this.derivePublicKey(participantSecretKey))
        let participant_key = self.derive_public_key(participant_secret_key)?;

        Ok(AggSignStepOneData {
            secret_nonce,
            public_nonce,
            participant_key,
        })
    }

    /// Step 2 of aggregate signing: Create partial signature
    /// Equivalent to: solana-tss agg-send-step-two
    pub async fn aggregate_sign_step_two(
        &self,
        step_one_data: &AggSignStepOneData,
        participant_secret_key: [u8; 32],
        transaction_details: &TSSTransactionDetails,
        all_public_nonces: &[[u8; 32]],
    ) -> Result<AggSignStepTwoData, Error> {
        // Create the transaction to sign (like TypeScript this.createTransactionFromDetails(transactionDetails))
        let tx = create_transaction_from_details(&self.rpc_client, transaction_details).await?;
        let message_to_sign = tx.message.serialize();

        // Aggregate all nonces (like TypeScript this.aggregateNonces(allPublicNonces))
        let aggregated_nonce = self.aggregate_nonces(all_public_nonces);

        // Create partial signature using the secret key and nonce (like TypeScript this.createPartialSignature(...))
        let partial_signature = self.create_partial_signature(
            &message_to_sign,
            participant_secret_key,
            step_one_data.secret_nonce,
            aggregated_nonce,
        )?;

        Ok(AggSignStepTwoData {
            partial_signature,
            public_nonce: step_one_data.public_nonce,
            participant_key: step_one_data.participant_key,
        })
    }

    /// Aggregate all partial signatures and broadcast transaction
    /// Equivalent to: solana-tss aggregate-signatures-and-broadcast
    pub async fn aggregate_signatures_and_broadcast(
        &self,
        partial_signatures: &[AggSignStepTwoData],
        transaction_details: &TSSTransactionDetails,
        aggregate_wallet: &AggregateWallet,
    ) -> Result<String, Error> {
        // Verify we have enough signatures
        if partial_signatures.len() < aggregate_wallet.threshold {
            return Err(Error::InsufficientSignatures {
                provided: partial_signatures.len(),
                required: aggregate_wallet.threshold,
            });
        }

        // Create the transaction
        let mut tx = create_transaction_from_details(&self.rpc_client, transaction_details).await?;

        // Aggregate the partial signatures into a complete signature
        let complete_signature =
            self.aggregate_partial_signatures(partial_signatures, aggregate_wallet)?;

        // Add the aggregated signature to the transaction
        tx.signatures
            .push(Signature::from(complete_signature.signature));

        // Broadcast the transaction
        let tx_id = self
            .rpc_client
            .send_and_confirm_transaction(&tx)
            .map_err(Error::SendTransactionFailed)?;

        Ok(tx_id.to_string())
    }

    /// Create a transaction from transaction details
    /// Equivalent to createTransactionFromDetails() in TypeScript
    async fn create_transaction_from_details(
        &self,
        details: &TSSTransactionDetails,
    ) -> Result<solana_sdk::transaction::Transaction, Error> {
        create_transaction_from_details(&self.rpc_client, details).await
    }

    /// Derive public key from secret key
    /// Equivalent to derivePublicKey() in TypeScript
    fn derive_public_key(&self, secret_key: [u8; 32]) -> Result<Pubkey, Error> {
        let signing_key = SigningKey::from_bytes(&secret_key);
        let verifying_key = signing_key.verifying_key();
        Ok(Pubkey::new_from_array(verifying_key.to_bytes()))
    }

    /// Aggregate nonces for TSS signing
    /// Equivalent to aggregateNonces() in TypeScript
    fn aggregate_nonces(&self, nonces: &[[u8; 32]]) -> [u8; 32] {
        let mut aggregated = [0u8; 32];
        for nonce in nonces {
            for i in 0..32 {
                aggregated[i] ^= nonce[i];
            }
        }
        aggregated
    }

    /// Create a partial signature for TSS
    /// Equivalent to createPartialSignature() in TypeScript
    fn create_partial_signature(
        &self,
        message: &[u8],
        secret_key: [u8; 32],
        secret_nonce: [u8; 32],
        _aggregated_nonce: [u8; 32],
    ) -> Result<[u8; 64], Error> {
        // Simplified partial signature creation (like TypeScript)
        // In production, this would use proper TSS signature schemes like FROST or similar

        // Ensure we have a valid 32-byte seed for key generation (like TypeScript)
        let signing_key = SigningKey::from_bytes(&secret_key);
        let signature = signing_key.sign(message);

        // For TSS, we need to incorporate the nonce into the signature
        // This is a simplified implementation matching the TypeScript logic
        let mut partial_sig = [0u8; 64];
        partial_sig[..32].copy_from_slice(&secret_nonce);
        partial_sig[32..].copy_from_slice(&signature.to_bytes()[..32]);

        Ok(partial_sig)
    }

    /// Aggregate partial signatures into a complete signature
    /// Equivalent to aggregatePartialSignatures() in TypeScript
    fn aggregate_partial_signatures(
        &self,
        partial_signatures: &[AggSignStepTwoData],
        aggregate_wallet: &AggregateWallet,
    ) -> Result<CompleteSignature, Error> {
        // Simplified signature aggregation - XOR all partial signatures
        let mut aggregated_sig = [0u8; 64];

        for partial in partial_signatures {
            for i in 0..64 {
                aggregated_sig[i] ^= partial.partial_signature[i];
            }
        }

        Ok(CompleteSignature {
            signature: aggregated_sig,
            public_key: aggregate_wallet.aggregated_public_key,
            transaction: vec![], // Would contain serialized transaction
        })
    }

    /// Verify a partial signature
    /// Equivalent to verifyPartialSignature() in TypeScript
    pub fn verify_partial_signature(
        &self,
        signature: &TSSPartialSignature,
        message: &[u8],
    ) -> bool {
        match VerifyingKey::from_bytes(&signature.signer.to_bytes()) {
            Ok(verifying_key) => {
                let ed25519_signature = ed25519_dalek::Signature::from_bytes(&signature.signature);
                verifying_key
                    .verify_strict(message, &ed25519_signature)
                    .is_ok()
            }
            Err(_) => false,
        }
    }

    /// Create a new MPC session for threshold signing
    pub fn create_mpc_session(
        &self,
        session_id: String,
        participants: Vec<solana_sdk::pubkey::Pubkey>,
        threshold: usize,
    ) -> MPCSession {
        MPCSession::new(session_id, participants, threshold)
    }

    /// Generate threshold signature shares for a message
    pub fn generate_threshold_signature_shares(
        &self,
        message: &[u8],
        tss_config: &TSSConfig,
        participant_indices: &[usize],
    ) -> Result<Vec<ThresholdSignatureShare>, Error> {
        let mut shares = Vec::new();

        for &index in participant_indices {
            if index < tss_config.participants.len() {
                let participant_key = tss_config.participants[index];

                // Create a simple signature for demonstration
                // In production, this would use proper threshold signature shares
                let mut rng = OsRng;
                let mut secret_bytes = [0u8; 32];
                rng.fill_bytes(&mut secret_bytes);
                let signing_key = SigningKey::from_bytes(&secret_bytes);
                let signature = signing_key.sign(message);

                shares.push(ThresholdSignatureShare {
                    participant_index: index,
                    signature: signature.to_bytes(),
                    public_key: participant_key,
                });
            }
        }

        Ok(shares)
    }

    /// Aggregate threshold signature shares into a complete signature
    pub fn aggregate_threshold_signature_shares(
        &self,
        shares: &[ThresholdSignatureShare],
        tss_config: &TSSConfig,
        _message: &[u8],
    ) -> Result<AggregatedThresholdSignature, Error> {
        if shares.len() < tss_config.threshold {
            return Err(Error::InsufficientSignatures {
                provided: shares.len(),
                required: tss_config.threshold,
            });
        }

        let master_public_key = tss_config.master_public_key();

        // Simple signature aggregation - XOR all signatures
        let mut aggregated_signature = [0u8; 64];
        for share in shares {
            for i in 0..64 {
                aggregated_signature[i] ^= share.signature[i];
            }
        }

        Ok(AggregatedThresholdSignature {
            signature: aggregated_signature,
            master_public_key,
            participant_count: shares.len(),
            threshold: tss_config.threshold,
        })
    }

    /// Enhanced signing with multiple key types
    pub fn enhanced_sign(
        &self,
        message: &[u8],
        enhanced_keypair: &EnhancedTSSKeypair,
    ) -> Result<
        (
            solana_sdk::signature::Signature,
            solana_sdk::signature::Signature,
        ),
        Error,
    > {
        // Sign with Ed25519 using the enhanced keypair's secret key
        let ed25519_signer =
            TSSSigner::from_secret_key(enhanced_keypair.secret_key, enhanced_keypair.threshold)?;
        let ed25519_signature = ed25519_signer.sign(message)?;

        // Sign with TSS using the same keypair
        let tss_signer =
            TSSSigner::from_secret_key(enhanced_keypair.secret_key, enhanced_keypair.threshold)?;
        let tss_signature = tss_signer.sign(message)?;

        Ok((ed25519_signature, tss_signature))
    }

    /// Verify enhanced signature
    pub fn verify_enhanced_signature(
        &self,
        message: &[u8],
        ed25519_signature: &solana_sdk::signature::Signature,
        tss_signature: &solana_sdk::signature::Signature,
        enhanced_keypair: &EnhancedTSSKeypair,
    ) -> Result<bool, Error> {
        // Verify Ed25519 signature using the enhanced keypair
        let ed25519_signer =
            TSSSigner::from_secret_key(enhanced_keypair.secret_key, enhanced_keypair.threshold)?;
        let ed25519_valid = ed25519_signer.verify(message, ed25519_signature);

        // Verify TSS signature using the same keypair
        let tss_signer =
            TSSSigner::from_secret_key(enhanced_keypair.secret_key, enhanced_keypair.threshold)?;
        let tss_valid = tss_signer.verify(message, tss_signature);

        Ok(ed25519_valid && tss_valid)
    }
}

