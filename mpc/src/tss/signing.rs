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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpc::create_mpc_signer;
    use crate::tss::types::SolanaNetwork;
    use solana_client::rpc_client::RpcClient;
    use std::time::Instant;

    fn create_test_signing_service() -> TSSSigningService {
        TSSSigningService::new(RpcClient::new("https://api.devnet.solana.com".to_string()))
    }

    #[test]
    fn test_aggregate_nonces() {
        let service = create_test_signing_service();
        let nonces = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let aggregated = service.aggregate_nonces(&nonces);

        // XOR of [1,1,1...], [2,2,2...], [3,3,3...] should be [0,0,0...]
        assert_eq!(aggregated, [0u8; 32]);
    }

    #[test]
    fn test_aggregate_nonces_single() {
        let service = create_test_signing_service();
        let nonces = vec![[42u8; 32]];
        let aggregated = service.aggregate_nonces(&nonces);

        // Single nonce should remain unchanged
        assert_eq!(aggregated, [42u8; 32]);
    }

    #[test]
    fn test_aggregate_nonces_empty() {
        let service = create_test_signing_service();
        let nonces = vec![];
        let aggregated = service.aggregate_nonces(&nonces);

        // Empty nonces should result in zero
        assert_eq!(aggregated, [0u8; 32]);
    }

    #[test]
    fn test_aggregate_nonces_commutativity() {
        let service = create_test_signing_service();
        let nonces1 = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let nonces2 = vec![[3u8; 32], [1u8; 32], [2u8; 32]]; // Different order

        let aggregated1 = service.aggregate_nonces(&nonces1);
        let aggregated2 = service.aggregate_nonces(&nonces2);

        // XOR is commutative, so results should be the same
        assert_eq!(aggregated1, aggregated2);
    }

    #[test]
    fn test_derive_public_key() {
        let service = create_test_signing_service();
        let secret_key = [1u8; 32];
        let public_key = service.derive_public_key(secret_key).unwrap();

        assert_eq!(public_key.to_bytes().len(), 32);
    }

    #[test]
    fn test_derive_public_key_consistency() {
        let service = create_test_signing_service();
        let secret_key = [42u8; 32];

        let public_key1 = service.derive_public_key(secret_key).unwrap();
        let public_key2 = service.derive_public_key(secret_key).unwrap();

        // Same secret key should produce same public key
        assert_eq!(public_key1, public_key2);
    }

    #[test]
    fn test_derive_public_key_different_secrets() {
        let service = create_test_signing_service();
        let secret1 = [1u8; 32];
        let secret2 = [2u8; 32];

        let public_key1 = service.derive_public_key(secret1).unwrap();
        let public_key2 = service.derive_public_key(secret2).unwrap();

        // Different secret keys should produce different public keys
        assert_ne!(public_key1, public_key2);
    }

    #[test]
    fn test_create_mpc_session() {
        let service = create_test_signing_service();
        let participants = vec![
            solana_sdk::pubkey::Pubkey::new_unique(),
            solana_sdk::pubkey::Pubkey::new_unique(),
        ];
        let session =
            service.create_mpc_session("test_session".to_string(), participants.clone(), 2);

        assert_eq!(session.session_id, "test_session");
        assert_eq!(session.threshold, 2);
        assert_eq!(session.participants, participants);
        assert_eq!(
            session.status,
            crate::tss::types::MPCSessionStatus::Initializing
        );
        assert!(!session.is_ready());
    }

    #[test]
    fn test_create_mpc_session_different_thresholds() {
        let service = create_test_signing_service();
        let participants = vec![
            solana_sdk::pubkey::Pubkey::new_unique(),
            solana_sdk::pubkey::Pubkey::new_unique(),
            solana_sdk::pubkey::Pubkey::new_unique(),
        ];

        let session1 = service.create_mpc_session("session1".to_string(), participants.clone(), 1);
        let session2 = service.create_mpc_session("session2".to_string(), participants.clone(), 2);
        let session3 = service.create_mpc_session("session3".to_string(), participants.clone(), 3);

        assert_eq!(session1.threshold, 1);
        assert_eq!(session2.threshold, 2);
        assert_eq!(session3.threshold, 3);

        // All should have same participants but different thresholds
        assert_eq!(session1.participants, participants);
        assert_eq!(session2.participants, participants);
        assert_eq!(session3.participants, participants);
    }

    #[test]
    fn test_enhanced_signature() {
        let service = create_test_signing_service();
        let enhanced_keypair = EnhancedTSSKeypair::new(3);
        let message = b"test message";

        let (ed25519_sig, tss_sig) = service.enhanced_sign(message, &enhanced_keypair).unwrap();

        assert_eq!(ed25519_sig.as_ref().len(), 64);
        assert_eq!(tss_sig.as_ref().len(), 64);

        // Verify the signatures
        let is_valid = service
            .verify_enhanced_signature(message, &ed25519_sig, &tss_sig, &enhanced_keypair)
            .unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_enhanced_signature_different_messages() {
        let service = create_test_signing_service();
        let enhanced_keypair = EnhancedTSSKeypair::new(2);
        let message1 = b"message one";
        let message2 = b"message two";

        let (ed25519_sig1, tss_sig1) = service.enhanced_sign(message1, &enhanced_keypair).unwrap();
        let (ed25519_sig2, tss_sig2) = service.enhanced_sign(message2, &enhanced_keypair).unwrap();

        // Different messages should produce different signatures
        assert_ne!(ed25519_sig1, ed25519_sig2);
        assert_ne!(tss_sig1, tss_sig2);

        // Each signature should only verify for its own message
        assert!(service
            .verify_enhanced_signature(message1, &ed25519_sig1, &tss_sig1, &enhanced_keypair)
            .unwrap());
        assert!(service
            .verify_enhanced_signature(message2, &ed25519_sig2, &tss_sig2, &enhanced_keypair)
            .unwrap());
        assert!(!service
            .verify_enhanced_signature(message1, &ed25519_sig2, &tss_sig2, &enhanced_keypair)
            .unwrap());
        assert!(!service
            .verify_enhanced_signature(message2, &ed25519_sig1, &tss_sig1, &enhanced_keypair)
            .unwrap());
    }

    #[test]
    fn test_enhanced_signature_consistency() {
        let service = create_test_signing_service();
        let enhanced_keypair = EnhancedTSSKeypair::new(3);
        let message = b"consistency test";

        let (ed25519_sig1, tss_sig1) = service.enhanced_sign(message, &enhanced_keypair).unwrap();
        let (ed25519_sig2, tss_sig2) = service.enhanced_sign(message, &enhanced_keypair).unwrap();

        // Same message and keypair should produce same signatures
        assert_eq!(ed25519_sig1, ed25519_sig2);
        assert_eq!(tss_sig1, tss_sig2);
    }

    #[test]
    fn test_aggregate_sign_step_one() {
        let service = create_test_signing_service();
        let secret_key = [42u8; 32];
        let transaction_details = TSSTransactionDetails {
            amount: 0.1,
            to: solana_sdk::pubkey::Pubkey::new_unique(),
            from: solana_sdk::pubkey::Pubkey::new_unique(),
            network: SolanaNetwork::Devnet,
            memo: Some("test".to_string()),
            recent_blockhash: "11111111111111111111111111111111".to_string(),
        };

        let step_one_data = service
            .aggregate_sign_step_one(secret_key, &transaction_details)
            .unwrap();

        assert_eq!(step_one_data.secret_nonce.len(), 32);
        assert_eq!(step_one_data.public_nonce.len(), 32);
        assert_eq!(step_one_data.participant_key.to_bytes().len(), 32);
    }

    #[test]
    fn test_aggregate_sign_step_one_different_secrets() {
        let service = create_test_signing_service();
        let secret1 = [1u8; 32];
        let secret2 = [2u8; 32];
        let transaction_details = TSSTransactionDetails {
            amount: 0.1,
            to: solana_sdk::pubkey::Pubkey::new_unique(),
            from: solana_sdk::pubkey::Pubkey::new_unique(),
            network: SolanaNetwork::Devnet,
            memo: None,
            recent_blockhash: "11111111111111111111111111111111".to_string(),
        };

        let step_one_data1 = service
            .aggregate_sign_step_one(secret1, &transaction_details)
            .unwrap();
        let step_one_data2 = service
            .aggregate_sign_step_one(secret2, &transaction_details)
            .unwrap();

        // Different secrets should produce different participant keys
        assert_ne!(
            step_one_data1.participant_key,
            step_one_data2.participant_key
        );

        // But both should have valid nonces
        assert_eq!(step_one_data1.secret_nonce.len(), 32);
        assert_eq!(step_one_data2.secret_nonce.len(), 32);
        assert_eq!(step_one_data1.public_nonce.len(), 32);
        assert_eq!(step_one_data2.public_nonce.len(), 32);
    }

    #[test]
    fn test_create_partial_signature() {
        let service = create_test_signing_service();
        let message = b"test message";
        let secret_key = [42u8; 32];
        let secret_nonce = [123u8; 32];
        let aggregated_nonce = [200u8; 32];

        let partial_sig = service
            .create_partial_signature(message, secret_key, secret_nonce, aggregated_nonce)
            .unwrap();

        assert_eq!(partial_sig.len(), 64);

        // First 32 bytes should be the secret nonce
        assert_eq!(&partial_sig[..32], &secret_nonce);

        // Last 32 bytes should be the signature
        assert_ne!(&partial_sig[32..], &[0u8; 32]); // Should not be all zeros
    }

    #[test]
    fn test_aggregate_partial_signatures() {
        let service = create_test_signing_service();
        let participant_keys = vec![
            solana_sdk::pubkey::Pubkey::new_unique(),
            solana_sdk::pubkey::Pubkey::new_unique(),
        ];
        let aggregate_wallet = AggregateWallet::new(participant_keys, Some(2));

        let partial_signatures = vec![
            AggSignStepTwoData {
                partial_signature: [1u8; 64],
                public_nonce: [10u8; 32],
                participant_key: aggregate_wallet.participant_keys[0],
            },
            AggSignStepTwoData {
                partial_signature: [2u8; 64],
                public_nonce: [20u8; 32],
                participant_key: aggregate_wallet.participant_keys[1],
            },
        ];

        let complete_sig = service
            .aggregate_partial_signatures(&partial_signatures, &aggregate_wallet)
            .unwrap();

        assert_eq!(complete_sig.signature.len(), 64);
        assert_eq!(
            complete_sig.public_key,
            aggregate_wallet.aggregated_public_key
        );
        assert_eq!(complete_sig.transaction.len(), 0); // Empty in current implementation
    }

    #[test]
    fn test_verify_partial_signature() {
        let service = create_test_signing_service();
        let message = b"test message";

        // Create a valid signature
        let signer = create_mpc_signer();
        let signature = signer.sign(message).unwrap();

        let partial_sig = TSSPartialSignature {
            signer: signer.public_key,
            signature: signature.as_ref().try_into().unwrap(),
            nonce: [42u8; 32],
        };

        // Should verify correctly
        assert!(service.verify_partial_signature(&partial_sig, message));

        // Should not verify for different message
        assert!(!service.verify_partial_signature(&partial_sig, b"different message"));
    }

    #[test]
    fn test_generate_threshold_signature_shares() {
        let service = create_test_signing_service();
        let participants = vec![
            solana_sdk::pubkey::Pubkey::new_unique(),
            solana_sdk::pubkey::Pubkey::new_unique(),
            solana_sdk::pubkey::Pubkey::new_unique(),
        ];
        let tss_config = TSSConfig::new(participants.clone(), 2);
        let message = b"threshold test message";
        let participant_indices = vec![0, 1];

        let shares = service
            .generate_threshold_signature_shares(message, &tss_config, &participant_indices)
            .unwrap();

        assert_eq!(shares.len(), 2);
        for (i, share) in shares.iter().enumerate() {
            assert_eq!(share.participant_index, participant_indices[i]);
            assert_eq!(share.signature.len(), 64);
            assert_eq!(share.public_key, participants[participant_indices[i]]);
        }
    }

    #[test]
    fn test_aggregate_threshold_signature_shares() {
        let service = create_test_signing_service();
        let participants = vec![
            solana_sdk::pubkey::Pubkey::new_unique(),
            solana_sdk::pubkey::Pubkey::new_unique(),
            solana_sdk::pubkey::Pubkey::new_unique(),
        ];
        let tss_config = TSSConfig::new(participants.clone(), 2);
        let message = b"aggregate test message";

        let shares = vec![
            ThresholdSignatureShare {
                participant_index: 0,
                signature: [1u8; 64],
                public_key: participants[0],
            },
            ThresholdSignatureShare {
                participant_index: 1,
                signature: [2u8; 64],
                public_key: participants[1],
            },
        ];

        let aggregated = service
            .aggregate_threshold_signature_shares(&shares, &tss_config, message)
            .unwrap();

        assert_eq!(aggregated.signature.len(), 64);
        assert_eq!(aggregated.master_public_key, tss_config.master_public_key());
        assert_eq!(aggregated.participant_count, 2);
        assert_eq!(aggregated.threshold, 2);
    }

    #[test]
    fn test_insufficient_signatures_error() {
        let service = create_test_signing_service();
        let participants = vec![
            solana_sdk::pubkey::Pubkey::new_unique(),
            solana_sdk::pubkey::Pubkey::new_unique(),
            solana_sdk::pubkey::Pubkey::new_unique(),
        ];
        let tss_config = TSSConfig::new(participants.clone(), 3);
        let message = b"insufficient test";

        // Only provide 1 signature when 3 are required
        let shares = vec![ThresholdSignatureShare {
            participant_index: 0,
            signature: [1u8; 64],
            public_key: participants[0],
        }];

        let result = service.aggregate_threshold_signature_shares(&shares, &tss_config, message);

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::InsufficientSignatures { provided, required } => {
                assert_eq!(provided, 1);
                assert_eq!(required, 3);
            }
            _ => panic!("Expected InsufficientSignatures error"),
        }
    }

    #[test]
    fn test_performance_aggregate_nonces() {
        let service = create_test_signing_service();
        let nonces: Vec<[u8; 32]> = (0..100).map(|i| [i as u8; 32]).collect();

        let start = Instant::now();
        let _aggregated = service.aggregate_nonces(&nonces);
        let duration = start.elapsed();

        println!("Aggregate nonces time for 100 nonces: {:?}", duration);
        assert!(
            duration.as_millis() < 10,
            "Aggregating nonces should be fast"
        );
    }

    #[test]
    fn test_performance_derive_public_key() {
        let service = create_test_signing_service();
        let secret_key = [42u8; 32];

        let start = Instant::now();
        for _ in 0..1000 {
            let _public_key = service.derive_public_key(secret_key).unwrap();
        }
        let duration = start.elapsed();

        let avg_time = duration.as_micros() as f64 / 1000.0;
        println!("Average derive public key time: {:.2}μs", avg_time);
        assert!(avg_time < 200.0, "Deriving public key should be fast");
    }
}
