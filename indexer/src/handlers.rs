use actix_web::{web, HttpResponse, Result as ActixResult};
use std::sync::Arc;

use crate::database::AssetDatabase;
use crate::models::{SubscribeRequest, UnsubscribeRequest};
use crate::subscription::SubscriptionService;

pub struct IndexerHandlers {
    database: Arc<AssetDatabase>,
    subscription_service: Arc<SubscriptionService>,
}

impl IndexerHandlers {
    pub fn new(database: Arc<AssetDatabase>, subscription_service: Arc<SubscriptionService>) -> Self {
        Self {
            database,
            subscription_service,
        }
    }

    pub async fn subscribe_to_account(
        &self,
        req: web::Json<SubscribeRequest>,
    ) -> ActixResult<HttpResponse> {
        let wallet_address = &req.wallet_address;
        let user_id = &req.user_id;

        if let Err(e) = self.database.ensure_user_exists(user_id).await {
            tracing::error!("Failed to ensure user exists: {:?}", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to create user"
            })));
        }

        if let Err(e) = self.database.subscribe_to_account(user_id, wallet_address).await {
            tracing::error!("Failed to subscribe to account: {:?}", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to subscribe to account"
            })));
        }

        // Get the subscription from database
        let subscriptions = self.database.get_active_subscriptions().await
            .map_err(|e| {
                tracing::error!("Failed to get subscriptions: {:?}", e);
                actix_web::error::ErrorInternalServerError("Database error")
            })?;

        if let Some(subscription) = subscriptions.iter()
            .find(|s| s.user_id == *user_id && s.wallet_address == *wallet_address) {
            
            // Start gRPC subscription
            if let Err(e) = self.subscription_service.start_subscription(subscription.clone()).await {
                tracing::error!("Failed to start gRPC subscription: {:?}", e);
                return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to start gRPC subscription"
                })));
            }
        }

        Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "Successfully subscribed to account",
            "wallet_address": wallet_address
        })))
    }

    pub async fn unsubscribe_from_account(
        &self,
        req: web::Json<UnsubscribeRequest>,
    ) -> ActixResult<HttpResponse> {
        let wallet_address = &req.wallet_address;
        let user_id = &req.user_id;

        if let Err(e) = self.database.unsubscribe_from_account(&user_id, wallet_address).await {
            tracing::error!("Failed to unsubscribe from account: {:?}", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to unsubscribe from account"
            })));
        }

        Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "Successfully unsubscribed from account",
            "wallet_address": wallet_address
        })))
    }
}
