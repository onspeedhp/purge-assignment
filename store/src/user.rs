use crate::Store;
use chrono::Utc;
use sqlx::Row;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct User {
    pub id: String,
    pub email: String,
    pub created_at: String,
}

#[derive(Debug)]
pub struct CreateUserRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug)]
pub enum UserError {
    UserExists,
    UserNotFound,
    InvalidPassword,
    InvalidInput(String),
    DatabaseError(String),
}

impl std::fmt::Display for UserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserError::UserExists => write!(f, "User already exists"),
            UserError::UserNotFound => write!(f, "User not found"),
            UserError::InvalidPassword => write!(f, "Invalid password"),
            UserError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            UserError::DatabaseError(msg) => write!(f, "Database error: {}", msg),
        }
    }
}

impl std::error::Error for UserError {}

impl Store {
    pub async fn create_user(&self, request: CreateUserRequest) -> Result<User, UserError> {
        info!(
            "Starting user creation process for email: {}",
            request.email
        );

        // Validate email format
        if !request.email.contains('@') {
            return Err(UserError::InvalidInput("Invalid email format".to_string()));
        }

        // Validate password length
        if request.password.len() < 6 {
            return Err(UserError::InvalidInput(
                "Password must be at least 6 characters".to_string(),
            ));
        }

        // Check if user already exists
        let existing_user = sqlx::query("SELECT id FROM users WHERE email = $1")
            .bind(&request.email)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| {
                error!("Database error while checking existing user: {}", e);
                UserError::DatabaseError(e.to_string())
            })?;

        if existing_user.is_some() {
            return Err(UserError::UserExists);
        }

        // Hash the password
        let password_hash = bcrypt::hash(&request.password, bcrypt::DEFAULT_COST).map_err(|e| {
            error!("Password hashing failed: {}", e);
            UserError::DatabaseError(format!("Password hashing failed: {}", e))
        })?;

        // Generate user ID and timestamp
        let user_id = Uuid::new_v4().to_string();
        let created_at = Utc::now();

        // Insert user into database
        sqlx::query(
            "INSERT INTO users (id, email, password_hash, created_at) VALUES ($1, $2, $3, $4)",
        )
        .bind(&user_id)
        .bind(&request.email)
        .bind(&password_hash)
        .bind(&created_at)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            error!("Database error while inserting user: {}", e);
            UserError::DatabaseError(e.to_string())
        })?;

        // Return the created user
        let user = User {
            id: user_id,
            email: request.email,
            created_at: created_at.to_rfc3339(),
        };

        Ok(user)
    }

    pub async fn get_user_by_id(&self, id: &str) -> Result<Option<User>, UserError> {
        let row = sqlx::query("SELECT id, email, created_at FROM users WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| {
                error!("Database error while looking up user: {}", e);
                UserError::DatabaseError(e.to_string())
            })?;

        match row {
            Some(row) => {
                let user = User {
                    id: row.get("id"),
                    email: row.get("email"),
                    created_at: row
                        .get::<chrono::DateTime<chrono::Utc>, _>("created_at")
                        .to_rfc3339(),
                };
                Ok(Some(user))
            }
            None => Ok(None),
        }
    }

    pub async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, UserError> {
        let row =
            sqlx::query("SELECT id, email, password_hash, created_at FROM users WHERE email = $1")
                .bind(email)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| {
                    error!("Database error while looking up user: {}", e);
                    UserError::DatabaseError(e.to_string())
                })?;

        match row {
            Some(row) => {
                let user = User {
                    id: row.get("id"),
                    email: row.get("email"),
                    created_at: row
                        .get::<chrono::DateTime<chrono::Utc>, _>("created_at")
                        .to_rfc3339(),
                };
                Ok(Some(user))
            }
            None => Ok(None),
        }
    }

    pub async fn validate_password(
        &self,
        email: &str,
        password: &str,
    ) -> Result<Option<User>, UserError> {
        let user_option = self.get_user_by_email(email).await?;

        match user_option {
            Some(user) => {
                let row = sqlx::query("SELECT password_hash FROM users WHERE email = $1")
                    .bind(email)
                    .fetch_one(&self.pool)
                    .await
                    .map_err(|e| {
                        error!("Database error while getting password hash: {}", e);
                        UserError::DatabaseError(e.to_string())
                    })?;

                let stored_hash: String = row.get("password_hash");

                let is_valid = bcrypt::verify(password, &stored_hash).map_err(|e| {
                    error!("Password verification failed: {}", e);
                    UserError::DatabaseError(format!("Password verification failed: {}", e))
                })?;

                if is_valid { Ok(Some(user)) } else { Ok(None) }
            }
            None => Ok(None),
        }
    }
}
