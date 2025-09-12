pub mod user;
pub mod redis;

use sqlx::PgPool;

#[derive(Clone)]
pub struct Store {
    pub pool: PgPool,
}

impl Store {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}
