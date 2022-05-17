use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
// Todo : make it independent of DBMS
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Row};
use std::fmt;
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: Uuid,
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    pub orgs: Option<Vec<Org>>,
    #[serde(skip_serializing)]
    pub hashword: String,
    #[serde(skip_serializing)]
    pub salt: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "enum_org_role", rename_all = "snake_case")]
pub enum UserOrgRole {
    Admin,
    Owner,
}

#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct RegistrationReq {
    pub first_name: String,
    pub last_name: String,
    #[validate(email)]
    pub email: String,
    pub organization: Option<String>,
    #[validate(length(min = 8), must_match = "password_confirm")]
    pub password: String,
    pub password_confirm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct UserSummary {
    pub id: Uuid,
    pub first_name: String,
    pub last_name: String,
    pub email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct UserLoginRequest {
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 8))]
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRefreshRequest {
    pub refresh: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct PasswordResetRequest {
    #[validate(email)]
    pub email: String,
}

#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct PwdResetInfo {
    pub token: String,
    #[validate(length(min = 8), must_match = "password_confirm")]
    pub password: String,
    pub password_confirm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Org {
    pub id: Uuid,
    pub name: String,
    pub is_personal: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_role: Option<UserOrgRole>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl fmt::Display for UserOrgRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Admin => write!(f, "admin"),
            Self::Owner => write!(f, "owner"),
        }
    }
}

impl From<PgRow> for User {
    fn from(row: PgRow) -> Self {
        User {
            id: row.try_get("id").expect("Couldn't try_get id for user."),
            first_name: row
                .try_get("first_name")
                .expect("Couldn't try_get first_name for user."),
            last_name: row
                .try_get("last_name")
                .expect("Couldn't try_get last_name for user."),
            email: row
                .try_get("email")
                .expect("Couldn't try_get email for user."),
            hashword: row
                .try_get("hashword")
                .expect("Couldn't try_get hashword for user."),
            salt: row
                .try_get("salt")
                .expect("Couldn't try_get salt for user."),
            token: row
                .try_get("token")
                .expect("Couldn't try_get token for user."),
            refresh: row
                .try_get("refresh")
                .expect("Couldn't try_get refresh for user."),
            orgs: None,
            created_at: row
                .try_get("created_at")
                .expect("Couldn't try_get created_at for user."),
            updated_at: row
                .try_get("updated_at")
                .expect("Couldn't try_get updated_at for user."),
        }
    }
}
