use super::types::{
    Org, PasswordResetRequest, PwdResetInfo, RegistrationReq, User, UserLoginRequest, UserOrgRole,
    UserRefreshRequest, UserSummary,
};
use crate::errors::Error;
use crate::request;
use crate::response::Result;
use anyhow::anyhow;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use sendgrid::v3::{Content, Email, Message, Personalization, Sender};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;
use validator::Validate;

impl User {
    pub async fn create_user(req: RegistrationReq, db_pool: &PgPool) -> Result<Self> {
        let _ = req
            .validate()
            .map_err(|e| Error::ValidationError(e.to_string()));

        let argon2 = Argon2::default();
        let salt = SaltString::generate(&mut OsRng);
        if let Some(hashword) = argon2
            .hash_password(req.password.as_bytes(), salt.as_str())
            .map_err(|_| anyhow!("Hashing error"))?
            .hash
        {
            let mut tx = db_pool.begin().await?;
            let result = sqlx::query(
                r#"
                INSERT INTO
                users (email, hashword, salt,first_name,last_name)
                values
                (
                    Lower($1), $2, $3, $4, $5
                )
                   RETURNING *
                "#,
            )
            .bind(req.email)
            .bind(hashword.to_string())
            .bind(salt.as_str())
            .bind(req.first_name)
            .bind(req.last_name)
            .fetch_one(&mut tx)
            .await
            .map(Self::from)
            .map_err(Error::from);

            let mut user = result.unwrap();
            let organization = req.organization.unwrap();
            let org = Org::find_by_name(&organization, &mut tx).await?;

            Org::create_orgs_users_owner(org.id, user.id, &mut tx).await?;

            user.orgs = Some(Org::find_all_by_user(user.id, &mut tx).await?);

            tx.commit().await?;
            Ok(user)
        } else {
            Err(Error::ValidationError("Invalid password.".to_string()))
        }
    }

    pub async fn login(user_login_req: UserLoginRequest, db_pool: &PgPool) -> Result<User> {
        let user = User::find_by_email(&user_login_req.email, db_pool)
            .await?
            .set_jwt()
            .map_err(|_e| {
                Error::InvalidAuthentication(anyhow!("Email or password is invalid."))
            })?;
        let _ = user.verify_password(&user_login_req.password)?;
        Ok(user)
    }

    pub async fn find_by_email(email: &str, db_pool: &PgPool) -> Result<User> {
        let mut tx = db_pool.begin().await?;
        let user = sqlx::query(
            r#"SELECT *
                    FROM   users
                    WHERE  Lower(email) = Lower($1)
                    LIMIT  1
                    "#,
        )
        .bind(email)
        .fetch_one(&mut tx)
        .await
        .map(Self::from)
        .map_err(Error::from);
        let mut user = user.unwrap();
        user.orgs = Some(Org::find_all_by_user(user.id, &mut tx).await?);
        tx.commit().await?;
        user.set_jwt()
    }

    pub async fn find_summary_by_user(user_id: &Uuid, db_pool: &PgPool) -> Result<UserSummary> {
        let user = sqlx::query_as::<_, UserSummary>(
            r#"
            SELECT 
                users.id, 
                email
            FROM
                users
            WHERE
                users.id = $1
            "#,
        )
        .bind(user_id)
        .fetch_one(db_pool)
        .await?;

        Ok(user)
    }

    pub async fn find_by_id(id: Uuid, pool: &PgPool) -> Result<User> {
        let user = sqlx::query(r#"SELECT * FROM users WHERE id = $1 limit 1"#)
            .bind(id)
            .fetch_one(pool)
            .await
            .map(Self::from)
            .map_err(Error::from);
        Ok(user.unwrap())
    }

    pub async fn refresh(req: UserRefreshRequest, pool: &PgPool) -> Result<User> {
        let user = User::find_by_refresh(&req.refresh, pool)
            .await?
            .set_jwt()
            .map_err(Error::from)?;
        Ok(user)
    }
    pub async fn find_by_refresh(refresh: &str, pool: &PgPool) -> Result<User> {
        let user = sqlx::query(r#"SELECT * FROM users WHERE refresh = $1 limit 1"#)
            .bind(refresh)
            .fetch_one(pool)
            .await
            .map(Self::from)
            .map_err(Error::from);
        Ok(user.unwrap())
    }

    pub async fn email_reset_password(req: PasswordResetRequest, db_pool: &PgPool) -> Result<()> {
        let user = User::find_by_email(&req.email, db_pool).await?;

        let auth_data = request::UserAuthData {
            user_id: user.id,
            user_role: user.first_name.to_string(),
        };

        let token = request::create_temp_jwt(&auth_data)?;

        let p = Personalization::new(Email::new(&user.email));

        let subject = "Reset Password".to_string();
        let body = format!(
            r##"
            <h1>Password Reset</h1>
            <p>You have requested to reset your BlockJoy password.
            Please visit <a href="https://console.blockjoy.com/reset?t={token}">
            https://console.blockjoy.com/reset?t={token}</a>.</p><br /><br /><p>Thank You!</p>"##
        );
        let sendgrid_api_key = dotenv::var("SENDGRID_API_KEY").map_err(|_| {
            Error::UnexpectedError(anyhow!("Could not find SENDGRID_API_KEY in env."))
        })?;
        let sender = Sender::new(sendgrid_api_key);
        let m = Message::new(Email::new("BlockJoy <hello@blockjoy.com>"))
            .set_subject(&subject)
            .add_content(Content::new().set_content_type("text/html").set_value(body))
            .add_personalization(p);

        sender
            .send(&m)
            .await
            .map_err(|_| Error::UnexpectedError(anyhow!("Could not send email")))?;

        Ok(())
    }

    pub async fn reset_password(req: &PwdResetInfo, db_pool: &PgPool) -> Result<User> {
        let _ = req
            .validate()
            .map_err(|e| Error::ValidationError(e.to_string()))?;

        match request::validate_jwt(&req.token)? {
            request::JwtValidationStatus::Valid(auth_data) => {
                let user = User::find_by_id(auth_data.user_id, db_pool).await?;
                return User::update_password(user, &req.password, db_pool).await;
            }
            _ => Err(Error::InsufficientPermissionsError),
        }
    }

    pub async fn update_password(user: User, password: &str, pool: &PgPool) -> Result<Self> {
        let argon2 = Argon2::default();
        let salt = SaltString::generate(&mut OsRng);
        if let Some(hashword) = argon2
            .hash_password(password.as_bytes(), salt.as_str())
            .map_err(|_| anyhow!("Hashing error"))?
            .hash
        {
            return sqlx::query(
                r#"
                UPDATE
                users
                SET
                hashword = $1,
                salt = $2
                WHERE
                  id = $3 RETURNING *, '' as orgs
                "#,
            )
            .bind(hashword.to_string())
            .bind(salt.as_str())
            .bind(user.id)
            .map(Self::from)
            .fetch_one(pool)
            .await
            .map_err(Error::from)
            .unwrap()
            .set_jwt();
        }

        Err(Error::ValidationError("Invalid password.".to_string()))
    }
    pub fn verify_password(&self, password: &str) -> Result<()> {
        let argon2 = Argon2::default();
        let parsed_hash = argon2
            .hash_password(password.as_bytes(), &self.salt)
            .map_err(|_| anyhow!("Hashing error"))?;

        if let Some(output) = parsed_hash.hash {
            if self.hashword == output.to_string() {
                return Ok(());
            }
        }
        Err(Error::InvalidAuthentication(anyhow!(
            "Invalid email or password."
        )))
    }

    pub fn set_jwt(&mut self) -> Result<Self> {
        let auth_data = request::UserAuthData {
            user_id: self.id,
            user_role: self.first_name.to_string(),
        };
        self.token = Some(request::create_jwt(&auth_data)?);
        Ok(self.to_owned())
    }
}

impl Org {
    pub async fn find_by_name(name: &str, tx: &mut PgConnection) -> Result<Org> {
        sqlx::query_as::<_, Self>(
            "SELECT o.id, o.name, o.is_personal,o.created_at, o.updated_at , ou.role FROM orgs o inner join orgs_users ou on o.id = ou.orgs_id WHERE o.name = $1 order by created_at DESC",
        )
            .bind(name)
            .fetch_one(tx)
            .await
            .map_err(Error::from)
    }

    pub async fn find_all_by_user(user_id: Uuid, tx: &mut PgConnection) -> Result<Vec<Self>> {
        sqlx::query_as::<_, Self>(
            "SELECT o.id, o.name, o.is_personal,o.created_at, o.updated_at , ou.role FROM orgs o inner join orgs_users ou on o.id = ou.orgs_id WHERE users_id = $1 order by created_at DESC",
        )
            .bind(user_id)
            .fetch_all(tx)
            .await
            .map_err(Error::from)
    }

    pub async fn create_orgs_users_owner(
        org_id: Uuid,
        user_id: Uuid,
        tx: &mut PgConnection,
    ) -> Result<()> {
        let _result = sqlx::query(
            r#"
            INSERT INTO
            orgs_users (orgs_id, users_id, role)
            values
            (
                $1, $2, $3
            )
            "#,
        )
        .bind(org_id)
        .bind(user_id)
        .bind(UserOrgRole::Owner)
        .execute(tx)
        .await
        .map_err(Error::from);

        Ok(())
    }
}
