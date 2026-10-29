use utoipa::{
    Modify, OpenApi,
    openapi::security::{ApiKey, ApiKeyValue, HttpAuthScheme, HttpBuilder, SecurityScheme},
};

use crate::{auth, error, routes};

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Ark API",
        description = "Ark turns a Wi-Fi network into a shared media drive. \
            Unlock a folder (or log in as admin) from this page and the session cookie \
            is sent with later calls automatically. For curl, pass \
            `Authorization: Bearer <session_id>` from the unlock/login response."
    ),
    paths(
        crate::healthz,
        auth::admin::setup,
        auth::admin::login,
        routes::folders::me,
        routes::folders::logout,
        routes::folders::hub_unlock,
        routes::folders::unlock,
        routes::join::join,
        routes::folders::list_folders,
        routes::folders::list_items,
        routes::folders::create_subfolder,
        routes::admin::list_folders,
        routes::admin::create_folder,
        routes::admin::update_folder,
        routes::admin::archive_folder,
        routes::admin::list_pins,
        routes::admin::create_pin,
        routes::admin::update_pin,
        routes::admin::revoke_pin,
        routes::uploads::options,
        routes::uploads::create,
        routes::uploads::head,
        routes::uploads::patch,
        routes::uploads::terminate,
        routes::downloads::download,
        routes::downloads::preview,
        routes::downloads::preview_hls,
        routes::zip::create,
        routes::zip::download,
        routes::items::update,
        routes::items::delete,
        routes::items::restore,
        routes::items::versions,
        routes::events::events,
        routes::join::list_tokens,
        routes::join::create_token,
        routes::join::revoke_token,
        routes::admin_ops::qr_code,
        routes::admin_ops::list_sessions,
        routes::admin_ops::end_session,
        routes::admin_ops::activity,
        routes::admin_ops::storage_report,
        routes::admin_ops::list_trash,
        routes::admin_ops::empty_trash,
        routes::admin_ops::sync_status,
        routes::admin_ops::sync_retry,
        routes::admin_ops::tunnel_status,
        routes::admin_ops::tunnel_enable,
        routes::admin_ops::tunnel_disable,
    ),
    components(schemas(error::ErrorBody, auth::Role)),
    modifiers(&SecuritySchemes),
    tags(
        (name = "auth", description = "Unlock folders, current sessions"),
        (name = "folders", description = "Browse folders and create subfolders"),
        (name = "items", description = "Rename, move, tag, trash, restore"),
        (name = "uploads", description = "tus 1.0 resumable uploads"),
        (name = "downloads", description = "File downloads and previews"),
        (name = "events", description = "Server-sent live updates"),
        (name = "admin", description = "Admin setup, folders, PINs, tokens"),
        (name = "system", description = "Health"),
    )
)]
pub struct ApiDoc;

struct SecuritySchemes;

impl Modify for SecuritySchemes {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "ark_session",
            SecurityScheme::ApiKey(ApiKey::Cookie(ApiKeyValue::with_description(
                "ark_s_*",
                "Signed session cookies (ark_s_admin, ark_s_hub, ark_s_<folder>). \
                 Set by unlock/login; the browser sends them automatically.",
            ))),
        );
        components.add_security_scheme(
            "bearer",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .description(Some("session_id from an unlock or login response"))
                    .build(),
            ),
        );
    }
}
