//! HTTP-level tests: scope rules, role checks over real routes, path traversal.

use std::path::PathBuf;

use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::{AppState, app, build_state, config::Config};

struct TestApp {
    app: Router,
    state: AppState,
    dir: PathBuf,
}

struct Resp {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    body: Vec<u8>,
}

impl Resp {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    fn header(&self, name: &str) -> Option<String> {
        self.headers
            .get(name)
            .map(|v| v.to_str().unwrap().to_string())
    }
}

/// A session id goes in as a bearer token; a `name=value` cookie pair (from a join
/// link's Set-Cookie) goes in as a cookie.
fn auth_header(sid: &str) -> (header::HeaderName, String) {
    if sid.contains('=') {
        (header::COOKIE, sid.to_string())
    } else {
        (header::AUTHORIZATION, format!("Bearer {sid}"))
    }
}

impl Drop for TestApp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl TestApp {
    async fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("ark-it-{}", crate::util::new_id()));
        let state = build_state(Config::for_tests(dir.clone())).await.unwrap();
        Self {
            app: app(state.clone()),
            state,
            dir,
        }
    }

    async fn send(&self, req: Request<Body>) -> Resp {
        let resp = self.app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        Resp {
            status,
            headers,
            body,
        }
    }

    async fn call(
        &self,
        method: Method,
        uri: &str,
        sid: Option<&str>,
        body: Option<Value>,
    ) -> Resp {
        let mut req = Request::builder().method(method).uri(uri);
        if let Some(sid) = sid {
            let (name, value) = auth_header(sid);
            req = req.header(name, value);
        }
        let req = match body {
            Some(b) => req
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(b.to_string())),
            None => req.body(Body::empty()),
        };
        self.send(req.unwrap()).await
    }

    async fn get(&self, uri: &str, sid: &str) -> Resp {
        self.call(Method::GET, uri, Some(sid), None).await
    }

    async fn post(&self, uri: &str, sid: Option<&str>, body: Value) -> Resp {
        self.call(Method::POST, uri, sid, Some(body)).await
    }

    async fn admin(&self) -> String {
        let code = self.state.setup.code.lock().unwrap().clone().unwrap();
        let r = self
            .post(
                "/api/v1/admin/setup",
                None,
                json!({"setup_code": code, "password": "correct horse"}),
            )
            .await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.text());
        r.json()["session_id"].as_str().unwrap().to_string()
    }

    async fn folder(&self, admin: &str, name: &str) -> String {
        let r = self
            .post("/api/v1/admin/folders", Some(admin), json!({"name": name}))
            .await;
        assert_eq!(r.status, StatusCode::CREATED, "{}", r.text());
        r.json()["id"].as_str().unwrap().to_string()
    }

    async fn subfolder(&self, sid: &str, slug: &str, path: &str, name: &str) -> String {
        let r = self
            .post(
                &format!("/api/v1/folders/{slug}/subfolders"),
                Some(sid),
                json!({"path": path, "name": name}),
            )
            .await;
        assert_eq!(r.status, StatusCode::CREATED, "{}", r.text());
        r.json()["id"].as_str().unwrap().to_string()
    }

    async fn pin(&self, admin: &str, folder_id: Option<&str>, pin: &str, role: &str) {
        let r = self
            .post(
                "/api/v1/admin/pins",
                Some(admin),
                json!({"folder_id": folder_id, "label": format!("{role} {pin}"), "pin": pin, "role": role}),
            )
            .await;
        assert_eq!(r.status, StatusCode::CREATED, "{}", r.text());
    }

    async fn unlock_resp(&self, slug: &str, path: &str, pin: &str) -> Resp {
        self.post(
            &format!("/api/v1/folders/{slug}/unlock"),
            None,
            json!({"pin": pin, "path": path}),
        )
        .await
    }

    async fn unlock(&self, slug: &str, path: &str, pin: &str) -> String {
        let r = self.unlock_resp(slug, path, pin).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.text());
        r.json()["session_id"].as_str().unwrap().to_string()
    }

    /// Unlocks as a browser holding `cookies` would, and returns its cookie pair.
    async fn unlock_cookie(
        &self,
        cookies: Option<&str>,
        slug: &str,
        path: &str,
        pin: &str,
    ) -> String {
        let r = self
            .post(
                &format!("/api/v1/folders/{slug}/unlock"),
                cookies,
                json!({"pin": pin, "path": path}),
            )
            .await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.text());
        r.header("set-cookie")
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string()
    }

    /// Single-request tus upload. Returns the final PATCH response.
    async fn upload(&self, sid: &str, slug: &str, path: &str, filename: &str, data: &[u8]) -> Resp {
        let meta = format!(
            "filename {},folder {},path {}",
            STANDARD.encode(filename),
            STANDARD.encode(slug),
            STANDARD.encode(path)
        );
        let create = Request::post("/api/v1/uploads")
            .header(auth_header(sid).0, auth_header(sid).1)
            .header("tus-resumable", "1.0.0")
            .header("upload-length", data.len())
            .header("upload-metadata", meta)
            .body(Body::empty())
            .unwrap();
        let r = self.send(create).await;
        if r.status != StatusCode::CREATED {
            return r;
        }
        let location = r.header("location").unwrap();
        let patch = Request::patch(location)
            .header(auth_header(sid).0, auth_header(sid).1)
            .header("tus-resumable", "1.0.0")
            .header("upload-offset", 0)
            .header(header::CONTENT_TYPE, "application/offset+octet-stream")
            .body(Body::from(data.to_vec()))
            .unwrap();
        self.send(patch).await
    }

    async fn items(&self, sid: &str, slug: &str, path: &str) -> Resp {
        self.get(&format!("/api/v1/folders/{slug}/items?path={path}"), sid)
            .await
    }
}

/// sunday-service/{day-1/{photos}, day-2} and youth-camp, with:
/// 1111 editor on sunday-service, 2222 viewer on day-1, 3333 uploader on day-2.
async fn fixture() -> (TestApp, String) {
    let t = TestApp::new().await;
    let admin = t.admin().await;
    let sunday = t.folder(&admin, "Sunday Service").await;
    t.folder(&admin, "Youth Camp").await;
    let day1 = t.subfolder(&admin, "sunday-service", "", "Day 1").await;
    let day2 = t.subfolder(&admin, "sunday-service", "", "Day 2").await;
    t.subfolder(&admin, "sunday-service", "day-1", "Photos")
        .await;
    t.pin(&admin, Some(&sunday), "1111", "editor").await;
    t.pin(&admin, Some(&day1), "2222", "viewer").await;
    t.pin(&admin, Some(&day2), "3333", "uploader").await;
    (t, admin)
}

#[tokio::test]
async fn subfolder_session_stays_inside_its_subtree() {
    let (t, _) = fixture().await;
    let viewer = t.unlock("sunday-service", "day-1", "2222").await;

    assert_eq!(
        t.items(&viewer, "sunday-service", "day-1").await.status,
        StatusCode::OK
    );
    assert_eq!(
        t.items(&viewer, "sunday-service", "day-1/photos")
            .await
            .status,
        StatusCode::OK
    );
    for (slug, path) in [
        ("sunday-service", ""),
        ("sunday-service", "day-2"),
        ("youth-camp", ""),
    ] {
        let r = t.items(&viewer, slug, path).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{slug}/{path}");
        let body = r.text().to_lowercase();
        assert!(
            !body.contains("sunday") && !body.contains("youth") && !body.contains("day"),
            "{body}"
        );
    }
}

#[tokio::test]
async fn listing_shows_only_children() {
    let (t, _) = fixture().await;
    let viewer = t.unlock("sunday-service", "day-1", "2222").await;
    let r = t.items(&viewer, "sunday-service", "day-1").await.json();
    let subs: Vec<&str> = r["subfolders"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["slug"].as_str().unwrap())
        .collect();
    assert_eq!(subs, ["photos"]);
}

#[tokio::test]
async fn subfolder_pins_never_open_the_parent() {
    let (t, _) = fixture().await;
    // day-1's own PIN does not unlock its parent, and the parent's PIN does not
    // unlock day-1, which has PINs of its own.
    assert_eq!(
        t.unlock_resp("sunday-service", "", "2222").await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        t.unlock_resp("sunday-service", "day-1", "1111")
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn inherited_pin_scopes_to_the_unlocked_subfolder() {
    let (t, admin) = fixture().await;
    t.subfolder(&admin, "sunday-service", "", "Extra").await;
    // "extra" has no PINs, so sunday-service's editor PIN applies, scoped to extra.
    let sid = t.unlock("sunday-service", "extra", "1111").await;
    assert_eq!(
        t.items(&sid, "sunday-service", "extra").await.status,
        StatusCode::OK
    );
    assert_eq!(
        t.items(&sid, "sunday-service", "").await.status,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn ancestor_session_reaches_descendants() {
    let (t, _) = fixture().await;
    let editor = t.unlock("sunday-service", "", "1111").await;
    assert_eq!(
        t.items(&editor, "sunday-service", "day-1/photos")
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        t.items(&editor, "youth-camp", "").await.status,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn role_matrix_over_http() {
    let (t, admin) = fixture().await;
    let sunday_id = t.items(&admin, "sunday-service", "").await.json()["folder"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    t.pin(&admin, Some(&sunday_id), "4444", "contributor").await;
    let editor = t.unlock("sunday-service", "", "1111").await;
    let contributor = t.unlock("sunday-service", "", "4444").await;
    let viewer = t.unlock("sunday-service", "day-1", "2222").await;
    let uploader = t.unlock("sunday-service", "day-2", "3333").await;

    // Upload
    assert_eq!(
        t.upload(&viewer, "sunday-service", "day-1", "v.txt", b"v")
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    let up = t
        .upload(&uploader, "sunday-service", "day-2", "mine.txt", b"mine")
        .await;
    assert_eq!(up.status, StatusCode::NO_CONTENT);
    let mine = up.header("ark-file-id").unwrap();
    let theirs = t
        .upload(&editor, "sunday-service", "day-2", "theirs.txt", b"theirs")
        .await
        .header("ark-file-id")
        .unwrap();

    // Uploader: own files only, no downloads.
    let names: Vec<String> = t.items(&uploader, "sunday-service", "day-2").await.json()["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["name"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(names, ["mine.txt"]);
    assert_eq!(
        t.get(&format!("/dl/{mine}"), &uploader).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        t.get(&format!("/dl/{theirs}"), &editor).await.text(),
        "theirs"
    );

    // Subfolders
    let subfolders = "/api/v1/folders/sunday-service/subfolders";
    let r = t
        .post(subfolders, Some(&viewer), json!({"name": "by viewer"}))
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let r = t
        .post(
            subfolders,
            Some(&contributor),
            json!({"name": "by contributor"}),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED);

    // Modify / trash
    let item = format!("/api/v1/items/{theirs}");
    let tag = json!({"status_tag": "final"});
    assert_eq!(
        t.call(Method::PATCH, &item, Some(&contributor), Some(tag.clone()))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        t.call(Method::PATCH, &item, Some(&editor), Some(tag))
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        t.call(Method::DELETE, &item, Some(&contributor), None)
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        t.call(Method::DELETE, &item, Some(&editor), None)
            .await
            .status,
        StatusCode::NO_CONTENT
    );

    // Hub list and admin API
    assert_eq!(
        t.get("/api/v1/folders", &editor).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        t.get("/api/v1/admin/folders", &editor).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        t.get("/api/v1/folders/sunday-service/items", "not-a-session")
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn hub_session_lists_and_reaches_all_folders() {
    let (t, admin) = fixture().await;
    t.pin(&admin, None, "9090", "hub").await;
    let r = t
        .post("/api/v1/hub/unlock", None, json!({"pin": "9090"}))
        .await;
    let hub = r.json()["session_id"].as_str().unwrap().to_string();
    assert_eq!(
        t.get("/api/v1/folders", &hub)
            .await
            .json()
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(t.items(&hub, "youth-camp", "").await.status, StatusCode::OK);
    assert_eq!(
        t.get("/api/v1/admin/pins", &hub).await.status,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn revoked_pin_ends_its_sessions() {
    let (t, admin) = fixture().await;
    let viewer = t.unlock("sunday-service", "day-1", "2222").await;
    let pins = t.get("/api/v1/admin/pins", &admin).await.json();
    let id = pins
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["role"] == "viewer")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    t.call(
        Method::DELETE,
        &format!("/api/v1/admin/pins/{id}"),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(
        t.items(&viewer, "sunday-service", "day-1").await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn sixth_wrong_pin_locks_even_the_right_one() {
    let (t, _) = fixture().await;
    for _ in 0..5 {
        assert_eq!(
            t.unlock_resp("sunday-service", "", "0000").await.status,
            StatusCode::UNAUTHORIZED
        );
    }
    let r = t.unlock_resp("sunday-service", "", "1111").await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(r.header("retry-after").is_some());
}

#[tokio::test]
async fn join_token_respects_max_uses() {
    let (t, admin) = fixture().await;
    let folders = t.get("/api/v1/admin/folders", &admin).await.json();
    let sunday = folders
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["slug"] == "sunday-service")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let r = t
        .post(
            "/api/v1/admin/tokens",
            Some(&admin),
            json!({"folder_id": sunday, "role": "uploader", "label": "poster", "max_uses": 1}),
        )
        .await;
    let secret = r.json()["secret"].as_str().unwrap().to_string();
    assert!(
        r.json()["url"]
            .as_str()
            .unwrap()
            .starts_with("http://ark.local")
    );

    let first = t
        .call(Method::GET, &format!("/j/{secret}"), None, None)
        .await;
    assert_eq!(first.status, StatusCode::FOUND);
    assert_eq!(
        first.header("location").as_deref(),
        Some("/f/sunday-service")
    );
    assert!(first.header("set-cookie").unwrap().contains("HttpOnly"));
    assert_eq!(
        t.call(Method::GET, &format!("/j/{secret}"), None, None)
            .await
            .status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn contributor_join_link_views_downloads_and_uploads_in_the_subtree() {
    let (t, admin) = fixture().await;
    let editor = t.unlock("sunday-service", "", "1111").await;
    let theirs = t
        .upload(
            &editor,
            "sunday-service",
            "day-1/photos",
            "a.jpg",
            b"theirs",
        )
        .await
        .header("ark-file-id")
        .unwrap();
    let folders = t.get("/api/v1/admin/folders", &admin).await.json();
    let sunday = folders
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["slug"] == "sunday-service")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let r = t
        .post(
            "/api/v1/admin/tokens",
            Some(&admin),
            json!({"folder_id": sunday, "role": "contributor", "label": "guests"}),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.text());
    let secret = r.json()["secret"].as_str().unwrap().to_string();
    let joined = t
        .call(Method::GET, &format!("/j/{secret}"), None, None)
        .await;
    assert_eq!(joined.status, StatusCode::FOUND);
    let set_cookie = joined.header("set-cookie").unwrap();
    let cookie = set_cookie.split(';').next().unwrap();

    // Everything below the link's folder: list and download others' files, upload.
    let items = t.items(cookie, "sunday-service", "day-1/photos").await;
    assert_eq!(items.status, StatusCode::OK);
    assert_eq!(items.json()["files"].as_array().unwrap().len(), 1);
    assert_eq!(
        t.get(&format!("/dl/{theirs}"), cookie).await.text(),
        "theirs"
    );
    let up = t
        .upload(cookie, "sunday-service", "day-2", "mine.jpg", b"mine")
        .await;
    assert_eq!(up.status, StatusCode::NO_CONTENT, "{}", up.text());
    // But nothing outside it.
    assert_eq!(
        t.items(cookie, "youth-camp", "").await.status,
        StatusCode::FORBIDDEN
    );

    let r = t
        .post(
            "/api/v1/admin/tokens",
            Some(&admin),
            json!({"folder_id": sunday, "role": "editor", "label": "nope"}),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn guest_views_downloads_and_uploads_but_changes_nothing() {
    let (t, admin) = fixture().await;
    let editor = t.unlock("sunday-service", "", "1111").await;
    let theirs = t
        .upload(
            &editor,
            "sunday-service",
            "day-1/photos",
            "a.jpg",
            b"theirs",
        )
        .await
        .header("ark-file-id")
        .unwrap();
    let folders = t.get("/api/v1/admin/folders", &admin).await.json();
    let youth = folders
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["slug"] == "youth-camp")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    t.pin(&admin, Some(&youth), "5555", "guest").await;
    let sunday = t.items(&admin, "sunday-service", "").await.json()["folder"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let r = t
        .post(
            "/api/v1/admin/tokens",
            Some(&admin),
            json!({"folder_id": sunday, "role": "guest", "label": "guests"}),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.text());
    let secret = r.json()["secret"].as_str().unwrap().to_string();
    let joined = t
        .call(Method::GET, &format!("/j/{secret}"), None, None)
        .await;
    let guest = joined
        .header("set-cookie")
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();

    // Sees and downloads everyone's files, in subfolders too, and uploads.
    let items = t.items(&guest, "sunday-service", "day-1/photos").await;
    assert_eq!(items.json()["files"].as_array().unwrap().len(), 1);
    assert_eq!(
        t.get(&format!("/dl/{theirs}"), &guest).await.text(),
        "theirs"
    );
    let up = t
        .upload(&guest, "sunday-service", "day-1/photos", "b.jpg", b"mine")
        .await;
    assert_eq!(up.status, StatusCode::NO_CONTENT);
    let mine = up.header("ark-file-id").unwrap();

    // No subfolders, no rename, no delete, not even of its own upload.
    let r = t
        .post(
            "/api/v1/folders/sunday-service/subfolders",
            Some(&guest),
            json!({"name": "by guest"}),
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    for id in [&theirs, &mine] {
        let item = format!("/api/v1/items/{id}");
        let rename = json!({"name": "renamed.jpg"});
        assert_eq!(
            t.call(Method::PATCH, &item, Some(&guest), Some(rename))
                .await
                .status,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            t.call(Method::DELETE, &item, Some(&guest), None)
                .await
                .status,
            StatusCode::FORBIDDEN
        );
    }

    // A guest PIN works the same way.
    let pin_guest = t.unlock("youth-camp", "", "5555").await;
    let up = t.upload(&pin_guest, "youth-camp", "", "c.jpg", b"c").await;
    assert_eq!(up.status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn admin_can_look_up_pins_and_links_again() {
    let (t, admin) = fixture().await;
    let pins = t.get("/api/v1/admin/pins", &admin).await.json();
    let mut digits: Vec<&str> = pins
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["pin"].as_str().unwrap())
        .collect();
    digits.sort();
    assert_eq!(digits, ["1111", "2222", "3333"]);
    assert!(
        !t.get("/api/v1/admin/pins", &admin)
            .await
            .text()
            .contains("sealed")
    );

    let sunday = t.items(&admin, "sunday-service", "").await.json()["folder"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let created = t
        .post(
            "/api/v1/admin/tokens",
            Some(&admin),
            json!({"folder_id": sunday, "role": "viewer", "label": "poster"}),
        )
        .await
        .json();
    let listed = t.get("/api/v1/admin/tokens", &admin).await.json();
    let url = listed[0]["url"].as_str().unwrap();
    assert_eq!(url, created["url"].as_str().unwrap());
    assert!(url.ends_with(created["secret"].as_str().unwrap()));
    let path = &url[url.find("/j/").unwrap()..];
    assert_eq!(
        t.call(Method::GET, path, None, None).await.status,
        StatusCode::FOUND
    );

    // Revoked ones are no longer shown, even with include_revoked.
    let id = created["id"].as_str().unwrap();
    t.call(
        Method::DELETE,
        &format!("/api/v1/admin/tokens/{id}"),
        Some(&admin),
        None,
    )
    .await;
    let listed = t
        .get("/api/v1/admin/tokens?include_revoked=true", &admin)
        .await
        .json();
    assert!(listed[0]["url"].is_null());
    let pin_id = pins[0]["id"].as_str().unwrap();
    t.call(
        Method::DELETE,
        &format!("/api/v1/admin/pins/{pin_id}"),
        Some(&admin),
        None,
    )
    .await;
    let pins = t
        .get("/api/v1/admin/pins?include_revoked=true", &admin)
        .await
        .json();
    let revoked = pins
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["id"] == pin_id)
        .unwrap();
    assert!(revoked["pin"].is_null());
}

#[tokio::test]
async fn pin_alone_opens_its_folder_from_the_home_page() {
    let (t, admin) = fixture().await;
    let r = t.post("/api/v1/unlock", None, json!({"pin": "2222"})).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let body = r.json();
    assert_eq!(
        (&body["role"], &body["folder_slug"], &body["path"]),
        (&json!("viewer"), &json!("sunday-service"), &json!("day-1"))
    );
    let sid = body["session_id"].as_str().unwrap();
    assert!(r.header("set-cookie").is_some());
    // Scoped to the PIN's own folder, exactly like unlocking it on its page.
    assert_eq!(
        t.items(sid, "sunday-service", "day-1/photos").await.status,
        StatusCode::OK
    );
    assert_eq!(
        t.items(sid, "sunday-service", "").await.status,
        StatusCode::FORBIDDEN
    );

    // The hub PIN works here too.
    t.pin(&admin, None, "9090", "hub").await;
    let r = t.post("/api/v1/unlock", None, json!({"pin": "9090"})).await;
    assert_eq!(r.json()["role"], "hub");
    assert!(r.json()["folder_slug"].is_null());

    // PINs of archived folders open nothing.
    let folders = t.get("/api/v1/admin/folders", &admin).await.json();
    let youth = folders
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["slug"] == "youth-camp")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    t.pin(&admin, Some(&youth), "5555", "guest").await;
    assert_eq!(
        t.post("/api/v1/unlock", None, json!({"pin": "5555"}))
            .await
            .status,
        StatusCode::OK
    );
    t.call(
        Method::DELETE,
        &format!("/api/v1/admin/folders/{youth}"),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(
        t.post("/api/v1/unlock", None, json!({"pin": "5555"}))
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn pin_digits_are_unique_across_ark() {
    let (t, admin) = fixture().await;
    let folders = t.get("/api/v1/admin/folders", &admin).await.json();
    let youth = folders
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["slug"] == "youth-camp")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    for (folder, role) in [(Some(youth.as_str()), "guest"), (None, "hub")] {
        let r = t
            .post(
                "/api/v1/admin/pins",
                Some(&admin),
                json!({"folder_id": folder, "label": "dup", "pin": "2222", "role": role}),
            )
            .await;
        assert_eq!(r.status, StatusCode::CONFLICT, "{role}");
        assert_eq!(r.json()["error"], "pin_in_use");
    }

    // Duplicates from before the rule (no encrypted copy, so argon2 is checked) make
    // the home-page unlock ambiguous; the folder page still works.
    t.pin(&admin, Some(&youth), "7777", "guest").await;
    sqlx::query(
        "UPDATE pins SET pin_hash = (SELECT pin_hash FROM pins WHERE label = 'viewer 2222'),
                         pin_sealed = NULL
         WHERE label = 'guest 7777'",
    )
    .execute(&t.state.db)
    .await
    .unwrap();
    let r = t.post("/api/v1/unlock", None, json!({"pin": "2222"})).await;
    assert_eq!(
        (r.status, r.json()["error"].clone()),
        (StatusCode::CONFLICT, json!("ambiguous_pin"))
    );
    assert_eq!(
        t.unlock_resp("youth-camp", "", "2222").await.status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn home_page_unlock_has_its_own_lockout() {
    let (t, _) = fixture().await;
    for _ in 0..5 {
        let r = t.post("/api/v1/unlock", None, json!({"pin": "0000"})).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    }
    let r = t.post("/api/v1/unlock", None, json!({"pin": "2222"})).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(r.header("retry-after").is_some());
    // Folder pages are not locked by it.
    assert_eq!(
        t.unlock_resp("sunday-service", "day-1", "2222")
            .await
            .status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn sessions_do_not_combine() {
    let (t, _) = fixture().await;
    let editor = t.unlock_cookie(None, "sunday-service", "", "1111").await;
    let viewer = t
        .unlock_cookie(None, "sunday-service", "day-1", "2222")
        .await;
    let both = format!("{editor}; {viewer}");

    // In day-1 only the viewer session (rooted closer) counts: no editor upload there.
    let up = t
        .upload(&both, "sunday-service", "day-1", "a.txt", b"a")
        .await;
    assert_eq!(up.status, StatusCode::FORBIDDEN);
    // Elsewhere in sunday-service the editor session still applies.
    let up = t
        .upload(&both, "sunday-service", "day-2", "b.txt", b"b")
        .await;
    assert_eq!(up.status, StatusCode::NO_CONTENT);

    // Ending day-1's session hands day-1 back to the editor session.
    let day1 = t.items(&both, "sunday-service", "day-1").await.json()["folder"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let r = t
        .post("/api/v1/logout", Some(&both), json!({"folder_id": day1}))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(r.json()["ended"], 1);
    let cleared = r.header("set-cookie").unwrap();
    assert!(
        cleared.starts_with(viewer.split('=').next().unwrap()) && cleared.contains("Max-Age=0"),
        "{cleared}"
    );
    assert_eq!(
        t.items(&viewer, "sunday-service", "day-1").await.status,
        StatusCode::UNAUTHORIZED
    );
    let up = t
        .upload(&both, "sunday-service", "day-1", "a.txt", b"a")
        .await;
    assert_eq!(up.status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn unlocking_again_replaces_the_folder_session() {
    let (t, admin) = fixture().await;
    let day1 = t.items(&admin, "sunday-service", "day-1").await.json()["folder"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    t.pin(&admin, Some(&day1), "4444", "contributor").await;

    let viewer = t
        .unlock_cookie(None, "sunday-service", "day-1", "2222")
        .await;
    let contributor = t
        .unlock_cookie(Some(&viewer), "sunday-service", "day-1", "4444")
        .await;
    assert_eq!(viewer.split('=').next(), contributor.split('=').next());
    assert_eq!(
        t.items(&viewer, "sunday-service", "day-1").await.status,
        StatusCode::UNAUTHORIZED
    );
    let up = t
        .upload(&contributor, "sunday-service", "day-1", "c.txt", b"c")
        .await;
    assert_eq!(up.status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn logout_targets() {
    let (t, admin) = fixture().await;
    let viewer = t
        .unlock_cookie(None, "sunday-service", "day-1", "2222")
        .await;
    for body in [
        json!({}),
        json!({"all": true, "role": "admin"}),
        json!({"role": "viewer"}),
    ] {
        let r = t.post("/api/v1/logout", Some(&viewer), body.clone()).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{body}");
    }
    // Nothing to end is not an error.
    let r = t.post("/api/v1/logout", None, json!({"all": true})).await;
    assert_eq!(
        (r.status, r.json()["ended"].clone()),
        (StatusCode::OK, json!(0))
    );

    let r = t
        .post("/api/v1/logout", Some(&admin), json!({"role": "admin"}))
        .await;
    assert_eq!(r.json()["ended"], 1);
    assert_eq!(
        t.get("/api/v1/admin/folders", &admin).await.status,
        StatusCode::UNAUTHORIZED
    );
    let r = t
        .post("/api/v1/logout", Some(&viewer), json!({"all": true}))
        .await;
    assert_eq!(r.json()["ended"], 1);
    assert_eq!(
        t.items(&viewer, "sunday-service", "day-1").await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn traversal_in_folder_paths_is_rejected() {
    let (t, admin) = fixture().await;
    for (slug, path) in [
        ("sunday-service", "../youth-camp"),
        ("sunday-service", "day-1/../day-2"),
        ("sunday-service", ".."),
        ("..", ""),
        ("sunday-service", "%2e%2e"),
    ] {
        let r = t.items(&admin, slug, path).await;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{slug} / {path}");
    }
    let r = t.get("/dl/..%2F..%2Fark.db", &admin).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn traversal_in_names_stays_inside_the_folder() {
    let (t, _) = fixture().await;
    let editor = t.unlock("sunday-service", "", "1111").await;

    for (raw, shown) in [
        ("../../evil.txt", "evil.txt"),
        ("..\\..\\win.txt", "win.txt"),
        ("/etc/passwd", "passwd"),
    ] {
        let r = t
            .upload(&editor, "sunday-service", "", raw, raw.as_bytes())
            .await;
        assert_eq!(r.status, StatusCode::NO_CONTENT, "{raw}");
        let id = r.header("ark-file-id").unwrap();
        let item = t
            .call(
                Method::PATCH,
                &format!("/api/v1/items/{id}"),
                Some(&editor),
                Some(json!({})),
            )
            .await
            .json();
        assert_eq!(item["name"], shown);
    }
    for bad in ["..", "/", "   "] {
        let r = t.upload(&editor, "sunday-service", "", bad, b"x").await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{bad:?}");
    }

    // Everything landed in sunday-service's own directory.
    let sunday = t.items(&editor, "sunday-service", "").await.json()["folder"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let mut on_disk: Vec<String> = std::fs::read_dir(t.dir.join("files").join(&sunday))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    on_disk.sort();
    assert_eq!(on_disk, ["evil.txt", "passwd", "win.txt"]);
    assert!(!t.dir.join("evil.txt").exists() && !t.dir.parent().unwrap().join("evil.txt").exists());

    // Renames sanitize too.
    let any = t.items(&editor, "sunday-service", "").await.json()["files"][0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let r = t
        .call(
            Method::PATCH,
            &format!("/api/v1/items/{any}"),
            Some(&editor),
            Some(json!({"name": "../../x.txt"})),
        )
        .await;
    assert_eq!(r.json()["name"], "x.txt");

    // Subfolder names become slugs.
    let r = t
        .post(
            "/api/v1/folders/sunday-service/subfolders",
            Some(&editor),
            json!({"name": "../../etc"}),
        )
        .await;
    assert_eq!(r.json()["path"], "etc");
    let r = t
        .post(
            "/api/v1/folders/sunday-service/subfolders",
            Some(&editor),
            json!({"name": "../.."}),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn moves_cannot_leave_the_scope() {
    let (t, admin) = fixture().await;
    let sunday = t.items(&admin, "sunday-service", "").await.json()["folder"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let day2 = t.items(&admin, "sunday-service", "day-2").await.json()["folder"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let day1 = t.items(&admin, "sunday-service", "day-1").await.json()["folder"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    t.pin(&admin, Some(&day1), "5555", "editor").await;
    let day1_editor = t.unlock("sunday-service", "day-1", "5555").await;
    let id = t
        .upload(&day1_editor, "sunday-service", "day-1", "a.txt", b"a")
        .await
        .header("ark-file-id")
        .unwrap();

    let r = t
        .call(
            Method::PATCH,
            &format!("/api/v1/items/{id}"),
            Some(&day1_editor),
            Some(json!({"move_to": sunday})),
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    // Its own root folder cannot be moved out either.
    let r = t
        .call(
            Method::PATCH,
            &format!("/api/v1/items/{day1}"),
            Some(&day1_editor),
            Some(json!({"move_to": day2})),
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn concurrent_uploads_all_finalize() {
    let (t, _) = fixture().await;
    let editor = t.unlock("sunday-service", "", "1111").await;
    let uploads = (0..20).map(|i| {
        let (t, editor) = (&t, &editor);
        async move {
            let data = format!("photo number {i}");
            t.upload(
                editor,
                "sunday-service",
                "",
                &format!("p{i}.jpg"),
                data.as_bytes(),
            )
            .await
        }
    });
    let results = futures_util::future::join_all(uploads).await;
    for (i, r) in results.iter().enumerate() {
        assert_eq!(r.status, StatusCode::NO_CONTENT, "upload {i}: {}", r.text());
        assert!(
            r.header("ark-file-id").is_some(),
            "upload {i} has no file id"
        );
    }
    let listed = t.items(&editor, "sunday-service", "").await.json()["files"]
        .as_array()
        .unwrap()
        .len();
    assert_eq!(listed, 20);
}

#[tokio::test]
async fn received_upload_is_finalized_on_next_head() {
    let (t, _) = fixture().await;
    let editor = t.unlock("sunday-service", "", "1111").await;
    let create = Request::post("/api/v1/uploads")
        .header(header::AUTHORIZATION, format!("Bearer {editor}"))
        .header("upload-length", 5)
        .header(
            "upload-metadata",
            format!(
                "filename {},folder {}",
                STANDARD.encode("late.txt"),
                STANDARD.encode("sunday-service")
            ),
        )
        .body(Body::empty())
        .unwrap();
    let location = t.send(create).await.header("location").unwrap();
    let id = location.rsplit('/').next().unwrap().to_string();

    // As if the last PATCH stored every byte and then finalizing failed.
    std::fs::write(crate::storage::part_path(&t.state.cfg, &id), b"hello").unwrap();
    sqlx::query("UPDATE uploads SET offset = size WHERE id = ?")
        .bind(&id)
        .execute(&t.state.db)
        .await
        .unwrap();

    let head = Request::head(&location)
        .header(header::AUTHORIZATION, format!("Bearer {editor}"))
        .body(Body::empty())
        .unwrap();
    let r = t.send(head).await;
    assert_eq!(r.header("upload-offset").as_deref(), Some("5"));
    let file_id = r.header("ark-file-id").expect("finalized on HEAD");
    assert_eq!(
        t.get(&format!("/dl/{file_id}"), &editor).await.text(),
        "hello"
    );
}
