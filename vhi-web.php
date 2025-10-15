<?php
/******************************************************
 * VHI Web Manager — Single file (PHP 8.1+)
 * UI (HTML/CSS/JS) + API proxy (cURL)
 * Features: Auth, Dashboard, List/Create/Delete/Actions VMs
 * Wizard de création (DHCP/IP fixe, SG, spoofing, keypair, cloud-init, type volume)
 * Console noVNC via portail externe (iframe) + ouverture nouvel onglet
 * Floating IPs manager
 * Réseaux/Subnets manager (list, edit, delete, create)
 * Design: glassmorphism, dark-mode friendly
 ******************************************************/

session_start();

/* --- DEBUG --- */
ini_set('display_errors', 1);
error_reporting(E_ALL);

/* ========== CONFIG VHI (adapter) ========== */
const OS_AUTH_URL            = "https://vhi-panel.X.fr:5000/v3";
const OS_USERNAME            = "evan";
const OS_PASSWORD            = "";
const OS_USER_DOMAIN_NAME    = "";
const OS_PROJECT_DOMAIN_NAME = "";
const OS_PROJECT_NAME        = "Evan"; // essaie "evan" si 401
// Passe à true dès que le trust CA est OK
const VERIFY_TLS             = false;   // false pour tester self-signed / chaîne CA manquante
/* ========================================= */

/* ----------------- HTTP helpers ----------------- */
function http_request(string $method, string $url, array $opts = [], ?string $token = null): array {
    $ch = curl_init();
    $headers = ["Content-Type: application/json"];
    if ($token) $headers[] = "X-Auth-Token: {$token}";
    if (!empty($opts['headers']) && is_array($opts['headers'])) $headers = array_merge($headers, $opts['headers']);
    $payload = $opts['json'] ?? null;
    $timeout = $opts['timeout'] ?? 60;

    curl_setopt_array($ch, [
        CURLOPT_URL            => $url,
        CURLOPT_CUSTOMREQUEST  => strtoupper($method),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => $timeout,
        CURLOPT_HTTPHEADER     => $headers,
        CURLOPT_SSL_VERIFYPEER => VERIFY_TLS,
        CURLOPT_SSL_VERIFYHOST => VERIFY_TLS ? 2 : 0,
    ]);
    if ($payload !== null) curl_setopt($ch, CURLOPT_POSTFIELDS, is_string($payload) ? $payload : json_encode($payload));

    $respBody = curl_exec($ch);
    $status   = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $errno    = curl_errno($ch);
    $err      = curl_error($ch);
    curl_close($ch);

    $json = null;
    if ($respBody !== false && strlen(trim((string)$respBody))) {
        $t = ltrim($respBody);
        if ($t !== "" && ($t[0] === '{' || $t[0] === '[')) {
            $json = json_decode($respBody, true);
        }
    }
    return ["status"=>$status, "body"=>$respBody, "json"=>$json, "errno"=>$errno, "error"=>$err];
}
function http_get($url, $token=null, $opts=[])    { return http_request("GET",    $url, $opts, $token); }
function http_post($url,$token=null,$opts=[])     { return http_request("POST",   $url, $opts, $token); }
function http_delete($url,$token=null,$opts=[])   { return http_request("DELETE", $url, $opts, $token); }
function http_put($url,$token=null,$opts=[])      { return http_request("PUT",    $url, $opts, $token); }

/* ----------------- Keystone auth ----------------- */
function keystone_auth(): array {
    $payload = [
        "auth" => [
            "identity" => [
                "methods"  => ["password"],
                "password" => ["user" => [
                    "name"   => OS_USERNAME,
                    "domain" => ["name" => OS_USER_DOMAIN_NAME],
                    "password" => OS_PASSWORD
                ]]
            ],
            "scope" => ["project" => [
                "name"   => OS_PROJECT_NAME,
                "domain" => ["name" => OS_PROJECT_DOMAIN_NAME]
            ]]
        ]
    ];

    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL            => rtrim(OS_AUTH_URL, "/")."/auth/tokens",
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => json_encode($payload),
        CURLOPT_HTTPHEADER     => ["Content-Type: application/json"],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER         => true,
        CURLOPT_SSL_VERIFYPEER => VERIFY_TLS,
        CURLOPT_SSL_VERIFYHOST => VERIFY_TLS ? 2 : 0,
        CURLOPT_TIMEOUT        => 60,
    ]);
    $resp   = curl_exec($ch);
    $errno  = curl_errno($ch);
    $cerror = curl_error($ch);
    $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $hs     = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $hdr    = $resp !== false ? substr($resp,0,$hs) : "";
    $body   = $resp !== false ? substr($resp,$hs) : "";
    curl_close($ch);

    if ($errno)          throw new Exception("cURL[$errno]: ".$cerror);
    if ($status !== 201) throw new Exception("Keystone HTTP $status — ".$body);

    $headers = [];
    foreach (explode("\r\n", $hdr) as $h) {
        $p = strpos($h, ":");
        if ($p !== false) $headers[strtolower(trim(substr($h,0,$p)))] = trim(substr($h,$p+1));
    }
    $token = $headers["x-subject-token"] ?? null;
    if (!$token) throw new Exception("Auth ok mais X-Subject-Token manquant");

    $bodyJ = json_decode($body, true) ?: [];
    $project_id = $bodyJ["token"]["project"]["id"] ?? null;

    $endpoints = [];
    foreach ($bodyJ["token"]["catalog"] ?? [] as $svc) {
        $stype = $svc["type"] ?? null;
        if (!$stype) continue;
        foreach ($svc["endpoints"] ?? [] as $ep) {
            if (($ep["interface"] ?? "") === "public") {
                $endpoints[$stype] = rtrim($ep["url"], "/");
                break;
            }
        }
    }

    $_SESSION["vhi"] = ["token"=>$token, "endpoints"=>$endpoints, "project_id"=>$project_id, "ts"=>time()];
    return $_SESSION["vhi"];
}
function ensure_auth(): array {
    if (!isset($_SESSION["vhi"]["token"])) return keystone_auth();
    if (time() - ($_SESSION["vhi"]["ts"] ?? 0) > 45*60) return keystone_auth(); // refresh 45 min
    return $_SESSION["vhi"];
}

/* ----------------- OpenStack helpers ----------------- */
function ep_get(string $key): ?string {
    $ep = $_SESSION["vhi"]["endpoints"] ?? [];
    return $ep[$key] ?? null;
}

/* ---------- Dashboard stats ---------- */
function gather_stats(): array {
    $ctx = ensure_auth(); $t = $ctx["token"]; $ep = $ctx["endpoints"]; $project_id = $ctx["project_id"];
    $stats = [];

    // Nova
    if (!empty($ep["compute"])) {
        $sv = http_get($ep["compute"]."/servers/detail", $t);
        $stats["vm_count"] = is_array($sv["json"]) ? count($sv["json"]["servers"] ?? []) : 0;
        $lim = http_get($ep["compute"]."/limits", $t);
        $abs = $lim["json"]["limits"]["absolute"] ?? [];
        $stats["cores_used"] = $abs["totalCoresUsed"] ?? null;
        $stats["cores_max"]  = $abs["maxTotalCores"] ?? null;
        $stats["ram_used"]   = $abs["totalRAMUsed"] ?? null;
        $stats["ram_max"]    = $abs["maxTotalRAMSize"] ?? null;
    }
    // Neutron
    if (!empty($ep["network"])) {
        $fips = http_get($ep["network"]."/v2.0/floatingips", $t);
        $arr = $fips["json"]["floatingips"] ?? [];
        $stats["fip_total"] = is_array($arr) ? count($arr) : 0;
        $stats["fip_associated"] = is_array($arr) ? array_reduce($arr, fn($c,$x)=>$c + (!empty($x["port_id"])?1:0), 0) : 0;
    }
    // Cinder
    $cinder = $ep["volumev3"] ?? ($ep["volumev2"] ?? ($ep["volume"] ?? null));
    if ($cinder) {
        $base = rtrim($cinder, "/");
        $vols = http_get($base."/volumes/detail", $t);
        if (!in_array($vols["status"], [200,203])) $vols = http_get($base."/".$project_id."/volumes/detail", $t);
        $vlist = $vols["json"]["volumes"] ?? [];
        $stats["vol_count"] = is_array($vlist) ? count($vlist) : 0;
        $stats["vol_size_gb"] = is_array($vlist) ? array_reduce($vlist, fn($c,$v)=>$c + (int)($v["size"] ?? 0), 0) : 0;

        $lim = http_get($base."/limits", $t);
        if (!in_array($lim["status"], [200,203])) $lim = http_get($base."/".$project_id."/limits", $t);
        $abs = $lim["json"]["limits"]["absolute"] ?? [];
        $stats["vol_gb_max"] = $abs["maxTotalVolumeGigabytes"] ?? null;
    }
    return $stats;
}

/* ---------- Listings ---------- */
function list_images(): array {
    $ctx = ensure_auth(); $t = $ctx["token"]; $glance = ep_get("image");
    $imgs = [];
    foreach (["", "?visibility=public", "?visibility=shared&member_status=accepted", "?visibility=community"] as $q) {
        $r = http_get($glance."/v2/images".$q, $t);
        if (in_array($r["status"], [200,203]) && isset($r["json"]["images"])) $imgs = array_merge($imgs, $r["json"]["images"]);
    }
    $seen=[]; $uniq=[];
    foreach ($imgs as $im) { if (!in_array($im["id"], $seen)) { $seen[]=$im["id"]; $uniq[]=$im; } }
    usort($uniq, fn($a,$b)=>strcmp(strtolower($a["name"]??""), strtolower($b["name"]??"")));
    return $uniq;
}
function list_flavors(): array {
    $ctx = ensure_auth(); $t = $ctx["token"]; $nova = ep_get("compute");
    $r = http_get($nova."/flavors/detail", $t);
    $fls = $r["json"]["flavors"] ?? [];
    usort($fls, fn($a,$b)=>($a["vcpus"] <=> $b["vcpus"]) ?: ($a["ram"] <=> $b["ram"]));
    return $fls;
}
function list_networks(): array {
    $ctx = ensure_auth(); $t = $ctx["token"]; $neutron = ep_get("network");
    $r = http_get($neutron."/v2.0/networks", $t);
    return $r["json"]["networks"] ?? [];
}
function list_keypairs(): array {
    $ctx = ensure_auth(); $t = $ctx["token"]; $nova = ep_get("compute");
    $r = http_get($nova."/os-keypairs", $t);
    $out = [];
    foreach (($r["json"]["keypairs"] ?? []) as $kp) { if (!empty($kp["keypair"]["name"])) $out[] = $kp["keypair"]["name"]; }
    sort($out);
    return $out;
}
function list_secgroups(): array {
    $ctx = ensure_auth(); $t = $ctx["token"]; $neutron = ep_get("network"); $project_id = $ctx["project_id"];
    $r = http_get($neutron."/v2.0/security-groups", $t);
    $sgs = $r["json"]["security_groups"] ?? [];
    $mine = [];
    foreach ($sgs as $sg) {
        $pid = $sg["project_id"] ?? ($sg["tenant_id"] ?? "");
        if ($pid === $project_id) $mine[] = $sg;
    }
    if (!$mine) $mine = $sgs;
    usort($mine, fn($a,$b)=>strcmp(strtolower($a["name"]??""), strtolower($b["name"]??"")));
    return array_map(fn($sg)=>["id"=>$sg["id"], "name"=>$sg["name"] ?? $sg["id"]], $mine);
}

/* ---------- Volume types (Cinder) ---------- */
function list_volume_types(): array {
    $ctx = ensure_auth(); $t = $ctx["token"];
    $cinder = ep_get("volumev3") ?? ep_get("volumev2") ?? ep_get("volume");
    if (!$cinder) return [];
    $base = rtrim($cinder, "/");
    $r = http_get($base."/types", $t);
    if (!in_array($r["status"], [200,203])) {
        $r = http_get($base."/".($ctx["project_id"]??"")."/types", $t);
    }
    $types = $r["json"]["volume_types"] ?? [];
    usort($types, fn($a,$b)=>strcmp(strtolower($a["name"]??""), strtolower($b["name"]??"")));
    return array_map(fn($x)=>["id"=>$x["id"]??($x["name"]??""), "name"=>$x["name"]??($x["id"]??"")], $types);
}

/* ---------- Neutron Port ---------- */
function create_port(string $network_id, array $secgroup_ids, bool $spoofing, ?string $fixed_ip): string {
    $ctx = ensure_auth(); $t = $ctx["token"]; $neutron = ep_get("network");
    $body = ["port" => [
        "network_id" => $network_id,
        "port_security_enabled" => $spoofing ? false : true
    ]];
    if ($secgroup_ids) $body["port"]["security_groups"] = array_values($secgroup_ids);
    if ($fixed_ip) $body["port"]["fixed_ips"] = [["ip_address" => $fixed_ip]];
    $r = http_post($neutron."/v2.0/ports", $t, ["json"=>$body, "timeout"=>120]);
    if (!in_array($r["status"], [201,202])) throw new Exception("Create port error ".$r["status"]." ".$r["body"]);
    return $r["json"]["port"]["id"] ?? "";
}

/* ---------- Volume helpers ---------- */
function get_image($image_id): array {
    $ctx = ensure_auth(); $t = $ctx["token"]; $glance = ep_get("image");
    $r = http_get($glance."/v2/images/{$image_id}", $t);
    if (!in_array($r["status"], [200,203])) throw new Exception("Image introuvable");
    return $r["json"];
}
function ceil_gib_from_bytes($n) { return max(1, (int)ceil($n / (1024**3))); }
function wait_volume($vol_id, $timeout=600): array {
    $ctx = ensure_auth(); $t = $ctx["token"]; $ep = $ctx["endpoints"]; $project_id = $ctx["project_id"];
    $cinder = $ep["volumev3"] ?? ($ep["volumev2"] ?? ($ep["volume"] ?? null));
    $base = rtrim($cinder, "/");
    $try1 = http_get($base."/volumes/{$vol_id}", $t);
    $vol_url = in_array($try1["status"], [200,203]) ? $base."/volumes/{$vol_id}" : $base."/{$project_id}/volumes/{$vol_id}";
    $t0 = time();
    do {
        $r = http_get($vol_url, $t);
        $v = $r["json"]["volume"] ?? [];
        $st = $v["status"] ?? null;
        if ($st === "available") return $v;
        if (in_array($st, ["error","error_extending"])) throw new Exception("Volume en erreur");
        usleep(800000);
    } while (time() - $t0 < $timeout);
    throw new Exception("Attente volume trop longue");
}
function create_boot_volume($image_id, $name, $min_size_gb=null, $volume_type=null): string {
    $ctx = ensure_auth(); $t = $ctx["token"]; $ep = $ctx["endpoints"]; $project_id = $ctx["project_id"];
    $img = get_image($image_id);
    $need = $img["min_disk"] ?? 0;
    if (!$need) $need = isset($img["size"]) ? ceil_gib_from_bytes($img["size"]) : 10;
    if ($min_size_gb) $need = max($need, (int)$min_size_gb);
    $cinder = $ep["volumev3"] ?? ($ep["volumev2"] ?? ($ep["volume"] ?? null));
    $base = rtrim($cinder, "/");
    $volSpec = ["name"=>$name, "size"=>$need, "imageRef"=>$image_id];
    if ($volume_type) $volSpec["volume_type"] = $volume_type;
    $body = ["volume"=>$volSpec];
    $r = http_post($base."/volumes", $t, ["json"=>$body, "timeout"=>120]);
    if (!in_array($r["status"], [200,202])) $r = http_post($base."/{$project_id}/volumes", $t, ["json"=>$body, "timeout"=>120]);
    if (!in_array($r["status"], [200,202])) throw new Exception("Create volume error ".$r["status"]);
    $vol_id = $r["json"]["volume"]["id"] ?? null;
    if (!$vol_id) throw new Exception("Volume ID manquant");
    wait_volume($vol_id);
    return $vol_id;
}

/* ---------- Create / Delete / Actions VM ---------- */
function flavor_by_id($flavor_id): array {
    foreach (list_flavors() as $f) if (($f["id"] ?? null) === $flavor_id) return $f;
    return [];
}
function create_server_from_volume($name,$flavor_id,$port_id,$volume_id,$key_name=null,$user_data_b64=null): array {
    $ctx = ensure_auth(); $t = $ctx["token"]; $nova = ep_get("compute");
    $bdm = [[
        "boot_index"=>"0","uuid"=>$volume_id,
        "source_type"=>"volume","destination_type"=>"volume",
        "delete_on_termination"=>true
    ]];
    $server = ["server"=>[
        "name"=>$name, "flavorRef"=>$flavor_id,
        "block_device_mapping_v2"=>$bdm,
        "networks"=>[["port"=>$port_id]]
    ]];
    if ($key_name)        $server["server"]["key_name"] = $key_name;
    if ($user_data_b64)   $server["server"]["user_data"] = $user_data_b64;
    $r = http_post($nova."/servers", $t, ["json"=>$server, "timeout"=>180]);
    if (!in_array($r["status"], [202,200])) throw new Exception("Create VM (volume) ".$r["status"]." ".$r["body"]);
    return $r["json"];
}
function create_server_image_boot($name,$image_id,$flavor_id,$port_id,$key_name=null,$user_data_b64=null): array {
    $ctx = ensure_auth(); $t = $ctx["token"]; $nova = ep_get("compute");
    $server = ["server"=>[
        "name"=>$name, "imageRef"=>$image_id, "flavorRef"=>$flavor_id,
        "networks"=>[["port"=>$port_id]]
    ]];
    if ($key_name)        $server["server"]["key_name"] = $key_name;
    if ($user_data_b64)   $server["server"]["user_data"] = $user_data_b64;
    $r = http_post($nova."/servers", $t, ["json"=>$server, "timeout"=>180]);
    if (!in_array($r["status"], [202,200])) throw new Exception("Create VM ".$r["status"]." ".$r["body"]);
    return $r["json"];
}
function delete_server($server_id): bool {
    $ctx = ensure_auth(); $t = $ctx["token"]; $nova = ep_get("compute");
    $r = http_delete($nova."/servers/{$server_id}", $t, ["timeout"=>90]);
    return in_array($r["status"], [202,204]);
}
function server_action($server_id, $action): bool {
    $ctx = ensure_auth(); $t = $ctx["token"]; $nova = ep_get("compute");
    $map = [
        "start"        => ["os-start" => null],
        "stop"         => ["os-stop"  => null],
        "reboot_soft"  => ["reboot"   => ["type"=>"SOFT"]],
        "reboot_hard"  => ["reboot"   => ["type"=>"HARD"]],
    ];
    if (!isset($map[$action])) throw new Exception("Action inconnue");
    $r = http_post($nova."/servers/{$server_id}/action", $t, ["json"=>$map[$action], "timeout"=>90]);
    return in_array($r["status"], [202,204]);
}
function vm_snapshot($server_id, $name): bool {
    $ctx = ensure_auth(); $t = $ctx["token"]; $nova = ep_get("compute");
    $body = ["createImage" => ["name" => $name, "metadata" => new stdClass()]];
    $r = http_post($nova."/servers/{$server_id}/action", $t, ["json"=>$body, "timeout"=>120]);
    return in_array($r["status"], [202,200]);
}

/* ---------- List Servers (enrichi) ---------- */
function list_servers(): array {
    $ctx = ensure_auth(); $t = $ctx["token"];
    $nova = ep_get("compute");

    $r = http_get($nova."/servers/detail", $t);
    $servers = $r["json"]["servers"] ?? [];

    $flavors = list_flavors(); $fmap = [];
    foreach ($flavors as $f) { $fmap[$f["id"]] = $f; }

    foreach ($servers as &$s) {
        $fid = $s["flavor"]["id"] ?? null;
        if ($fid && isset($fmap[$fid])) {
            $f = $fmap[$fid];
            $s["flavor_info"] = [
                "name"=>$f["name"]??$fid, "vcpus"=>$f["vcpus"]??null, "ram"=>$f["ram"]??null, "disk"=>$f["disk"]??null
            ];
        } else {
            $s["flavor_info"] = ["name"=>$s["flavor"]["original_name"] ?? ($s["flavor"]["name"] ?? ($fid ?? "-"))];
        }

        $iface = "-";
        if (!empty($s["addresses"]) && is_array($s["addresses"])) {
            $keys = array_keys($s["addresses"]);
            if (!empty($keys)) $iface = $keys[0];
        }
        $s["primary_net"] = $iface;

        $fips = [];
        foreach (($s["addresses"][$iface] ?? []) as $a) {
            if (!empty($a["OS-EXT-IPS:type"]) && $a["OS-EXT-IPS:type"] === "floating" && !empty($a["addr"])) {
                $fips[] = $a["addr"];
            }
        }
        $s["floating_ips"] = $fips;
    }
    unset($s);
    return $servers;
}

/* ---------- Floating IP & Ports (Neutron) ---------- */
function neutron_list_fips(): array {
    $ctx = ensure_auth(); $t = $ctx["token"]; $neutron = ep_get("network");
    $r = http_get($neutron."/v2.0/floatingips", $t);
    return $r["json"]["floatingips"] ?? [];
}
function neutron_list_ports(): array {
    $ctx = ensure_auth(); $t = $ctx["token"]; $neutron = ep_get("network");
    $r = http_get($neutron."/v2.0/ports", $t);
    return $r["json"]["ports"] ?? [];
}
function neutron_allocate_fip($floating_network_id): array {
    $ctx = ensure_auth(); $t = $ctx["token"]; $neutron = ep_get("network");
    $body = ["floatingip" => ["floating_network_id"=>$floating_network_id]];
    $r = http_post($neutron."/v2.0/floatingips", $t, ["json"=>$body, "timeout"=>60]);
    if (!in_array($r["status"], [201,200])) throw new Exception("FIP allocate error ".$r["status"]." ".$r["body"]);
    return $r["json"]["floatingip"] ?? [];
}
function neutron_update_fip($fip_id, $payload): array {
    $ctx = ensure_auth(); $t = $ctx["token"]; $neutron = ep_get("network");
    $r = http_put($neutron."/v2.0/floatingips/".$fip_id, $t, ["json"=>["floatingip"=>$payload], "timeout"=>60]);
    if (!in_array($r["status"], [200,202])) throw new Exception("FIP update error ".$r["status"]." ".$r["body"]);
    return $r["json"]["floatingip"] ?? [];
}
function neutron_delete_fip($fip_id): bool {
    $ctx = ensure_auth(); $t = $ctx["token"]; $neutron = ep_get("network");
    $r = http_delete($neutron."/v2.0/floatingips/".$fip_id, $t, ["timeout"=>60]);
    return in_array($r["status"], [204,202]);
}
function ports_by_server($server_id): array {
    $ports = neutron_list_ports(); $out=[];
    $nets = list_networks(); $nmap=[];
    foreach($nets as $n){ $nmap[$n["id"]] = $n["name"] ?? $n["id"]; }
    foreach($ports as $p){
        if(($p["device_id"] ?? "") === $server_id){
            $ip4 = "";
            foreach(($p["fixed_ips"] ?? []) as $fi){ if (!empty($fi["ip_address"])) { $ip4 = $fi["ip_address"]; break; } }
            $out[] = [
                "id"=>$p["id"], "ip"=>$ip4, "network_id"=>$p["network_id"],
                "network_name"=>$nmap[$p["network_id"]] ?? $p["network_id"]
            ];
        }
    }
    return $out;
}

/* ---------- Networks/Subnets (Neutron) ---------- */
function neutron_list_subnets(): array {
    $ctx = ensure_auth(); $t = $ctx["token"]; $neutron = ep_get("network");
    $r = http_get($neutron."/v2.0/subnets", $t);
    return $r["json"]["subnets"] ?? [];
}
function neutron_create_network(string $name, bool $admin_state_up=true): array {
    $ctx = ensure_auth(); $t = $ctx["token"]; $neutron = ep_get("network");
    $body = ["network"=>["name"=>$name, "admin_state_up"=>$admin_state_up]];
    $r = http_post($neutron."/v2.0/networks", $t, ["json"=>$body, "timeout"=>60]);
    if (!in_array($r["status"], [201,200])) throw new Exception("Create network error ".$r["status"]." ".$r["body"]);
    return $r["json"]["network"] ?? [];
}
function neutron_delete_network(string $network_id): bool {
    $ctx = ensure_auth(); $t = $ctx["token"]; $neutron = ep_get("network");
    $r = http_delete($neutron."/v2.0/networks/".$network_id, $t, ["timeout"=>60]);
    return in_array($r["status"], [204,202]);
}
function neutron_create_subnet(string $network_id, string $cidr, ?string $gateway, bool $enable_dhcp, array $alloc_pools, array $dns): array {
    $ctx = ensure_auth(); $t = $ctx["token"]; $neutron = ep_get("network");
    $payload = [
        "subnet"=>[
            "network_id"=>$network_id,
            "ip_version"=>4,
            "cidr"=>$cidr,
            "enable_dhcp"=>$enable_dhcp,
        ]
    ];
    if ($gateway !== null && $gateway !== "") $payload["subnet"]["gateway_ip"] = $gateway;
    if ($dns) $payload["subnet"]["dns_nameservers"] = array_values($dns);
    if ($alloc_pools) $payload["subnet"]["allocation_pools"] = array_values($alloc_pools);
    $r = http_post($neutron."/v2.0/subnets", $t, ["json"=>$payload, "timeout"=>60]);
    if (!in_array($r["status"], [201,200])) throw new Exception("Create subnet error ".$r["status"]." ".$r["body"]);
    return $r["json"]["subnet"] ?? [];
}
function neutron_update_subnet(string $subnet_id, ?string $gateway, ?bool $enable_dhcp, array $alloc_pools, array $dns): array {
    $ctx = ensure_auth(); $t = $ctx["token"]; $neutron = ep_get("network");
    $upd = [];
    if ($enable_dhcp !== null) $upd["enable_dhcp"] = $enable_dhcp;
    if ($gateway !== null) $upd["gateway_ip"] = ($gateway === "" ? null : $gateway);
    if ($dns !== null) $upd["dns_nameservers"] = array_values($dns);
    if ($alloc_pools !== null) $upd["allocation_pools"] = array_values($alloc_pools);
    $r = http_put($neutron."/v2.0/subnets/".$subnet_id, $t, ["json"=>["subnet"=>$upd], "timeout"=>60]);
    if (!in_array($r["status"], [200,202])) throw new Exception("Update subnet error ".$r["status"]." ".$r["body"]);
    return $r["json"]["subnet"] ?? [];
}
function neutron_delete_subnet(string $subnet_id): bool {
    $ctx = ensure_auth(); $t = $ctx["token"]; $neutron = ep_get("network");
    $r = http_delete($neutron."/v2.0/subnets/".$subnet_id, $t, ["timeout"=>60]);
    return in_array($r["status"], [204,202]);
}

/* ---------- API Router (AJAX) ---------- */
if (isset($_GET["api"])) {
    header("Content-Type: application/json; charset=utf-8");
    try {
        $action = $_GET["api"];
        if ($action === "auth") {
            $ctx = keystone_auth();
            echo json_encode(["ok"=>true, "project_id"=>$ctx["project_id"]]); exit;
        }
        ensure_auth();

        switch ($action) {
            case "stats":
                echo json_encode(["ok"=>true, "data"=>gather_stats()]); break;

            case "list_servers":
                echo json_encode(["ok"=>true, "data"=>list_servers()]); break;

            case "list_options":
                echo json_encode([
                    "ok"=>true,
                    "images"=>list_images(),
                    "flavors"=>list_flavors(),
                    "networks"=>list_networks()
                ]); break;

            case "extra_options":
                echo json_encode([
                    "ok"=>true,
                    "secgroups"=>list_secgroups(),
                    "keypairs"=>list_keypairs(),
                    "volume_types"=>list_volume_types()
                ]); break;

            /* ---- FIPs ---- */
            case "fip_list": {
                $fips = neutron_list_fips();
                $ports = neutron_list_ports();
                $nets  = list_networks();
                $sv    = list_servers();

                $nmap = [];
                foreach($nets as $n){ $nmap[$n["id"]] = $n["name"] ?? $n["id"]; }

                $p_to_vm = [];
                foreach($ports as $p){
                    $pid = $p["id"] ?? null;
                    if($pid) $p_to_vm[$pid] = [
                        "vm_id" => $p["device_id"] ?? null,
                        "fixed_ip" => ($p["fixed_ips"][0]["ip_address"] ?? null)
                    ];
                }
                $smap = [];
                foreach($sv as $s){ $smap[$s["id"]] = ($s["name"] ?? $s["id"]); }

                $out = [];
                foreach($fips as $f){
                    $port_id = $f["port_id"] ?? null;
                    $vm_id = $port_id && isset($p_to_vm[$port_id]) ? $p_to_vm[$port_id]["vm_id"] : null;
                    $fixed_ip = $port_id && isset($p_to_vm[$port_id]) ? $p_to_vm[$port_id]["fixed_ip"] : null;
                    $out[] = [
                        "id" => $f["id"] ?? "",
                        "floating_ip_address" => $f["floating_ip_address"] ?? "",
                        "floating_network_id" => $f["floating_network_id"] ?? "",
                        "network_name" => $nmap[$f["floating_network_id"] ?? ""] ?? null,
                        "status" => $f["status"] ?? "",
                        "port_id" => $port_id,
                        "vm_id" => $vm_id,
                        "vm_name" => $vm_id ? ($smap[$vm_id] ?? $vm_id) : null,
                        "fixed_ip_address" => $fixed_ip
                    ];
                }
                echo json_encode(["ok"=>true, "data"=>$out]);
                break;
            }
            case "ports_by_server": {
                $p = json_decode(file_get_contents("php://input"), true) ?? [];
                $sid = $p["server_id"] ?? "";
                if(!$sid) throw new Exception("server_id manquant");
                $ports = ports_by_server($sid);
                echo json_encode(["ok"=>true, "data"=>$ports]);
                break;
            }
            case "fip_allocate": {
                $p = json_decode(file_get_contents("php://input"), true) ?? [];
                $net = $p["floating_network_id"] ?? "";
                if(!$net) throw new Exception("floating_network_id manquant");
                $fip = neutron_allocate_fip($net);
                echo json_encode(["ok"=>true, "fip"=>$fip]);
                break;
            }
            case "fip_associate": {
                $p = json_decode(file_get_contents("php://input"), true) ?? [];
                $fip = $p["fip_id"] ?? "";
                $port = $p["port_id"] ?? "";
                if(!$fip || !$port) throw new Exception("fip_id/port_id manquant");
                $res = neutron_update_fip($fip, ["port_id"=>$port]);
                echo json_encode(["ok"=>true, "fip"=>$res]);
                break;
            }
            case "fip_disassociate": {
                $p = json_decode(file_get_contents("php://input"), true) ?? [];
                $fip = $p["fip_id"] ?? "";
                if(!$fip) throw new Exception("fip_id manquant");
                $res = neutron_update_fip($fip, ["port_id"=>null]);
                echo json_encode(["ok"=>true, "fip"=>$res]);
                break;
            }
            case "fip_release": {
                $p = json_decode(file_get_contents("php://input"), true) ?? [];
                $fip = $p["fip_id"] ?? "";
                if(!$fip) throw new Exception("fip_id manquant");
                $ok = neutron_delete_fip($fip);
                echo json_encode(["ok"=>$ok]);
                break;
            }

            /* ---- Networks/Subnets ---- */
            case "net_list": {
                $nets = list_networks();
                echo json_encode(["ok"=>true, "data"=>$nets]);
                break;
            }
            case "subnet_list": {
                $subs = neutron_list_subnets();
                echo json_encode(["ok"=>true, "data"=>$subs]);
                break;
            }
            case "net_create": {
                $p = json_decode(file_get_contents("php://input"), true) ?? [];
                $name   = trim($p["name"] ?? "");
                $cidr   = trim($p["cidr"] ?? "");
                $gateway = isset($p["gateway"]) ? trim($p["gateway"]) : null;
                $enable_dhcp = (bool)($p["enable_dhcp"] ?? true);
                $pool_start  = trim($p["pool_start"] ?? "");
                $pool_end    = trim($p["pool_end"] ?? "");
                $dns_list    = is_array($p["dns"] ?? null) ? $p["dns"] : [];
                if (!$name || !$cidr) throw new Exception("name et cidr requis");

                $net = neutron_create_network($name, true);
                $alloc_pools = [];
                if ($pool_start && $pool_end) $alloc_pools[] = ["start"=>$pool_start, "end"=>$pool_end];
                $sub = neutron_create_subnet($net["id"], $cidr, $gateway, $enable_dhcp, $alloc_pools, $dns_list);
                echo json_encode(["ok"=>true, "network"=>$net, "subnet"=>$sub]);
                break;
            }
            case "subnet_update": {
                $p = json_decode(file_get_contents("php://input"), true) ?? [];
                $sid = $p["subnet_id"] ?? "";
                if (!$sid) throw new Exception("subnet_id manquant");
                $enable_dhcp = isset($p["enable_dhcp"]) ? (bool)$p["enable_dhcp"] : null;
                $gateway     = $p["gateway"] ?? null; // "" pour none
                $pool_start  = trim($p["pool_start"] ?? "");
                $pool_end    = trim($p["pool_end"] ?? "");
                $dns_list    = is_array($p["dns"] ?? null) ? $p["dns"] : null;

                $alloc_pools = null;
                if ($pool_start !== "" || $pool_end !== "") {
                    $alloc_pools = [];
                    if ($pool_start && $pool_end) $alloc_pools[] = ["start"=>$pool_start, "end"=>$pool_end];
                }
                $res = neutron_update_subnet($sid, $gateway, $enable_dhcp, $alloc_pools ?? [], $dns_list ?? []);
                echo json_encode(["ok"=>true, "subnet"=>$res]);
                break;
            }
            case "subnet_delete": {
                $p = json_decode(file_get_contents("php://input"), true) ?? [];
                $sid = $p["subnet_id"] ?? "";
                if (!$sid) throw new Exception("subnet_id manquant");
                $ok = neutron_delete_subnet($sid);
                echo json_encode(["ok"=>$ok]);
                break;
            }
            case "net_delete": {
                $p = json_decode(file_get_contents("php://input"), true) ?? [];
                $nid = $p["network_id"] ?? "";
                if (!$nid) throw new Exception("network_id manquant");
                $ok = neutron_delete_network($nid);
                echo json_encode(["ok"=>$ok]);
                break;
            }

            case "create_vm":
                $p = json_decode(file_get_contents("php://input"), true) ?? [];
                $name       = trim($p["name"] ?? "");
                $image_id   = $p["image_id"] ?? null;
                $flavor_id  = $p["flavor_id"] ?? null;
                $network_id = $p["network_id"] ?? null;
                $root_size  = isset($p["root_gb"]) ? (int)$p["root_gb"] : null;
                $user_data_b64 = $p["user_data_b64"] ?? null;
                $key_name   = $p["key_name"] ?? null;

                $ip_mode_dhcp = (bool)($p["ip_mode_dhcp"] ?? true);
                $fixed_ip     = $p["fixed_ip"] ?? null;
                $secgroup_ids = is_array($p["secgroup_ids"] ?? null) ? $p["secgroup_ids"] : [];
                $spoofing     = (bool)($p["spoofing"] ?? false);

                $volume_type  = $p["volume_type"] ?? null; // Cinder volume type

                if (!$name || !$image_id || !$flavor_id || !$network_id)
                    throw new Exception("Champs requis manquants");

                $port_id = create_port($network_id, $secgroup_ids, $spoofing, $ip_mode_dhcp ? null : $fixed_ip);

                $fl = flavor_by_id($flavor_id);
                $fl_disk = (int)($fl["disk"] ?? 0);

                if ($fl_disk === 0 || ($root_size && $root_size > 0)) {
                    $vol_id = create_boot_volume($image_id, $name."-root", $root_size, $volume_type);
                    $resp = create_server_from_volume($name, $flavor_id, $port_id, $vol_id, $key_name, $user_data_b64);
                } else {
                    try {
                        $resp = create_server_image_boot($name, $image_id, $flavor_id, $port_id, $key_name, $user_data_b64);
                    } catch (Exception $e) {
                        if (str_contains(strtolower($e->getMessage()), "zero disk")) {
                            $vol_id = create_boot_volume($image_id, $name."-root", $root_size, $volume_type);
                            $resp = create_server_from_volume($name, $flavor_id, $port_id, $vol_id, $key_name, $user_data_b64);
                        } else { throw $e; }
                    }
                }
                echo json_encode(["ok"=>true, "server"=>$resp]); break;

            case "delete_vm":
                $payload = json_decode(file_get_contents("php://input"), true) ?? [];
                $sid = $payload["server_id"] ?? "";
                if (!$sid) throw new Exception("server_id manquant");
                $ok = delete_server($sid);
                echo json_encode(["ok"=>$ok]); break;

            case "vm_action":
                $p = json_decode(file_get_contents("php://input"), true) ?? [];
                $sid = $p["server_id"] ?? "";
                $act = $p["action"] ?? "";
                if (!$sid || !$act) throw new Exception("Paramètres manquants");
                $ok = server_action($sid, $act);
                echo json_encode(["ok"=>$ok]); break;

            case "vm_snapshot":
                $p = json_decode(file_get_contents("php://input"), true) ?? [];
                $sid = $p["server_id"] ?? "";
                $name = trim($p["name"] ?? "");
                if (!$sid || !$name) throw new Exception("Paramètres manquants");
                $ok = vm_snapshot($sid, $name);
                echo json_encode(["ok"=>$ok]); break;

            default:
                echo json_encode(["ok"=>false,"error"=>"Action inconnue"]);
        }
    } catch (Throwable $e) {
        echo json_encode(["ok"=>false, "error"=>$e->getMessage()]);
    }
    exit;
}
?>
<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>VHI Web Manager</title>
<style>
:root{
  --bg: #0f1120; --card:#151933cc; --muted:#aab1c7; --fg:#e6e9f5; --brand:#7c5cff; --brand-2:#17d1ff;
  --ok:#19d192; --warn:#ffb020; --err:#ff5468; --stroke:#26304a; --glass: blur(10px);
}
*{box-sizing:border-box}
html,body{height:100%}
body{
  margin:0; font-family: Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, "Helvetica Neue", Arial;
  background: radial-gradient(1200px 800px at 20% -10%, #1c2250 0%, transparent 60%),
              radial-gradient(1200px 800px at 120% 10%, #03263a 0%, transparent 60%), var(--bg);
  color:var(--fg);
}
.container{max-width:1200px; margin:0 auto; padding:24px}
.header{display:flex; align-items:center; justify-content:space-between; gap:16px; margin-bottom:18px;}
.brand{display:flex; align-items:center; gap:12px}
.logo{
  width:42px; height:42px; border-radius:12px;
  background: linear-gradient(145deg, var(--brand), var(--brand-2));
  box-shadow: 0 10px 30px #7c5cff66, inset 0 0 30px #ffffff22;
}
.title{font-weight:700; font-size:22px; letter-spacing:.3px}
.actions{display:flex; gap:10px}
.btn{
  border:1px solid var(--stroke); color:var(--fg); background:#11152a88;
  padding:10px 14px; border-radius:12px; cursor:pointer; backdrop-filter:var(--glass);
  transition:all .15s ease; font-weight:600;
}
.btn:hover{transform:translateY(-1px); border-color:#39507a}
.btn.primary{background:linear-gradient(180deg, #2a2f55, #1a1f3b); border-color:#3a4d86}
.btn.primary span{background:linear-gradient(90deg, var(--brand), var(--brand-2)); -webkit-background-clip:text; -webkit-text-fill-color:transparent}
.grid{display:grid; grid-template-columns: repeat(12, 1fr); gap:14px}

/* Cards */
.card{
  grid-column: span 12; border:1px solid var(--stroke); border-radius:16px; padding:16px;
  background:linear-gradient(180deg, #12162fbb, #0f1328a0); backdrop-filter:var(--glass);
  box-shadow: 0 8px 30px #00000044, inset 0 0 0 1px #ffffff06;
}
.card h3{margin:0 0 8px 0; font-size:15px; color:#c9d3ff; font-weight:700; text-transform:uppercase; letter-spacing:.12em}
.row{display:flex; flex-wrap:wrap; gap:10px}
.kpi{
  flex:1 1 120px; border:1px dashed #2a3555; border-radius:14px; padding:12px 14px; min-width:140px;
  background:#0d1230cc;
}
.kpi .label{font-size:12px; color:#99a6d1; text-transform:uppercase; letter-spacing:.12em}
.kpi .value{font-size:22px; font-weight:800; margin-top:6px}

/* VM list */
.vm-list{display:grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap:12px;}
.vm{
  border:1px solid var(--stroke); border-radius:16px; padding:14px; background:#0e1530cc; backdrop-filter:var(--glass);
  transition:.15s; position:relative;
}
.vm:hover{transform:translateY(-2px); border-color:#3a4d86}
.vm .vm-name{font-weight:700; font-size:16px}
.tag{display:inline-block; font-size:11px; padding:3px 8px; border-radius:10px; border:1px solid #2b375a; color:#a7b2d9; margin-top:6px}

.vm-header{display:flex; align-items:center; gap:10px; justify-content:space-between}
.iconbar{margin-left:auto; display:flex; gap:8px}
.iconbtn{
  border:1px solid var(--stroke); background:#0e1430; border-radius:10px;
  padding:6px 8px; cursor:pointer; transition:.15s;
}
.iconbtn:hover{border-color:#3a4d86; transform:translateY(-1px)}
.iconbtn[disabled]{opacity:.5; cursor:not-allowed; transform:none}
.vm-meta{margin-top:6px; display:flex; gap:6px; flex-wrap:wrap}

/* Modal générique */
.modal{position:fixed; inset:0; display:none; align-items:center; justify-content:center; padding:24px; z-index:60;}
.modal.open{display:flex}
.backdrop{position:absolute; inset:0; background:#0008; backdrop-filter: blur(8px); animation: fadeIn .15s ease;}
@keyframes fadeIn{from{opacity:0}to{opacity:1}}
/* === Modales : structure scrollable === */
.dialog{
  position:relative;
  width:min(920px, 100%);
  border:1px solid var(--stroke);
  border-radius:20px;
  background:linear-gradient(180deg, #101534ee, #0c1230e6);
  box-shadow: 0 30px 80px #000a, inset 0 0 0 1px #ffffff10;
  transform: scale(0.96);
  animation: pop .15s ease forwards;
  z-index:1;

  /* 🆕 rendre la popup “flex” et bornée en hauteur */
  display:flex;
  flex-direction:column;
  max-height: 88vh;       /* garde de l’air pour les bords */
  overflow:hidden;        /* header/footer fixes, contenu scrolle */
}

.dialog header{
  display:flex; align-items:center; justify-content:space-between;
  padding:16px; border-bottom:1px solid #22304f;
  flex:0 0 auto;          /* ne pas scroller */
}

.dialog .content{
  padding:16px;
  flex:1 1 auto;          /* 🆕 occupe l’espace restant */
  overflow:auto;          /* 🆕 active le scroll interne */
  min-height: 0;          /* 🆕 nécessaire pour que overflow marche en flex */
}

.actions-row{
  display:flex; justify-content:space-between; gap:10px;
  padding:12px 16px; border-top:1px solid #22304f;
  flex:0 0 auto;          /* ne pas scroller */
}
.steps{display:flex; gap:8px; flex-wrap:wrap; margin-bottom:12px}
.step{font-size:12px; padding:6px 10px; border-radius:999px; border:1px solid #2b375a; color:#9fb0dc; opacity:.6}
.step.active{opacity:1; color:#e6ebff; border-color:#4a61a3; box-shadow: inset 0 0 0 1px #ffffff12}
.form-row{display:grid; grid-template-columns:1fr 1fr; gap:12px}
label{font-size:13px; color:#c9d3ff}
select,input,textarea{
  width:100%; background:#0a1030; color:var(--fg); border:1px solid #2a3555; border-radius:12px; padding:10px 12px; outline:none;
}
textarea{min-height:120px; resize:vertical}
.helper{font-size:12px; color:#94a3c7; margin-top:6px}
.actions-row{display:flex; justify-content:space-between; gap:10px; padding:12px 16px; border-top:1px solid #22304f}

/* Console modal specific */
.console .dialog{ height:min(80vh, 820px); display:flex; flex-direction:column; }
.console .dialog .content{ padding:0; flex:1; overflow:hidden }
.console iframe{ border:0; width:100%; height:100%; background:#000 }

/* Toast */
.toast{
  position:fixed; bottom:72px; right:18px; background:#0a1128; border:1px solid #2a3555; color:#dfe6ff; padding:12px 14px; border-radius:12px; display:none; z-index:70;
}
.toast.show{display:block}
.badge{font-size:11px; padding:2px 7px; border-radius:10px; border:1px solid #3a4d86; margin-left:6px}

/* Footer */
.footer { position: fixed; left:0; right:0; bottom:0; z-index:50;
  display:flex; align-items:center; gap:12px; padding:10px 16px;
  background:#0f1328cc; backdrop-filter:blur(10px);
  border-top:1px solid var(--stroke); box-shadow:0 -10px 30px #00000040, inset 0 1px 0 #ffffff10;
}
.footer .left,.footer .right{display:flex; align-items:center; gap:8px; flex-wrap:wrap}
.footer .center{flex:1; text-align:center; font-size:12px; color:#a7b2d9}
.footer .pill{font-size:12px; padding:6px 10px; border-radius:12px; border:1px solid #2b375a; color:#a7b2d9}
body{padding-bottom:62px;}

@media (max-width: 900px){
  .form-row{grid-template-columns:1fr}
}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div class="brand">
      <div class="logo"></div>
      <div class="title">VHI Web Manager <span class="badge" id="proj"></span></div>
    </div>
    <div class="actions">
      <button class="btn" id="btnRefresh">Rafraîchir</button>
      <button class="btn" id="btnFip"><span>⚡ IP flottantes</span></button>
      <button class="btn" id="btnNetworks"><span>🛠 Réseaux</span></button>
      <button class="btn primary" id="btnCreate"><span>+ Créer une VM</span></button>
    </div>
  </div>

  <div class="grid">
    <div class="card" id="cardStats">
      <h3>Tableau de bord</h3>
      <div class="row" id="kpis"></div>
    </div>

    <div class="card">
      <h3>Mes VMs</h3>
      <div class="vm-list" id="vmList"></div>
    </div>
  </div>
</div>

<!-- Wizard Create -->
<div class="modal" id="wizard">
  <div class="backdrop" onclick="closeWizard()"></div>
  <div class="dialog">
    <header>
      <h3>Assistant de création</h3>
      <button class="btn" onclick="closeWizard()">Fermer</button>
    </header>
    <div class="content">
      <div class="steps" id="wSteps"></div>
      <div id="wBody"></div>
    </div>
    <div class="actions-row">
      <div><button class="btn" onclick="prevStep()" id="btnPrev">← Précédent</button></div>
      <div style="display:flex; gap:10px">
        <button class="btn" onclick="cancelWizard()">Annuler</button>
        <button class="btn primary" onclick="nextStep()" id="btnNext"><span>Suivant</span></button>
      </div>
    </div>
  </div>
</div>

<!-- Console modal -->
<div class="modal console" id="consoleModal">
  <div class="backdrop" onclick="closeConsole()"></div>
  <div class="dialog">
    <header>
      <h3 id="consoleTitle">Console</h3>
      <div style="display:flex; gap:8px">
        <button class="btn" onclick="openConsoleNewTab()">Ouvrir dans un onglet</button>
        <button class="btn" onclick="closeConsole()">Fermer</button>
      </div>
    </header>
    <div class="content">
      <iframe id="consoleFrame" src="about:blank"></iframe>
    </div>
  </div>
</div>

<!-- Floating IPs modal -->
<div class="modal" id="fipModal">
  <div class="backdrop" onclick="closeFipModal()"></div>
  <div class="dialog">
    <header>
      <h3>IP flottantes</h3>
      <div style="display:flex; gap:8px">
        <button class="btn" onclick="closeFipModal()">Fermer</button>
      </div>
    </header>
    <div class="content">
      <div id="fipList" style="display:grid; gap:8px"></div>
      <hr style="border-color:#22304f; opacity:.5; margin:14px 0" />
      <div class="form-row">
        <div>
          <label>Allouer une nouvelle FIP (réseau externe)</label>
          <div style="display:flex; gap:8px">
            <select id="fip_alloc_net"></select>
            <button class="btn" onclick="allocateFip()">Allouer</button>
          </div>
          <div class="helper">Choisis un réseau marqué <code>router:external</code>.</div>
        </div>
        <div>
          <label>Attribuer une FIP existante</label>
          <div style="display:grid; gap:8px">
            <select id="fip_assign_id"></select>
            <select id="fip_assign_vm"></select>
            <select id="fip_assign_port"></select>
            <button class="btn primary" onclick="doAssignFip()"><span>Attribuer</span></button>
          </div>
          <div class="helper">1) FIP non assignée → 2) VM → 3) Port de la VM.</div>
        </div>
      </div>
    </div>
  </div>
</div>

<!-- Networks modal -->
<div class="modal" id="netModal">
  <div class="backdrop" onclick="closeNetModal()"></div>
  <div class="dialog">
    <header>
      <h3>Réseaux & Sous-réseaux</h3>
      <div style="display:flex; gap:8px">
        <button class="btn" id="btnNetToggleForm">Créer un réseau</button>
        <button class="btn" onclick="closeNetModal()">Fermer</button>
      </div>
    </header>
    <div class="content">
      <!-- Form création réseau: caché par défaut, toggle par bouton -->
      <div id="netCreatePanel" style="display:none; border:1px solid var(--stroke); border-radius:12px; padding:12px; margin-bottom:12px; background:#0e1530cc;">
        <div class="form-row">
          <div>
            <label>Nom du réseau</label>
            <input id="net_new_name" placeholder="ex: private-net" />
          </div>
          <div>
            <label>CIDR IPv4</label>
            <input id="net_new_cidr" placeholder="ex: 192.168.50.0/24" />
          </div>
        </div>
        <div class="form-row">
          <div>
            <label>Gateway IPv4 (laisser vide = aucune)</label>
            <input id="net_new_gw" placeholder="ex: 192.168.50.1" />
          </div>
          <div>
            <label>DHCP</label>
            <select id="net_new_dhcp">
              <option value="on" selected>Activé</option>
              <option value="off">Désactivé</option>
            </select>
          </div>
        </div>
        <div class="form-row">
          <div>
            <label>Pool DHCP start</label>
            <input id="net_new_pool_start" placeholder="ex: 192.168.50.100" />
          </div>
          <div>
            <label>Pool DHCP end</label>
            <input id="net_new_pool_end" placeholder="ex: 192.168.50.200" />
          </div>
        </div>
        <div class="form-row">
          <div>
            <label>DNS servers (séparés par des virgules)</label>
            <input id="net_new_dns" placeholder="1.1.1.1,8.8.8.8" />
          </div>
          <div style="display:flex; align-items:flex-end">
            <button class="btn primary" onclick="createNetwork()"><span>Créer le réseau</span></button>
          </div>
        </div>
        <div class="helper">Remarque: le réseau est créé puis un subnet IPv4 y est attaché avec les paramètres ci-dessus.</div>
      </div>

      <div id="netList" style="display:grid; gap:10px"></div>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<!-- Footer -->
<div class="footer">
  <div class="left">
    <span class="pill">Mastere CIA2IF - Lycée jules fils 2025</span>
  </div>
  <div class="center"></div>
  <div class="right">
     <span class="pill">Solution VHI déployée par Evan IA</span>
  </div>
</div>

<script>
/* ---------- utils DOM ---------- */
const qs  = (s, el=document)=>el.querySelector(s);
const qsa = (s, el=document)=>Array.from(el.querySelectorAll(s));
function toast(msg, ms=2500){ const t=qs('#toast'); t.textContent=msg; t.classList.add('show'); setTimeout(()=>t.classList.remove('show'), ms); }
function esc(s){ return (s??"").toString().replace(/[&<>"']/g, m=>({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m])); }

async function api(action, payload){
  const opt = payload ? { method: "POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(payload)} : {};
  const r = await fetch(`?api=${encodeURIComponent(action)}`, opt);
  return r.json();
}

/* ---------- status -> emoji ---------- */
function statusIcon(st){
  switch (st) {
    case "ACTIVE": return "🟢";
    case "SHUTOFF":
    case "STOPPED": return "🔴";
    case "BUILD":
    case "REBUILD":
    case "RESIZE":
    case "VERIFY_RESIZE":
    case "MIGRATING": return "🟡";
    case "PAUSED":
    case "SUSPENDED": return "🟠";
    case "ERROR": return "🔺";
    case "SHELVED":
    case "SHELVED_OFFLOADED": return "⚪";
    default: return "⚫";
  }
}

/* ========= INIT ========= */
async function init(){
  try{
    const r = await api("auth");
    if(!r.ok) throw new Error(r.error||"Auth KO");
    qs('#proj').textContent = "Projet "+(r.project_id||"");
    await refreshAll();

    const o = await api("list_options");
    if(o.ok){
      window._opts = { images:o.images||[], flavors:o.flavors||[], networks:o.networks||[] };
    }
    const x = await api("extra_options");
    if(x.ok){
      window._extra = {
        secgroups: x.secgroups||[],
        keypairs : x.keypairs ||[],
        volume_types: x.volume_types ||[]
      };
    }
  }catch(e){ toast("Erreur d’init: "+e.message, 4000); }
}
async function refreshAll(){ await Promise.all([loadStats(), loadVMs()]); }
async function loadStats(){
  const r = await api("stats");
  const k = qs('#kpis'); k.innerHTML = "";
  if(!r.ok){ k.innerHTML = `<div class="kpi"><div class="label">Erreur</div><div class="value">-</div></div>`; return; }
  const s = r.data||{};
  const items = [
    ["VMs", s.vm_count ?? "—"],
    ["vCPU", (s.cores_used!=null ? `${s.cores_used} / ${s.cores_max??"?"}` : "—")],
    ["RAM (MB)", (s.ram_used!=null ? `${s.ram_used} / ${s.ram_max??"?"}` : "—")],
    ["Volumes", (s.vol_count!=null ? `${s.vol_count} — ${s.vol_size_gb??0} GiB` : "—")],
    ["Floating IPs", (s.fip_total!=null ? `${s.fip_associated} / ${s.fip_total}` : "—")],
  ];
  items.forEach(([label,val])=>{
    k.insertAdjacentHTML('beforeend', `<div class="kpi"><div class="label">${esc(label)}</div><div class="value">${esc(val)}</div></div>`);
  });
}

/* ========= VMs list + actions ========= */
function vmCard(s){
  const id = esc(s.id);
  const name = esc(s.name||id);
  const statusRaw = (s.status||"?").toUpperCase();
  const icon = statusIcon(statusRaw);

  // IPs privées
  let privIPs = [];
  try{
    const addr = s.addresses||{};
    Object.keys(addr).forEach(nw=>{
      (addr[nw]||[]).forEach(a=>{ if(a.addr && (a["OS-EXT-IPS:type"]!=="floating")) privIPs.push(a.addr); });
    });
  }catch{}
  const ipstr = privIPs.length? privIPs.join(", "): "—";

  const flavor = s.flavor_info?.name || s.flavor?.original_name || s.flavor?.name || "—";
  const iface  = s.primary_net || "—";
  const fip    = (s.floating_ips && s.floating_ips.length) ? s.floating_ips.join(", ") : "—";

  const isActive = (statusRaw === "ACTIVE");
  const isShut   = (statusRaw === "SHUTOFF" || statusRaw === "STOPPED");
  const isBuild  = ["BUILD","REBUILD","RESIZE","VERIFY_RESIZE","MIGRATING"].includes(statusRaw);

  return `<div class="vm">
    <div class="vm-header">
      <div class="vm-name">${name}</div>
      <div class="iconbar">
        <button class="iconbtn" title="Start" ${isActive||isBuild?'disabled':''} onclick="vmAction('${id}','start','${name}')">▶️</button>
        <button class="iconbtn" title="Reboot (soft)" ${isBuild?'disabled':''} onclick="vmAction('${id}','reboot_soft','${name}')">🔄</button>
        <button class="iconbtn" title="Stop" ${isShut||isBuild?'disabled':''} onclick="vmAction('${id}','stop','${name}')">⏹️</button>
        <button class="iconbtn" title="Console" ${isBuild?'disabled':''} onclick="openConsole('${id}','${name}')">🖥️</button>
        <button class="iconbtn" title="Snapshot" ${isBuild?'disabled':''} onclick="vmSnapshot('${id}','${name}')">📸</button>
        <button class="iconbtn" title="Supprimer" ${isBuild?'disabled':''} onclick="confirmDelete('${id}','${name}')">🗑️</button>
      </div>
    </div>

    <div class="vm-meta">
      <span class="tag status-emoji" title="${esc(statusRaw)}">Status&nbsp;: ${icon}</span>
      <span class="tag">IP: ${esc(ipstr)}</span>
      <span class="tag">Flavor: ${esc(flavor)}</span>
      <span class="tag">Interface: ${esc(iface)}</span>
      <span class="tag">FIP: ${esc(fip)}</span>
    </div>
  </div>`;
}

async function loadVMs(){
  const list = qs('#vmList'); list.innerHTML = "";
  const r = await api("list_servers");
  if(!r.ok){ list.innerHTML = "<div>Erreur de chargement.</div>"; return; }
  const V = r.data||[];
  if(!V.length){ list.innerHTML = "<div>Aucune VM.</div>"; return; }
  V.forEach(s=> list.insertAdjacentHTML('beforeend', vmCard(s)));
}
function confirmDelete(id, name){
  if (!confirm(`Supprimer la VM "${name}" ?`)) return;
  deleteVM(id);
}
async function deleteVM(id){
  const r = await api("delete_vm", {server_id:id});
  if(r.ok){ toast("Suppression demandée"); await loadVMs(); await loadStats(); }
  else { toast("Erreur suppression: "+(r.error||"")); }
}
async function vmAction(id, action, name){
  const r = await api("vm_action", {server_id:id, action});
  if(r.ok){
    toast(`${action.replace('_',' ')} demandé sur "${name}"`);
    await loadVMs(); await loadStats();
  }else{
    toast(`Erreur action ${action}: `+(r.error||""), 4000);
  }
}
async function vmSnapshot(id, name){
  const snap = prompt(`Nom du snapshot pour "${name}" :`, `${name}-snap-${new Date().toISOString().slice(0,19).replace(/[:T]/g,'')}`);
  if(!snap) return;
  const r = await api("vm_snapshot", {server_id:id, name:snap});
  if(r.ok){ toast(`Snapshot demandé: ${snap}`); }
  else{ toast("Erreur snapshot: "+(r.error||""), 4000); }
}

// ========= Console via portail externe (nouvel onglet uniquement) =========
const CONSOLE_BASE = "https://vhi-panel.ataraxie.fr:8800/compute/servers/instances/";

function buildConsoleUrl(instanceId){
  return `${CONSOLE_BASE}${encodeURIComponent(instanceId)}/console`;
}

// Appelée par le bouton 🖥️ de chaque VM
async function openConsole(id, name){
  const url = buildConsoleUrl(id);
  try {
    // 1) tentative nouvel onglet
    const win = window.open(url, "_blank", "noopener");
    if (!win || win.closed) {
      // 2) fallback si pop-up bloquée : on crée un <a> invisible et on simule un clic
      const a = document.createElement("a");
      a.href = url;
      a.target = "_blank";
      a.rel = "noopener";
      document.body.appendChild(a);
      a.click();
      a.remove();
    }
    toast("La console s’ouvre dans un nouvel onglet (l’iframe est bloquée par l’hôte).");
  } catch (e) {
    // 3) dernier recours : on copie l’URL et on informe
    try { await navigator.clipboard.writeText(url); } catch {}
    toast("Impossible d’ouvrir une pop-up. L’URL de console a été copiée dans le presse-papiers.");
  }
}

// Garde ces stubs pour éviter des appels résiduels ailleurs
function closeConsole(){ /* plus de modale à fermer */ }
function openConsoleNewTab(){ /* déjà géré dans openConsole */ }

function closeConsole(){
  const ifr = qs('#consoleFrame');
  try{ ifr.src = 'about:blank'; }catch{}
  _consoleURL = null;
  clearTimeout(_consoleFallbackTimer);
  qs('#consoleModal').classList.remove('open');
}

function openConsoleNewTab(){
  if(_consoleURL) window.open(_consoleURL, "_blank");
}

/* ========= Floating IPs ========= */
let _fipCache = { fips:[], networks:[], servers:[] };

function openFipModal(){
  qs('#fipModal').classList.add('open');
  loadFipsUI();
}
function closeFipModal(){
  qs('#fipModal').classList.remove('open');
}

async function loadFipsUI(){
  try{
    const [fipsResp, netsResp, svResp] = await Promise.all([
      api("fip_list"),
      api("list_options"),
      api("list_servers")
    ]);
    if(!fipsResp.ok) throw new Error(fipsResp.error||"fip_list ko");
    if(!netsResp.ok) throw new Error(netsResp.error||"list_options ko");
    if(!svResp.ok) throw new Error(svResp.error||"list_servers ko");

    _fipCache.fips = fipsResp.data || [];
    _fipCache.networks = (netsResp.networks||[]);
    _fipCache.servers = (svResp.data||[]);

    const cont = qs('#fipList'); cont.innerHTML="";
    if(!_fipCache.fips.length){
      cont.innerHTML = `<div class="helper">Aucune IP flottante.</div>`;
    }else{
      _fipCache.fips.forEach(f=>{
        const row = document.createElement('div');
        row.style.border = "1px solid var(--stroke)";
        row.style.borderRadius = "12px";
        row.style.padding = "10px";
        row.style.background = "#0e1530cc";

        const status = f.status || "UNKNOWN";
        const netName = f.network_name || f.floating_network_id || "—";
        const vm = f.vm_name || "—";
        const fixed = f.fixed_ip_address || "—";
        const assigned = !!f.port_id;

        row.innerHTML = `
          <div style="display:flex; justify-content:space-between; gap:8px; align-items:center; flex-wrap:wrap">
            <div style="display:flex; gap:12px; align-items:center; flex-wrap:wrap">
              <span class="tag">FIP: ${esc(f.floating_ip_address)}</span>
              <span class="tag">Statut: ${esc(status)}</span>
              <span class="tag">Réseau: ${esc(netName)}</span>
              <span class="tag">VM: ${esc(vm)}</span>
              <span class="tag">Fixed IP: ${esc(fixed)}</span>
            </div>
            <div style="display:flex; gap:8px">
              ${assigned
                ? `<button class="btn" onclick="disassociateFip('${esc(f.id)}')">Détacher</button>
                   <button class="btn" onclick="releaseFip('${esc(f.id)}')">Libérer</button>`
                : `<button class="btn" onclick="prefillAssign('${esc(f.id)}')">Attribuer…</button>
                   <button class="btn" onclick="releaseFip('${esc(f.id)}')">Libérer</button>`
              }
            </div>
          </div>`;
        cont.appendChild(row);
      });
    }

    const selNet = qs('#fip_alloc_net');
    selNet.innerHTML = "";
    _fipCache.networks
      .filter(n => n["router:external"] === true || n.router_external === true)
      .forEach(n=>{
        selNet.insertAdjacentHTML('beforeend', `<option value="${esc(n.id)}">${esc(n.name||n.id)}</option>`);
      });

    const selFip = qs('#fip_assign_id');
    selFip.innerHTML = "";
    const unbound = _fipCache.fips.filter(f => !f.port_id);
    if(unbound.length){
      unbound.forEach(f=>{
        selFip.insertAdjacentHTML('beforeend', `<option value="${esc(f.id)}">${esc(f.floating_ip_address)}</option>`);
      });
    }else{
      selFip.insertAdjacentHTML('beforeend', `<option value="">(aucune FIP libre)</option>`);
    }

    const selVm = qs('#fip_assign_vm');
    selVm.innerHTML = "";
    _fipCache.servers.forEach(s=>{
      selVm.insertAdjacentHTML('beforeend', `<option value="${esc(s.id)}">${esc(s.name||s.id)}</option>`);
    });

    selVm.onchange = updatePortsForSelectedVm;
    await updatePortsForSelectedVm();

  }catch(e){
    toast("Erreur chargement FIPs: "+e.message, 4000);
  }
}

function prefillAssign(fipId){
  const selFip = qs('#fip_assign_id');
  if(!selFip) return;
  selFip.value = fipId;
  qs('#fip_assign_vm').focus();
}
async function updatePortsForSelectedVm(){
  const vmId = qs('#fip_assign_vm').value;
  const selPort = qs('#fip_assign_port');
  selPort.innerHTML = `<option>(chargement...)</option>`;
  try{
    const r = await api("ports_by_server", {server_id: vmId});
    selPort.innerHTML = "";
    if(r.ok && Array.isArray(r.data) && r.data.length){
      r.data.forEach(p=>{
        const label = `${p.ip || "?"} — ${p.network_name || p.network_id} (${p.id.slice(0,8)})`;
        selPort.insertAdjacentHTML('beforeend', `<option value="${esc(p.id)}">${esc(label)}</option>`);
      });
    }else{
      selPort.insertAdjacentHTML('beforeend', `<option value="">(aucun port)</option>`);
    }
  }catch(e){
    selPort.innerHTML = `<option value="">(erreur ports)</option>`;
  }
}
async function allocateFip(){
  const netId = qs('#fip_alloc_net').value;
  if(!netId){ toast("Choisis un réseau externe."); return; }
  const r = await api("fip_allocate", {floating_network_id: netId});
  if(r.ok){ toast("FIP allouée"); loadFipsUI(); }
  else{ toast("Erreur allocation: "+(r.error||""), 4000); }
}
async function doAssignFip(){
  const fipId = qs('#fip_assign_id').value;
  const portId = qs('#fip_assign_port').value;
  if(!fipId || !portId){ toast("Sélectionne FIP + VM + Port"); return; }
  const r = await api("fip_associate", {fip_id:fipId, port_id:portId});
  if(r.ok){ toast("FIP attribuée"); loadFipsUI(); }
  else{ toast("Erreur attribution: "+(r.error||""), 4000); }
}
async function disassociateFip(fipId){
  if(!confirm("Détacher cette FIP ?")) return;
  const r = await api("fip_disassociate", {fip_id:fipId});
  if(r.ok){ toast("FIP détachée"); loadFipsUI(); }
  else{ toast("Erreur détachement: "+(r.error||""), 4000); }
}
async function releaseFip(fipId){
  if(!confirm("Libérer (supprimer) cette FIP ?")) return;
  const r = await api("fip_release", {fip_id:fipId});
  if(r.ok){ toast("FIP libérée"); loadFipsUI(); }
  else{ toast("Erreur libération: "+(r.error||""), 4000); }
}

/* ========= Réseaux/Subnets ========= */
let _netCache = { nets:[], subs:[] };

function openNetModal(){
  qs('#netModal').classList.add('open');
  loadNetworksUI();
}
function closeNetModal(){
  qs('#netModal').classList.remove('open');
}
qs('#btnNetToggleForm').addEventListener('click', ()=>{
  const p = qs('#netCreatePanel');
  if (!p) return;
  p.style.display = (p.style.display === 'none' || p.style.display === '') ? 'block' : 'none';
});

async function loadNetworksUI(){
  try{
    const [n, s] = await Promise.all([api("net_list"), api("subnet_list")]);
    if(!n.ok) throw new Error(n.error||"net_list ko");
    if(!s.ok) throw new Error(s.error||"subnet_list ko");
    _netCache.nets = n.data || [];
    _netCache.subs = s.data || [];

    const byNet = {};
    _netCache.subs.forEach(sub=>{
      const nid = sub.network_id;
      if(!byNet[nid]) byNet[nid] = [];
      byNet[nid].push(sub);
    });

    const cont = qs('#netList'); cont.innerHTML = "";
    if(!_netCache.nets.length){
      cont.innerHTML = `<div class="helper">Aucun réseau.</div>`;
      return;
    }

    _netCache.nets.forEach(net=>{
      const netBox = document.createElement('div');
      netBox.style.border = "1px solid var(--stroke)";
      netBox.style.borderRadius = "12px";
      netBox.style.padding = "12px";
      netBox.style.background = "#0e1530cc";

      const subs = byNet[net.id] || [];

      let subsHtml = "";
      if(!subs.length){
        subsHtml = `<div class="helper">Aucun subnet.</div>`;
      } else {
        subs.forEach(sub=>{
          const dns = (sub.dns_nameservers||[]).join(", ") || "—";
          const pools = (sub.allocation_pools||[]).map(p=>`${p.start} → ${p.end}`).join(" | ") || "—";
          const gw = (sub.gateway_ip ?? "—");
          const dhcp = sub.enable_dhcp ? "ON" : "OFF";

          subsHtml += `
          <div style="border:1px dashed #2a3555; border-radius:10px; padding:10px; margin-top:8px">
            <div style="display:flex; justify-content:space-between; gap:8px; align-items:center; flex-wrap:wrap">
              <div style="display:flex; gap:8px; flex-wrap:wrap">
                <span class="tag">Subnet: ${esc(sub.name || sub.id)}</span>
                <span class="tag">CIDR: ${esc(sub.cidr)}</span>
                <span class="tag">Gateway: ${esc(gw)}</span>
                <span class="tag">DHCP: ${esc(dhcp)}</span>
                <span class="tag">Pools: ${esc(pools)}</span>
                <span class="tag">DNS: ${esc(dns)}</span>
              </div>
              <div style="display:flex; gap:8px">
                <button class="btn" onclick='openEditSubnet("${esc(sub.id)}")'>Éditer</button>
                <button class="btn" onclick='deleteSubnet("${esc(sub.id)}')">Supprimer</button>
              </div>
            </div>
            <div id="edit_${esc(sub.id)}" style="display:none; margin-top:10px">
              <div class="form-row">
                <div>
                  <label>Gateway IPv4 (vide = none)</label>
                  <input id="e_gw_${esc(sub.id)}" value="${esc(sub.gateway_ip||'')}" />
                </div>
                <div>
                  <label>DHCP</label>
                  <select id="e_dhcp_${esc(sub.id)}">
                    <option value="on" ${sub.enable_dhcp?'selected':''}>Activé</option>
                    <option value="off" ${!sub.enable_dhcp?'selected':''}>Désactivé</option>
                  </select>
                </div>
              </div>
              <div class="form-row">
                <div>
                  <label>Pool start</label>
                  <input id="e_pool_s_${esc(sub.id)}" value="${esc(sub.allocation_pools?.[0]?.start || '')}" />
                </div>
                <div>
                  <label>Pool end</label>
                  <input id="e_pool_e_${esc(sub.id)}" value="${esc(sub.allocation_pools?.[0]?.end || '')}" />
                </div>
              </div>
              <div class="form-row">
                <div>
                  <label>DNS servers (virgules)</label>
                  <input id="e_dns_${esc(sub.id)}" value="${esc((sub.dns_nameservers||[]).join(', '))}" />
                </div>
                <div style="display:flex; align-items:flex-end">
                  <button class="btn primary" onclick='saveSubnet("${esc(sub.id)}")'><span>Enregistrer</span></button>
                </div>
              </div>
              <div class="helper">Le CIDR ne peut pas être modifié (neutron). Pour changer le CIDR, supprime et recrée le subnet.</div>
            </div>
          </div>`;
        });
      }

      const extBadge = (net["router:external"] || net.router_external) ? `<span class="tag">Externe</span>` : "";
      netBox.innerHTML = `
        <div style="display:flex; justify-content:space-between; gap:8px; align-items:center; flex-wrap:wrap">
          <div style="display:flex; gap:10px; flex-wrap:wrap; align-items:center">
            <span class="tag">Réseau: ${esc(net.name || net.id)}</span>
            <span class="tag">ID: ${esc(net.id)}</span>
            ${extBadge}
            <span class="tag">Admin: ${net.admin_state_up ? 'UP' : 'DOWN'}</span>
            <span class="tag">Partagé: ${(net.shared ? 'Oui' : 'Non')}</span>
          </div>
          <div style="display:flex; gap:8px">
            <button class="btn" onclick='deleteNetwork("${esc(net.id)}")'>Supprimer réseau</button>
          </div>
        </div>
        <div style="margin-top:8px">${subsHtml}</div>
      `;
      cont.appendChild(netBox);
    });

  }catch(e){
    toast("Erreur chargement réseaux: "+e.message, 4000);
  }
}

function openEditSubnet(id){
  const el = qs('#edit_'+CSS.escape(id));
  if(!el) return;
  el.style.display = (el.style.display==='none' || el.style.display==='') ? 'block' : 'none';
}
async function saveSubnet(id){
  const gw = qs('#e_gw_'+CSS.escape(id)).value.trim();
  const dhcp = qs('#e_dhcp_'+CSS.escape(id)).value === 'on';
  const ps = qs('#e_pool_s_'+CSS.escape(id)).value.trim();
  const pe = qs('#e_pool_e_'+CSS.escape(id)).value.trim();
  const dns = qs('#e_dns_'+CSS.escape(id)).value.split(',').map(s=>s.trim()).filter(Boolean);

  const payload = {
    subnet_id: id,
    gateway: gw, // "" => aucune
    enable_dhcp: dhcp,
    pool_start: ps,
    pool_end: pe,
    dns
  };
  const r = await api("subnet_update", payload);
  if(r.ok){ toast("Subnet mis à jour"); loadNetworksUI(); }
  else { toast("Erreur update subnet: "+(r.error||""), 4000); }
}
async function deleteSubnet(id){
  if(!confirm("Supprimer ce subnet ?")) return;
  const r = await api("subnet_delete", {subnet_id:id});
  if(r.ok){ toast("Subnet supprimé"); loadNetworksUI(); }
  else { toast("Erreur suppression subnet: "+(r.error||""), 4000); }
}
async function deleteNetwork(id){
  if(!confirm("Supprimer ce réseau ? (doit être vide)")) return;
  const r = await api("net_delete", {network_id:id});
  if(r.ok){ toast("Réseau supprimé"); loadNetworksUI(); }
  else { toast("Erreur suppression réseau: "+(r.error||""), 4000); }
}
async function createNetwork(){
  const name = qs('#net_new_name').value.trim();
  const cidr = qs('#net_new_cidr').value.trim();
  const gw   = qs('#net_new_gw').value.trim();
  const dhcp = (qs('#net_new_dhcp').value === 'on');
  const ps   = qs('#net_new_pool_start').value.trim();
  const pe   = qs('#net_new_pool_end').value.trim();
  const dns  = qs('#net_new_dns').value.split(',').map(s=>s.trim()).filter(Boolean);

  if(!name || !cidr){ toast("Nom et CIDR requis"); return; }

  const payload = {
    name, cidr, gateway: gw,
    enable_dhcp: dhcp,
    pool_start: ps, pool_end: pe,
    dns
  };
  const r = await api("net_create", payload);
  if(r.ok){
    toast("Réseau créé");
    qs('#net_new_name').value = "";
    qs('#net_new_cidr').value = "";
    qs('#net_new_gw').value   = "";
    qs('#net_new_dhcp').value = "on";
    qs('#net_new_pool_start').value = "";
    qs('#net_new_pool_end').value   = "";
    qs('#net_new_dns').value = "";
    loadNetworksUI();
  } else {
    toast("Erreur création réseau: "+(r.error||""), 4000);
  }
}

/* ========= Wizard ========= */
const steps = [
  { key:"basics",  label:"Général" },
  { key:"imageflavor", label:"Image & Flavor" },
  { key:"network", label:"Réseau" },
  { key:"security", label:"Sécurité" },
  { key:"access",  label:"Accès" },
  { key:"storage", label:"Stockage" },
  { key:"summary", label:"Récap" },
];
let w = null; let idx = 0;

function openWizard(){ resetWizard(); qs('#wizard').classList.add('open'); renderWizard(); }
function closeWizard(){ qs('#wizard').classList.remove('open'); }
function cancelWizard(){ closeWizard(); }
function resetWizard(){
  w = {
    name:"api-demo",
    image_id:null, flavor_id:null,
    network_id:null,
    ip_mode_dhcp:true, fixed_ip:"",
    secgroup_ids:[], spoofing:false,
    key_name:null,
    user_data:"",
    root_gb:null,
    volume_type:null
  };
  idx = 0;
}
function renderSteps(){
  const el = qs('#wSteps'); el.innerHTML = "";
  steps.forEach((s,i)=> el.insertAdjacentHTML('beforeend', `<div class="step ${i===idx?'active':''}">${esc(s.label)}</div>`));
}
function renderBody(){
  const b = qs('#wBody'); const o = (window._opts||{}); const x=(window._extra||{});
  b.innerHTML = "";
  if(steps[idx].key==="basics"){
    b.innerHTML = `
      <div class="form-row">
        <div><label>Nom de la VM</label><input id="w_name" value="${esc(w.name)}" /></div>
        <div>
          <label>Réseau</label>
          <select id="w_net">${(o.networks||[]).map(n=>`<option value="${esc(n.id)}" ${w.network_id===n.id?'selected':''}>${esc(n.name||n.id)}</option>`).join('')}</select>
          <div class="helper">Sélectionne le réseau principal (port créé automatiquement)</div>
        </div>
      </div>`;
  }
  if(steps[idx].key==="imageflavor"){
    b.innerHTML = `
      <div class="form-row">
        <div>
          <label>Image</label>
          <select id="w_img">${(o.images||[]).map(im=>`<option value="${esc(im.id)}" ${w.image_id===im.id?'selected':''}>${esc(im.name||im.id)} (${esc(im.visibility||'?')})</option>`).join('')}</select>
        </div>
        <div>
          <label>Flavor</label>
          <select id="w_flav">${(o.flavors||[]).map(f=>`<option value="${esc(f.id)}" ${w.flavor_id===f.id?'selected':''}>${esc(f.name)} — ${f.vcpus} vCPU / ${f.ram} MB / ${f.disk} GB</option>`).join('')}</select>
        </div>
      </div>`;
  }
  if(steps[idx].key==="network"){
    b.innerHTML = `
      <div class="form-row">
        <div>
          <label>Adressement</label>
          <select id="w_ipmode">
            <option value="dhcp" ${w.ip_mode_dhcp?'selected':''}>DHCP</option>
            <option value="static" ${!w.ip_mode_dhcp?'selected':''}>IP statique</option>
          </select>
        </div>
        <div>
          <label>IP fixe (si statique)</label>
          <input id="w_fixedip" placeholder="ex: 192.168.1.50" value="${esc(w.fixed_ip||'')}" />
        </div>
      </div>
      <div class="helper">Le port Neutron sera créé avec/ou sans IP fixe, et port_security selon tes choix.</div>`;
  }
  if(steps[idx].key==="security"){
    b.innerHTML = `
      <div class="form-row">
        <div>
          <label>Security Groups</label>
          <div id="w_sgs" style="display:grid; grid-template-columns:1fr 1fr; gap:6px; max-height:220px; overflow:auto; padding:8px; border:1px solid #2a3555; border-radius:12px;">
            ${(x.secgroups||[]).map(sg=>{
              const chk = (w.secgroup_ids||[]).includes(sg.id) ? "checked" : "";
              return `<label style="display:flex; gap:8px; align-items:center;">
                <input type="checkbox" value="${esc(sg.id)}" ${chk}/>
                <span>${esc(sg.name)}</span>
              </label>`;
            }).join('')}
          </div>
        </div>
        <div>
          <label>IP spoofing</label>
          <select id="w_spoof"><option value="off" ${!w.spoofing?'selected':''}>OFF (port_security ON)</option><option value="on" ${w.spoofing?'selected':''}>ON (désactive port_security)</option></select>
          <div class="helper">Si ON, le port sera créé avec <code>port_security_enabled=false</code>.</div>
        </div>
      </div>`;
  }
  if(steps[idx].key==="access"){
    b.innerHTML = `
      <div class="form-row">
        <div>
          <label>SSH Keypair</label>
          <select id="w_key">
            <option value="">(aucune)</option>
            ${(x.keypairs||[]).map(k=>`<option value="${esc(k)}" ${w.key_name===k?'selected':''}>${esc(k)}</option>`).join('')}
          </select>
        </div>
        <div>
          <label>Cloud-init (user-data YAML)</label>
          <textarea id="w_ud" placeholder="#cloud-config ...">${esc(w.user_data||'')}</textarea>
        </div>
      </div>`;
  }
  if(steps[idx].key==="storage"){
    const vtypes = (window._extra?.volume_types||[]);
    const fallback = [{id:"", name:"(par défaut)"},{id:"ssd", name:"ssd"}];
    const data = vtypes.length ? vtypes : fallback;
    b.innerHTML = `
      <div class="form-row">
        <div>
          <label>Taille volume root (GiB)</label>
          <input id="w_root" type="number" min="1" placeholder="vide = auto / flavor disk" value="${w.root_gb??''}"/>
          <div class="helper">Si renseigné ou flavor disk=0 → boot-from-volume auto.</div>
        </div>
        <div>
          <label>Type de volume</label>
          <select id="w_vtype">
            ${data.map(t=>`<option value="${esc(t.id)}" ${w.volume_type===t.id?'selected':''}>${esc(t.name||t.id||'(par défaut)')}</option>`).join('')}
          </select>
          <div class="helper">Choisis “ssd” si dispo côté Cinder (ou laisse “par défaut”).</div>
        </div>
      </div>`;
  }
  if(steps[idx].key==="summary"){
    const net = (window._opts?.networks||[]).find(n=>n.id===w.network_id);
    const img = (window._opts?.images||[]).find(i=>i.id===w.image_id);
    const flv = (window._opts?.flavors||[]).find(f=>f.id===w.flavor_id);
    const sgs = (window._extra?.secgroups||[]).filter(sg=> (w.secgroup_ids||[]).includes(sg.id)).map(sg=>sg.name).join(", ") || "(default)";
    b.innerHTML = `
      <div class="form-row">
        <div>
          <label>Nom</label><div class="helper">${esc(w.name)}</div>
          <label>Image</label><div class="helper">${esc(img?.name||w.image_id||"-")}</div>
          <label>Flavor</label><div class="helper">${esc(flv?.name||w.flavor_id||"-")}</div>
        </div>
        <div>
          <label>Réseau</label><div class="helper">${esc(net?.name||w.network_id||"-")}</div>
          <label>IP</label><div class="helper">${w.ip_mode_dhcp?"DHCP":("Statique: "+esc(w.fixed_ip||"-"))}</div>
          <label>SG</label><div class="helper">${esc(sgs)}</div>
        </div>
      </div>
      <div class="form-row" style="margin-top:8px">
        <div>
          <label>IP spoofing</label><div class="helper">${w.spoofing?"ON (port_security=OFF)":"OFF"}</div>
          <label>Keypair</label><div class="helper">${esc(w.key_name||"(aucune)")}</div>
        </div>
        <div>
          <label>Cloud-init</label><div class="helper">${w.user_data? "Oui" : "Non"}</div>
          <label>Root (GiB)</label><div class="helper">${w.root_gb??"(auto)"}</div>
          <label>Type de volume</label><div class="helper">${w.volume_type || "(par défaut)"}</div>
        </div>
      </div>`;
    qs('#btnNext').innerHTML = "<span>Créer la VM</span>";
  } else {
    qs('#btnNext').innerHTML = "<span>Suivant</span>";
  }
}
function renderWizard(){ renderSteps(); renderBody(); qs('#btnPrev').disabled = (idx===0); }
function prevStep(){ if(idx>0){ saveStep(); idx--; renderWizard(); } }
function nextStep(){
  if(steps[idx].key!=="summary"){
    if(!saveStep()) return;
    idx++; renderWizard();
  } else { submitWizard(); }
}
function saveStep(){
  const key = steps[idx].key;
  if(key==="basics"){
    const name = qs('#w_name').value.trim();
    const net  = qs('#w_net').value;
    if(!name || !net){ toast("Nom et réseau requis"); return false; }
    w.name = name; w.network_id = net;
  }
  if(key==="imageflavor"){
    const img  = qs('#w_img').value;
    const flav = qs('#w_flav').value;
    if(!img || !flav){ toast("Image et flavor requis"); return false; }
    w.image_id = img; w.flavor_id = flav;
  }
  if(key==="network"){
    const mode = qs('#w_ipmode').value;
    const ip   = qs('#w_fixedip').value.trim();
    w.ip_mode_dhcp = (mode==="dhcp");
    w.fixed_ip = w.ip_mode_dhcp ? "" : ip;
    if(!w.ip_mode_dhcp && !ip){ toast("IP fixe requise en mode statique"); return false; }
  }
  if(key==="security"){
    const box = qs('#w_sgs'); const ids=[];
    qsa('input[type="checkbox"]', box).forEach(c=>{ if(c.checked) ids.push(c.value); });
    w.secgroup_ids = ids;
    w.spoofing = (qs('#w_spoof').value==="on");
  }
  if(key==="access"){
    w.key_name = qs('#w_key').value || null;
    w.user_data = qs('#w_ud').value.trim();
  }
  if(key==="storage"){
    const v = qs('#w_root').value;
    w.root_gb = v ? parseInt(v,10) : null;
    const vt = qs('#w_vtype').value;
    w.volume_type = vt || null;
  }
  return true;
}
function toBase64(str){ return btoa(unescape(encodeURIComponent(str))); }
async function submitWizard(){
  const payload = {
    name: w.name,
    image_id: w.image_id,
    flavor_id: w.flavor_id,
    network_id: w.network_id,
    ip_mode_dhcp: !!w.ip_mode_dhcp,
    fixed_ip: w.ip_mode_dhcp ? null : (w.fixed_ip||null),
    secgroup_ids: w.secgroup_ids||[],
    spoofing: !!w.spoofing,
    root_gb: w.root_gb ?? null,
    volume_type: w.volume_type || null,
    key_name: w.key_name || null,
    user_data_b64: w.user_data ? toBase64(w.user_data) : null
  };
  qs('#btnNext').disabled = true;
  try{
    const r = await api("create_vm", payload);
    if(r.ok){ toast("VM création demandée"); closeWizard(); await loadVMs(); await loadStats(); }
    else { toast("Erreur création: "+(r.error||""), 4000); }
  } finally { qs('#btnNext').disabled = false; }
}

/* ========= Hooks ========= */
qs('#btnCreate').addEventListener('click', ()=> openWizard());
qs('#btnRefresh').addEventListener('click', ()=> refreshAll());
qs('#btnFip').addEventListener('click', ()=> openFipModal());
qs('#btnNetworks').addEventListener('click', ()=> openNetModal());

init();
</script>
</body>
</html>

