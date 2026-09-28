<?php
/**
 * aoi_signal.php  –  AOI 9.0 Buddy-Finder & WebRTC-Signaling
 * ============================================================
 * Kompatibel mit PHP 7.2+
 *
 * ZWECK
 * -----
 * Buddys finden sich hier. Danach spricht AOI 9.0 direkt P2P über WebRTC.
 * Dieser Server sieht nur: wer ist online und wer will mit wem verbinden.
 * Den Inhalt der Gespräche sieht er nie.
 *
 * AKTIONEN (POST mit JSON-Body)
 * ------------------------------
 *   info       – Selbsttest, kein Token nötig
 *   presence   – Herzschlag "Ich bin online", gibt Buddy-Liste zurück
 *   signal     – WebRTC SDP-Offer / SDP-Answer / ICE-Kandidat zustellen
 *   poll       – Eingangssignale abholen (Inbox wird danach geleert)
 *   bye        – Sauber abmelden (optional, TTL räumt sowieso auf)
 *
 * EINRICHTEN
 * ----------
 * 1. aoi_signal.php  hochladen
 * 2. .htaccess       hochladen (schützt aoi_data/)
 * 3. aoi_token.php   selbst anlegen – nur eine Zeile, kein PHP-Tag:
 *                    mein-geheimes-passwort-hier
 * 4. Das aoi_data/-Verzeichnis legt das Script beim ersten Aufruf selbst an.
 *
 * SELBSTTEST
 * ----------
 * GET-Anfrage an die URL -> gibt {"ok":true,"server":"AOI 9.0 Signal",...}
 */

header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, X-AOI-Token');
header('Cache-Control: no-store, no-cache');
header('X-Content-Type-Options: nosniff');

if (isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

define('DATEN_DIR',     __DIR__ . '/aoi_data');
define('PRESENCE_FILE',  DATEN_DIR . '/presence.php');
define('DIRECTORY_FILE', DATEN_DIR . '/directory.php');
define('INBOX_PREFIX',   DATEN_DIR . '/inbox_');
define('TOKEN_DATEI',   __DIR__ . '/aoi_token.php');
define('PRESENCE_TTL',  45);
define('SIGNAL_TTL',    120);
define('MAX_SIGNALE',   64);
define('MAX_NAME',      32);
define('MAX_SDP',       16384);
define('MAX_ICE',       2048);
define('MAX_BODY',      65536);
define('OFFLINE_PREFIX', DATEN_DIR . '/offline_');
define('PROFILE_PREFIX', DATEN_DIR . '/profile_');
define('ROOMS_FILE',     DATEN_DIR . '/rooms.php');
define('ROOM_PREFIX',    DATEN_DIR . '/room_');
define('OFFLINE_TTL',    604800);
define('MAX_OFFLINE',    50);
define('MAX_MSG_LEN',      2000);
define('MAX_ROOM_MEMBERS', 25);
define('ROOM_TTL',         7200);

/* ===== FEDERATION (Verteiltes AOI-Netz) ===== */
// Alle Server sind gleichberechtigt – kein Root-Zwang.
// FEDERATION_SEED = erster bekannter Server zum Netz-Beitritt (leer = keiner)
define('FEDERATION_ENABLED',   true);
define('FEDERATION_URL',       'https://innobytix-it.de/AOI_9/AOI_Treffpunkt/aoi_signal.php');
define('FEDERATION_SEED',      '');
define('FED_SERVERS_FILE',     DATEN_DIR . '/fed_servers.php');
define('FED_PRESENCE_FILE',    DATEN_DIR . '/fed_presence.php');
define('NOISE_CLIENTS_FILE',   DATEN_DIR . '/noise_clients.php');
define('NOISE_SERVER_FILE',    DATEN_DIR . '/noise_server.php');

/* ===== NOISE IK: Server-Keypair ===== */
function noise_server_keypair() {
    sicheres_daten_dir();
    if (is_file(NOISE_SERVER_FILE)) {
        $d = lies(NOISE_SERVER_FILE);
        if (!empty($d['priv']) && !empty($d['pub'])) return $d;
    }
    if (!function_exists('sodium_crypto_box_keypair')) return null;
    $kp   = sodium_crypto_box_keypair();
    $priv = sodium_crypto_box_secretkey($kp);
    $pub  = sodium_crypto_box_publickey($kp);
    $d = array('priv' => base64_encode($priv), 'pub' => base64_encode($pub));
    schreibe(NOISE_SERVER_FILE, $d);
    return $d;
}

$noise_res_key = null; // gesetzt nach erfolgreicher Noise-Entschlüsselung

function aoi_ok($daten = array()) {
    global $noise_res_key;
    $payload = array_merge(array('ok' => true), $daten);
    if ($noise_res_key !== null) {
        $json = json_encode($payload, JSON_UNESCAPED_UNICODE);
        $iv   = random_bytes(12);
        $tag  = '';
        $ct   = openssl_encrypt($json, 'aes-256-gcm', $noise_res_key, OPENSSL_RAW_DATA, $iv, $tag);
        echo json_encode(array('ok'=>true,'v'=>1,'iv'=>base64_encode($iv),'body'=>base64_encode($ct.$tag)));
    } else {
        echo json_encode($payload, JSON_UNESCAPED_UNICODE);
    }
    exit;
}

function aoi_fehler($text, $code = 400) {
    http_response_code($code);
    echo json_encode(array('ok' => false, 'fehler' => $text), JSON_UNESCAPED_UNICODE);
    exit;
}

function sicheres_daten_dir() {
    if (!is_dir(DATEN_DIR)) {
        @mkdir(DATEN_DIR, 0750, true);
        // .htaccess im Datenordner anlegen – schützt gegen Direktabruf
        $htaccess = DATEN_DIR . '/.htaccess';
        if (!is_file($htaccess)) {
            @file_put_contents($htaccess,
                "# AOI 9.0 – kein Direktzugriff\n" .
                "<IfModule mod_authz_core.c>\n  Require all denied\n</IfModule>\n" .
                "<IfModule !mod_authz_core.c>\n  Order deny,allow\n  Deny from all\n</IfModule>\n"
            );
        }
    }
}

function schreibe_atomar($ziel, $inhalt) {
    sicheres_daten_dir();
    $tmp = $ziel . '.' . bin2hex(random_bytes(4)) . '.tmp';
    if (@file_put_contents($tmp, $inhalt, LOCK_EX) === false) return false;
    if (!@rename($tmp, $ziel)) { @unlink($tmp); return false; }
    return true;
}

function lies($pfad) {
    if (!is_file($pfad)) return array();
    $roh = @file_get_contents($pfad);
    if ($roh === false || $roh === '') return array();
    if (strncmp($roh, "\xEF\xBB\xBF", 3) === 0) $roh = substr($roh, 3);
    $nl = strcspn($roh, "\r\n");
    if ($nl >= strlen($roh)) return array();
    $data = @json_decode(ltrim(substr($roh, $nl), "\r\n"), true);
    return is_array($data) ? $data : array();
}

function schreibe($pfad, $data) {
    return schreibe_atomar($pfad, "<?php exit; ?>\n" . json_encode($data, JSON_UNESCAPED_UNICODE));
}

function inbox_pfad($name) {
    return INBOX_PREFIX . substr(hash('sha256', strtolower($name)), 0, 16) . '.php';
}

function name_ok($name) {
    return strlen($name) >= 1 && strlen($name) <= MAX_NAME
        && preg_match('/^[a-zA-Z0-9_\-\.]+$/', $name) === 1;
}

function token_ok($eingabe) {
    if (!is_file(TOKEN_DATEI)) return true;
    $soll = trim((string)(@file_get_contents(TOKEN_DATEI) ?: ''));
    return $soll === '' || hash_equals($soll, $eingabe);
}

// HTTP-POST zu einem anderen Federation-Server (kein Token – Server-zu-Server)
// SSRF-Schutz: http:// und https:// erlaubt, keine privaten IPs.
// Bewusste Entscheidung: HTTPS-Pflicht würde kostenlose Webspaces (z.B. beplaced)
// ausschließen, die kein TLS anbieten. Der eigentliche SSRF-Schutz ist der
// private-IP-Check unten – nicht das Protokoll. WebRTC-Inhalte sind ohnehin
// immer E2E-verschlüsselt (DTLS/SRTP); lediglich Signalmetadaten (wer verbindet
// sich mit wem) könnten über HTTP-Server unverschlüsselt übertragen werden.
// Wer maximale Privatsphäre will, betreibt einen HTTPS-Server.
function fed_url_safe($url) {
    if (!preg_match('#^https?://#i', $url)) return false;
    $host = parse_url($url, PHP_URL_HOST);
    if (!$host) return false;
    $ip = @gethostbyname($host);
    if (!$ip || $ip === $host) return false;
    $long = ip2long($ip);
    if ($long === false) return false;
    foreach (array(
        array('127.0.0.0','127.255.255.255'),
        array('10.0.0.0','10.255.255.255'),
        array('172.16.0.0','172.31.255.255'),
        array('192.168.0.0','192.168.255.255'),
        array('169.254.0.0','169.254.255.255'),
        array('0.0.0.0','0.255.255.255'),
    ) as $r) {
        if ($long >= ip2long($r[0]) && $long <= ip2long($r[1])) return false;
    }
    return true;
}

function fed_post($url, $payload, $timeout = 5) {
    $body = json_encode($payload, JSON_UNESCAPED_UNICODE);
    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt_array($ch, array(
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $body,
            CURLOPT_HTTPHEADER     => array('Content-Type: application/json', 'Content-Length: ' . strlen($body)),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => $timeout,
            CURLOPT_SSL_VERIFYPEER => true,
        ));
        $result = @curl_exec($ch);
        curl_close($ch);
    } else {
        $opts = array('http' => array(
            'method'        => 'POST',
            'header'        => "Content-Type: application/json\r\nContent-Length: " . strlen($body) . "\r\n",
            'content'       => $body,
            'timeout'       => $timeout,
            'ignore_errors' => true,
        ));
        $result = @file_get_contents($url, false, stream_context_create($opts));
    }
    return ($result !== false && $result !== null) ? @json_decode($result, true) : null;
}

function bereinige($liste, $ttl) {
    $jetzt = time(); $r = array();
    foreach ($liste as $k => $e) {
        if (is_array($e) && isset($e['ts']) && ($e['ts'] + $ttl) > $jetzt) $r[$k] = $e;
    }
    return $r;
}

// GET -> Selbsttest
if (!isset($_SERVER['REQUEST_METHOD']) || $_SERVER['REQUEST_METHOD'] === 'GET') {
    $nkp = noise_server_keypair();
    aoi_ok(array('server'=>'AOI 9.0 Signal','version'=>'1.0','php'=>PHP_VERSION,
        'token_set'=>is_file(TOKEN_DATEI)&&trim((string)@file_get_contents(TOKEN_DATEI))!=='',
        'daten_dir'=>is_dir(DATEN_DIR)?'vorhanden':'wird angelegt','zeit'=>date('c'),
        'noise_pub'=>$nkp ? $nkp['pub'] : null));
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') aoi_fehler('Nur POST erlaubt.', 405);

$body = (string)file_get_contents('php://input');
if (strlen($body) > MAX_BODY) aoi_fehler('Anfrage zu gross.');
$ein = @json_decode($body, true);
if (!is_array($ein)) aoi_fehler('Kein gueltiges JSON.');

$aktion = isset($ein['aktion']) ? (string)$ein['aktion'] : '';
$name   = isset($ein['name'])   ? (string)$ein['name']   : '';
$token  = isset($ein['token'])  ? (string)$ein['token']  : (isset($_SERVER['HTTP_X_AOI_TOKEN']) ? (string)$_SERVER['HTTP_X_AOI_TOKEN'] : '');

if ($aktion === 'info') {
    $nkp = noise_server_keypair();
    aoi_ok(array('server'=>'AOI 9.0 Signal','version'=>'1.0','php'=>PHP_VERSION,
        'token_set'=>is_file(TOKEN_DATEI)&&trim((string)@file_get_contents(TOKEN_DATEI))!=='',
        'daten_dir'=>is_dir(DATEN_DIR)?'vorhanden':'wird angelegt','zeit'=>date('c'),
        'noise_pub'=>$nkp ? $nkp['pub'] : null));
}

// federation_signal: kein eigener Token nötig – kommt von einem anderen AOI-Server
// Wird vor dem Token-Check behandelt, da fremde Server unser Passwort nicht kennen.
if ($aktion === 'federation_signal') {
    if (!FEDERATION_ENABLED) aoi_fehler('Nicht im AOI-Netz.', 403);
    // IP-Rate-Limiting: max 30 Anfragen / 60 Sek pro IP
    $rl_hash = substr(hash('sha256', $_SERVER['REMOTE_ADDR'] ?? ''), 0, 12);
    $rl_pfad = DATEN_DIR . '/rl_' . $rl_hash . '.php';
    $rl = lies($rl_pfad); $rl_now = time();
    if (!isset($rl['start']) || ($rl_now - $rl['start']) > 60) {
        $rl = array('start' => $rl_now, 'count' => 1);
    } else { $rl['count']++; }
    schreibe($rl_pfad, $rl);
    if ($rl['count'] > 30) aoi_fehler('Rate limit.', 429);
    $an          = isset($ein['an'])          ? (string)$ein['an']          : '';
    $von         = isset($ein['von'])         ? (string)$ein['von']         : '';
    $typ         = isset($ein['typ'])         ? (string)$ein['typ']         : '';
    $daten       = isset($ein['daten'])       ? $ein['daten']               : null;
    $from_server = isset($ein['from_server']) ? (string)$ein['from_server'] : '';
    if (!name_ok($an) || !name_ok($von)) aoi_fehler('Ungueltige Namen.');
    if (!in_array($typ, array('offer','answer','ice'), true)) aoi_fehler('Unbekannter Signaltyp.');
    if ($daten === null) aoi_fehler('Kein Signal-Inhalt.');
    $daten_json = json_encode($daten);
    if (strlen($daten_json) > ($typ === 'ice' ? MAX_ICE * 2 : MAX_SDP)) aoi_fehler('Signal zu gross.');
    $pfad  = inbox_pfad($an);
    $inbox = array_values(bereinige(lies($pfad), SIGNAL_TTL));
    if (count($inbox) < MAX_SIGNALE) {
        $inbox[] = array('von' => $von, 'typ' => $typ, 'daten' => $daten, 'ts' => time(), 'from_server' => $from_server);
        schreibe($pfad, $inbox);
    }
    aoi_ok(array('relayed' => true));
}

// Weitere Server-zu-Server-Endpunkte: kein lokaler Token nötig
if (FEDERATION_ENABLED && in_array($aktion, array('federation_servers','federation_join','federation_name_check','federation_presence'), true)) {
    if ($aktion === 'federation_servers') {
        $servers = lies(FED_SERVERS_FILE);
        $list = array_values(array_map(function($s){ return $s['url']; }, $servers));
        if (!in_array(FEDERATION_URL, $list)) $list[] = FEDERATION_URL;
        aoi_ok(array('servers' => $list));
    }
    if ($aktion === 'federation_join') {
        $new_url = isset($ein['server_url']) ? trim((string)$ein['server_url']) : '';
        if (!$new_url || strlen($new_url) > 256 || !fed_url_safe($new_url)) aoi_fehler('Ungueltige Server-URL.');
        $servers = lies(FED_SERVERS_FILE);
        $key = substr(hash('sha256', $new_url), 0, 16);
        $servers[$key] = array('url' => $new_url, 'joined' => time(), 'last_seen' => time());
        schreibe(FED_SERVERS_FILE, $servers);
        $list = array_values(array_map(function($s){ return $s['url']; }, $servers));
        if (!in_array(FEDERATION_URL, $list)) $list[] = FEDERATION_URL;
        aoi_ok(array('willkommen' => true, 'servers' => $list));
    }
    if ($aktion === 'federation_name_check') {
        $check = isset($ein['check_name']) ? strtolower(trim((string)$ein['check_name'])) : '';
        if (!$check || !name_ok($check)) aoi_fehler('Kein gueltiger Name.');
        $presence = bereinige(lies(PRESENCE_FILE), PRESENCE_TTL);
        $dir = lies(DIRECTORY_FILE);
        $found = isset($presence[$check]) || isset($dir[$check]);
        aoi_ok(array('exists' => $found, 'server' => FEDERATION_URL));
    }
    if ($aktion === 'federation_presence') {
        $users = isset($ein['users']) ? (array)$ein['users'] : array();
        $server_url = isset($ein['server_url']) ? trim((string)$ein['server_url']) : '';
        if (!$server_url || !fed_url_safe($server_url) || $server_url === FEDERATION_URL) aoi_fehler('Ungueltige Server-URL.');
        $fed_srv = lies(FED_SERVERS_FILE);
        $srv_key = substr(hash('sha256', $server_url), 0, 16);
        $fed_srv[$srv_key] = array('url' => $server_url,
            'joined'    => isset($fed_srv[$srv_key]['joined']) ? $fed_srv[$srv_key]['joined'] : time(),
            'last_seen' => time());
        schreibe(FED_SERVERS_FILE, $fed_srv);
        $fed_pres = bereinige(lies(FED_PRESENCE_FILE), PRESENCE_TTL * 8);
        foreach ($fed_pres as $fn => $finfo) {
            if (isset($finfo['server']) && $finfo['server'] === $server_url) unset($fed_pres[$fn]);
        }
        foreach ($users as $u) {
            if (name_ok($u)) $fed_pres[strtolower($u)] = array('server' => $server_url, 'ts' => time());
        }
        schreibe(FED_PRESENCE_FILE, $fed_pres);
        aoi_ok(array('ok' => true));
    }
}

/* ===== NOISE IK: Client-Schlüssel registrieren ===== */
if ($aktion === 'noise_register') {
    if (!token_ok($token)) aoi_fehler('Ungueltiger Token.', 403);
    if (!name_ok($name))   aoi_fehler('Ungueltiger Name.');
    $spk = isset($ein['spk']) ? trim((string)$ein['spk']) : '';
    $spk_bytes = base64_decode($spk, true);
    if ($spk_bytes === false || strlen($spk_bytes) !== 32) aoi_fehler('Ungueltiger Public Key.');
    $clients = lies(NOISE_CLIENTS_FILE);
    $clients[$name] = array('spk' => $spk, 'ts' => time());
    schreibe(NOISE_CLIENTS_FILE, $clients);
    $nkp = noise_server_keypair();
    aoi_ok(array('registered' => true, 'noise_pub' => $nkp ? $nkp['pub'] : null));
}

/* ===== NOISE IK: Anfrage entschlüsseln ===== */
$noise_authenticated = false;
if (isset($ein['v']) && (int)$ein['v'] === 1) {
    if (!function_exists('sodium_crypto_scalarmult'))
        aoi_fehler('Serverseite unterstützt kein Noise IK (libsodium fehlt).', 503);
    $nkp = noise_server_keypair();
    if (!$nkp) aoi_fehler('Server-Schlüssel nicht verfügbar.', 503);
    $srv_priv = base64_decode($nkp['priv'], true);
    $epk_pub  = base64_decode($ein['epk'] ?? '', true);
    $spk_pub  = base64_decode($ein['spk'] ?? '', true);
    if (!$epk_pub || !$spk_pub || strlen($epk_pub) !== 32 || strlen($spk_pub) !== 32)
        aoi_fehler('Ungueltige Noise-Schluessel.', 400);
    // SPK muss registriert sein
    $clients = lies(NOISE_CLIENTS_FILE);
    $noise_client_name = null;
    foreach ($clients as $cn => $ci) {
        if (isset($ci['spk']) && base64_decode($ci['spk'], true) === $spk_pub) {
            $noise_client_name = $cn; break;
        }
    }
    if ($noise_client_name === null) aoi_fehler('Unbekannter Client-Schluessel.', 403);
    // DH + HKDF
    $dh1     = sodium_crypto_scalarmult($srv_priv, $epk_pub);
    $dh2     = sodium_crypto_scalarmult($srv_priv, $spk_pub);
    $ikm     = $dh1 . $dh2;
    $req_key = hash_hkdf('sha256', $ikm, 32, 'aoi-noise-req-v1');
    $res_key = hash_hkdf('sha256', $ikm, 32, 'aoi-noise-res-v1');
    // Entschlüsseln
    $iv = base64_decode($ein['iv'] ?? '', true);
    if (!$iv || strlen($iv) !== 12) aoi_fehler('Ungueltige IV.', 400);
    $combined = base64_decode($ein['body'] ?? '', true);
    if (!$combined || strlen($combined) < 17) aoi_fehler('Ciphertext zu kurz.', 400);
    $tag        = substr($combined, -16);
    $ciphertext = substr($combined, 0, -16);
    $aad        = $epk_pub . $spk_pub;
    $plain = openssl_decrypt($ciphertext, 'aes-256-gcm', $req_key, OPENSSL_RAW_DATA, $iv, $tag, $aad);
    if ($plain === false) aoi_fehler('Entschluesselung fehlgeschlagen.', 403);
    $ein = @json_decode($plain, true);
    if (!is_array($ein)) aoi_fehler('Ungueltige verschluesselte Nutzlast.', 400);
    $aktion = isset($ein['aktion']) ? (string)$ein['aktion'] : '';
    $name   = isset($ein['name'])   ? (string)$ein['name']   : $noise_client_name;
    $noise_res_key       = $res_key;
    $noise_authenticated = true;
}

if (!$noise_authenticated && !token_ok($token)) aoi_fehler('Ungueltiger Token.', 403);

// list_users braucht keinen Screen-Namen
if ($aktion === 'list_users') {
    $dir      = lies(DIRECTORY_FILE);
    $presence = bereinige(lies(PRESENCE_FILE), PRESENCE_TTL);
    $users    = array();
    foreach ($dir as $n => $info) {
        $users[] = array(
            'name'   => $n,
            'online' => isset($presence[$n]),
            'since'  => isset($info['since']) ? $info['since'] : 0,
        );
    }
    usort($users, function($a, $b) {
        if ($a['online'] !== $b['online']) return $b['online'] ? 1 : -1;
        return strcasecmp($a['name'], $b['name']);
    });
    aoi_ok(array('users' => $users, 'total' => count($users)));
}

if (!name_ok($name))   aoi_fehler('Ungueltiger Screen-Name.');

// CHECK_NAME – Prüft ob ein Name bereits online ist (liest nur, ändert nichts)
if ($aktion === 'check_name') {
    $presence = bereinige(lies(PRESENCE_FILE), PRESENCE_TTL);
    aoi_ok(array('taken' => isset($presence[$name])));
}

if ($aktion === 'presence') {
    $session = isset($ein['session']) ? (string)$ein['session'] : '';
    if (strlen($session) < 8 || strlen($session) > 64) aoi_fehler('Ungueltige Session-ID.');
    $presence = bereinige(lies(PRESENCE_FILE), PRESENCE_TTL);
    $presence[$name] = array('ts' => time(), 'session' => $session);
    schreibe(PRESENCE_FILE, $presence);
    // Optionaler Verzeichnis-Eintrag (öffentliche Nutzersuche)
    if (!empty($ein['public'])) {
        $dir = lies(DIRECTORY_FILE);
        $dir[$name] = array(
            'ts'    => time(),
            'since' => isset($dir[$name]['since']) ? $dir[$name]['since'] : time(),
        );
        schreibe(DIRECTORY_FILE, $dir);
    }

    $buddies = array();
    foreach ($presence as $n => $p) { if ($n !== $name) $buddies[] = $n; }

    // Federation: User anderer Server aus lokalem Cache zurückgeben
    $fed_buddies = array();
    if (FEDERATION_ENABLED) {
        $fed_pres = bereinige(lies(FED_PRESENCE_FILE), PRESENCE_TTL * 8);
        $local_lower = array_map('strtolower', $buddies);
        foreach ($fed_pres as $fn => $finfo) {
            if (strtolower($fn) !== strtolower($name) && !in_array(strtolower($fn), $local_lower)) {
                $fed_buddies[] = array('name' => $fn, 'server' => $finfo['server']);
            }
        }
        // Eigene User an ALLE bekannten Federation-Server broadcasten
        $fed_servers = lies(FED_SERVERS_FILE);
        $names_to_announce = array_keys($presence);
        foreach ($fed_servers as $srv) {
            if (empty($srv['url']) || $srv['url'] === FEDERATION_URL) continue;
            @fed_post($srv['url'], array(
                'aktion'     => 'federation_presence',
                'users'      => $names_to_announce,
                'server_url' => FEDERATION_URL,
            ), 2);
        }
        // Beim ersten Mal: Seed-Server beitreten falls noch keine Peers bekannt
        if (empty($fed_servers) && FEDERATION_SEED !== '' && FEDERATION_SEED !== FEDERATION_URL) {
            $res = fed_post(FEDERATION_SEED, array(
                'aktion'     => 'federation_join',
                'name'       => $name,
                'server_url' => FEDERATION_URL,
            ), 5);
            if ($res && !empty($res['servers'])) {
                foreach ($res['servers'] as $surl) {
                    if ($surl === FEDERATION_URL) continue;
                    $key = substr(hash('sha256', $surl), 0, 16);
                    $fed_servers[$key] = array('url' => $surl, 'joined' => time(), 'last_seen' => time());
                }
                schreibe(FED_SERVERS_FILE, $fed_servers);
            }
        }
    }

    aoi_ok(array('buddies' => $buddies, 'fed_buddies' => $fed_buddies));
}

if ($aktion === 'signal') {
    $an  = isset($ein['an'])  ? (string)$ein['an']  : '';
    $typ = isset($ein['typ']) ? (string)$ein['typ'] : '';
    if (!name_ok($an))  aoi_fehler('Ungueltiger Empfaenger.');
    if ($an === $name)  aoi_fehler('Kann nicht an sich selbst senden.');
    if (!in_array($typ, array('offer','answer','ice'), true)) aoi_fehler('Unbekannter Signaltyp.');
    $daten = isset($ein['daten']) ? $ein['daten'] : null;
    if ($daten === null) aoi_fehler('Kein Signal-Inhalt.');
    $daten_json = json_encode($daten);
    if ($daten_json === false) aoi_fehler('Nicht serialisierbar.');
    if (strlen($daten_json) > ($typ === 'ice' ? MAX_ICE : MAX_SDP)) aoi_fehler('Signal zu gross.');

    // Federation: Wenn Empfänger nicht lokal online ist, lokalen Cache befragen
    if (FEDERATION_ENABLED) {
        $local_pres = bereinige(lies(PRESENCE_FILE), PRESENCE_TTL);
        if (!isset($local_pres[$an])) {
            $fed_pres = bereinige(lies(FED_PRESENCE_FILE), PRESENCE_TTL * 8);
            if (isset($fed_pres[strtolower($an)])) {
                $target_server = $fed_pres[strtolower($an)]['server'];
                $res = fed_post($target_server, array(
                    'aktion' => 'federation_signal', 'von' => $name, 'an' => $an,
                    'typ' => $typ, 'daten' => $daten, 'from_server' => FEDERATION_URL,
                ));
                if ($res && !empty($res['relayed'])) aoi_ok(array('zugestellt' => true, 'via_federation' => true));
            }
        }
    }

    $pfad  = inbox_pfad($an);
    $inbox = array_values(bereinige(lies($pfad), SIGNAL_TTL));
    if (count($inbox) >= MAX_SIGNALE) aoi_fehler('Posteingang voll.');
    $inbox[] = array('von'=>$name,'typ'=>$typ,'daten'=>$daten,'ts'=>time());
    if (!schreibe($pfad, $inbox)) aoi_fehler('Speicherfehler.', 500);
    aoi_ok(array('zugestellt' => true));
}

if ($aktion === 'poll') {
    $pfad   = inbox_pfad($name);
    $frisch = array_values(bereinige(lies($pfad), SIGNAL_TTL));
    schreibe($pfad, array());
    aoi_ok(array('signale' => $frisch));
}

if ($aktion === 'bye') {
    $presence = lies(PRESENCE_FILE);
    unset($presence[$name]);
    schreibe(PRESENCE_FILE, $presence);
    aoi_ok(array('tschuess' => true));
}

if ($aktion === 'unregister_public') {
    $dir = lies(DIRECTORY_FILE);
    unset($dir[$name]);
    schreibe(DIRECTORY_FILE, $dir);
    aoi_ok(array('removed' => true));
}

/* ===== OFFLINE-NACHRICHTEN ===== */
function offline_pfad($n) {
    return OFFLINE_PREFIX . substr(hash('sha256', strtolower($n)), 0, 16) . '.php';
}

/* offline_send / offline_poll entfernt (v9.1.0) – Offline-Nachrichten liegen beim Absender-Client */

/* ===== PROFILE ===== */
function profil_pfad($n) {
    return PROFILE_PREFIX . substr(hash('sha256', strtolower($n)), 0, 16) . '.php';
}

if ($aktion === 'profile_save') {
    $erlaubt = array('avatar','motto','interessen','zitat','ort','alter');
    $profil  = array('name' => $name, 'ts' => time());
    foreach ($erlaubt as $feld) {
        if (isset($ein[$feld])) {
            $val = (string)$ein[$feld];
            if (strlen($val) > 200) $val = substr($val, 0, 200);
            $profil[$feld] = $val;
        }
    }
    if (!schreibe(profil_pfad($name), $profil)) aoi_fehler('Speicherfehler.', 500);
    aoi_ok(array('gespeichert' => true));
}

if ($aktion === 'profile_get') {
    $ziel = isset($ein['ziel']) ? (string)$ein['ziel'] : $name;
    if (!name_ok($ziel)) aoi_fehler('Ungueltiger Name.');
    $pfad  = profil_pfad($ziel);
    $profil = is_file($pfad) ? lies($pfad) : array();
    aoi_ok(array('profil' => $profil));
}

/* ===== CHATROOMS ===== */
function room_name_ok($r) {
    return strlen($r) >= 1 && strlen($r) <= 32 && preg_match('/^[a-zA-Z0-9_\-\. äöüÄÖÜß]+$/u', $r) === 1;
}
function room_pfad($r) {
    return ROOM_PREFIX . substr(hash('sha256', strtolower($r)), 0, 16) . '.php';
}

if ($aktion === 'room_list') {
    $rooms = lies(ROOMS_FILE);
    $presence = bereinige(lies(PRESENCE_FILE), PRESENCE_TTL);
    $result = array();
    foreach ($rooms as $rname => $info) {
        $is_private = !empty($info['private']);
        $creator    = isset($info['creator']) ? $info['creator'] : '';
        $raw_members = isset($info['members']) ? (array)$info['members'] : array();
        if ($is_private && $creator !== $name && !in_array($name, $raw_members)) continue;
        $members = array_values(array_filter($raw_members, function($m) use ($presence) { return isset($presence[$m]); }));
        $result[] = array(
            'name'    => $rname,
            'topic'   => isset($info['topic']) ? $info['topic'] : '',
            'members' => $members,
            'count'   => count($members),
            'full'    => count($raw_members) >= MAX_ROOM_MEMBERS,
            'private' => $is_private,
        );
    }
    usort($result, function($a,$b){ return $b['count'] - $a['count']; });
    aoi_ok(array('rooms' => $result));
}

if ($aktion === 'room_join') {
    $room  = isset($ein['room'])  ? trim((string)$ein['room'])  : '';
    $topic = isset($ein['topic']) ? trim((string)$ein['topic']) : '';
    if (!room_name_ok($room)) aoi_fehler('Ungueltiger Raumname.');
    $rooms = lies(ROOMS_FILE);
    if (!isset($rooms[$room])) {
        $eigene = count(array_filter($rooms, function($info) use ($name) {
            return isset($info['creator']) && $info['creator'] === $name;
        }));
        if ($eigene >= 4) aoi_fehler('Du hast bereits 4 Chaträume erstellt. Bitte erst einen bestehenden Raum verlassen (leere Räume werden automatisch gelöscht).');
        $is_private = !empty($ein['private']);
        $rooms[$room] = array('topic' => substr($topic, 0, 100), 'created' => time(), 'creator' => $name, 'members' => array(), 'private' => $is_private);
    }
    $members = (array)$rooms[$room]['members'];
    if (!in_array($name, $members)) {
        if (count($members) >= MAX_ROOM_MEMBERS) aoi_fehler('Dieser Raum ist voll (max. ' . MAX_ROOM_MEMBERS . ' Teilnehmer).');
        $members[] = $name;
    }
    $rooms[$room]['members'] = array_values($members);
    schreibe(ROOMS_FILE, $rooms);
    $others = array_values(array_filter($members, function($m) use($name){ return $m !== $name; }));
    aoi_ok(array('beigetreten' => true, 'topic' => $rooms[$room]['topic'], 'members' => $others, 'private' => !empty($rooms[$room]['private'])));
}

if ($aktion === 'room_leave') {
    $room = isset($ein['room']) ? trim((string)$ein['room']) : '';
    if (!room_name_ok($room)) aoi_fehler('Ungueltiger Raumname.');
    $rooms = lies(ROOMS_FILE);
    if (isset($rooms[$room])) {
        $members = array_values(array_filter((array)$rooms[$room]['members'], function($m) use($name){ return $m !== $name; }));
        if (empty($members)) unset($rooms[$room]);
        else $rooms[$room]['members'] = $members;
        schreibe(ROOMS_FILE, $rooms);
    }
    aoi_ok(array('verlassen' => true));
}

if ($aktion === 'room_members') {
    $room = isset($ein['room']) ? trim((string)$ein['room']) : '';
    if (!room_name_ok($room)) aoi_fehler('Ungueltiger Raumname.');
    $rooms    = lies(ROOMS_FILE);
    $presence = bereinige(lies(PRESENCE_FILE), PRESENCE_TTL);
    if (!isset($rooms[$room])) aoi_ok(array('members' => array()));
    $is_private = !empty($rooms[$room]['private']);
    $creator    = isset($rooms[$room]['creator']) ? $rooms[$room]['creator'] : '';
    $all        = (array)$rooms[$room]['members'];
    if ($is_private && $creator !== $name && !in_array($name, $all)) aoi_ok(array('members' => array()));
    $online = array_values(array_filter($all, function($m) use($presence){ return isset($presence[$m]); }));
    if (count($online) !== count($all)) {
        if (empty($online)) unset($rooms[$room]);
        else $rooms[$room]['members'] = $online;
        schreibe(ROOMS_FILE, $rooms);
    }
    aoi_ok(array('members' => $online));
}

/* ===== FEDERATION-ENDPUNKTE ===== */

// Bekannte Server im Netz zurückgeben
if ($aktion === 'federation_servers') {
    if (!FEDERATION_ENABLED) aoi_fehler('Nicht im AOI-Netz.', 403);
    $servers = lies(FED_SERVERS_FILE);
    $list = array_values(array_map(function($s){ return $s['url']; }, $servers));
    if (!in_array(FEDERATION_URL, $list)) $list[] = FEDERATION_URL;
    aoi_ok(array('servers' => $list));
}

// Neuer Server meldet sich am AOI-Netz an
if ($aktion === 'federation_join') {
    if (!FEDERATION_ENABLED) aoi_fehler('Nicht im AOI-Netz.', 403);
    $new_url = isset($ein['server_url']) ? trim((string)$ein['server_url']) : '';
    if (!$new_url || strlen($new_url) > 256 || !filter_var($new_url, FILTER_VALIDATE_URL)) aoi_fehler('Ungueltige Server-URL.');
    $servers = lies(FED_SERVERS_FILE);
    $key = substr(hash('sha256', $new_url), 0, 16);
    $servers[$key] = array('url' => $new_url, 'joined' => time(), 'last_seen' => time());
    schreibe(FED_SERVERS_FILE, $servers);
    $list = array_values(array_map(function($s){ return $s['url']; }, $servers));
    if (!in_array(FEDERATION_URL, $list)) $list[] = FEDERATION_URL;
    aoi_ok(array('willkommen' => true, 'servers' => $list));
}

// Prüfen ob ein Name lokal registriert/online ist
if ($aktion === 'federation_name_check') {
    if (!FEDERATION_ENABLED) aoi_fehler('Nicht im AOI-Netz.', 403);
    $check = isset($ein['check_name']) ? strtolower(trim((string)$ein['check_name'])) : '';
    if (!$check || !name_ok($check)) aoi_fehler('Kein gueltiger Name.');
    $presence = bereinige(lies(PRESENCE_FILE), PRESENCE_TTL);
    $dir = lies(DIRECTORY_FILE);
    $found = isset($presence[$check]) || isset($dir[$check]);
    aoi_ok(array('exists' => $found, 'server' => FEDERATION_URL));
}

// Anderer Server meldet seine aktiven User – jeder Server speichert das lokal
if ($aktion === 'federation_presence') {
    if (!FEDERATION_ENABLED) aoi_fehler('Nicht im AOI-Netz.', 403);
    $users = isset($ein['users']) ? (array)$ein['users'] : array();
    $server_url = isset($ein['server_url']) ? trim((string)$ein['server_url']) : '';
    if (!$server_url || !filter_var($server_url, FILTER_VALIDATE_URL) || $server_url === FEDERATION_URL) aoi_fehler('Ungueltige Server-URL.');
    // Sender als bekannten Peer speichern
    $fed_srv = lies(FED_SERVERS_FILE);
    $srv_key = substr(hash('sha256', $server_url), 0, 16);
    $fed_srv[$srv_key] = array('url' => $server_url,
        'joined'    => isset($fed_srv[$srv_key]['joined']) ? $fed_srv[$srv_key]['joined'] : time(),
        'last_seen' => time());
    schreibe(FED_SERVERS_FILE, $fed_srv);
    $fed_pres = bereinige(lies(FED_PRESENCE_FILE), PRESENCE_TTL * 8);
    // Alte Einträge dieses Servers entfernen
    foreach ($fed_pres as $fn => $finfo) {
        if (isset($finfo['server']) && $finfo['server'] === $server_url) unset($fed_pres[$fn]);
    }
    foreach ($users as $u) {
        if (name_ok($u)) $fed_pres[strtolower($u)] = array('server' => $server_url, 'ts' => time());
    }
    schreibe(FED_PRESENCE_FILE, $fed_pres);
    aoi_ok(array('ok' => true));
}

aoi_fehler('Unbekannte Aktion: ' . htmlspecialchars($aktion, ENT_QUOTES));
