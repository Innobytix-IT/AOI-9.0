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
define('PRESENCE_FILE', DATEN_DIR . '/presence.php');
define('INBOX_PREFIX',  DATEN_DIR . '/inbox_');
define('TOKEN_DATEI',   __DIR__ . '/aoi_token.php');
define('PRESENCE_TTL',  45);
define('SIGNAL_TTL',    120);
define('MAX_SIGNALE',   64);
define('MAX_NAME',      32);
define('MAX_SDP',       16384);
define('MAX_ICE',       2048);
define('MAX_BODY',      32768);

function aoi_ok($daten = array()) {
    echo json_encode(array_merge(array('ok' => true), $daten), JSON_UNESCAPED_UNICODE);
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

function bereinige($liste, $ttl) {
    $jetzt = time(); $r = array();
    foreach ($liste as $k => $e) {
        if (is_array($e) && isset($e['ts']) && ($e['ts'] + $ttl) > $jetzt) $r[$k] = $e;
    }
    return $r;
}

// GET -> Selbsttest
if (!isset($_SERVER['REQUEST_METHOD']) || $_SERVER['REQUEST_METHOD'] === 'GET') {
    aoi_ok(array('server'=>'AOI 9.0 Signal','version'=>'1.0','php'=>PHP_VERSION,
        'token_set'=>is_file(TOKEN_DATEI)&&trim((string)@file_get_contents(TOKEN_DATEI))!=='',
        'daten_dir'=>is_dir(DATEN_DIR)?'vorhanden':'wird angelegt','zeit'=>date('c')));
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
    aoi_ok(array('server'=>'AOI 9.0 Signal','version'=>'1.0','php'=>PHP_VERSION,
        'token_set'=>is_file(TOKEN_DATEI)&&trim((string)@file_get_contents(TOKEN_DATEI))!=='',
        'daten_dir'=>is_dir(DATEN_DIR)?'vorhanden':'wird angelegt','zeit'=>date('c')));
}

if (!token_ok($token)) aoi_fehler('Ungueltiger Token.', 403);
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
    $buddies = array();
    foreach ($presence as $n => $p) { if ($n !== $name) $buddies[] = $n; }
    aoi_ok(array('buddies' => $buddies));
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

aoi_fehler('Unbekannte Aktion: ' . htmlspecialchars($aktion, ENT_QUOTES));
