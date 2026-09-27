<?php
/**
 * aoi_signal.php  –  AOI 9.0 Buddy-Finder & WebRTC-Signaling
 * ============================================================
 *
 * ZWECK
 * -----
 * Buddys finden sich hier. Danach spricht AOI 9.0 direkt P2P über WebRTC.
 * Dieser Server sieht nur: wer ist online und wer will mit wem verbinden.
 * Den Inhalt der Gespräche sieht er nie.
 *
 * WAS ÜBER DIESEN SERVER LÄUFT
 * ----------------------------
 *   presence   – Herzschlag "Ich bin online", Rückgabe der Buddy-Liste
 *   signal     – WebRTC SDP-Offer / SDP-Answer / ICE-Kandidat zustellen
 *   poll       – Eingangssignale abholen (einmalig – Inbox wird geleert)
 *   bye        – Abmelden (optional; TTL räumt sowieso auf)
 *
 * WAS NICHT ÜBER DIESEN SERVER LÄUFT
 * ------------------------------------
 * Sobald WebRTC steht, kommunizieren die Clients direkt. Kein IM-Text,
 * keine Dateien, keine Audio – nichts davon berührt diesen Server.
 *
 * DATEI-LAYOUT AUF DEM WEBSPACE
 * -------------------------------
 *   aoi_signal.php          ← diese Datei
 *   aoi_token.php           ← gemeinsames Geheimnis (einzeilig, kein PHP-Tag)
 *   aoi_data/               ← Zustandsverzeichnis (vom Server angelegt)
 *     presence.php          ← wer ist online (PHP-Schutz gegen Direktabruf)
 *     inbox_<hash>.php      ← Eingangsbox je Buddy
 *   .htaccess               ← sperrt aoi_data/ gegen direkte HTTP-Abrufe
 *
 * SICHERHEITSMODELL
 * -----------------
 *   • Shared Token  –  alle AOI-Nutzer kennen dasselbe Geheimnis.
 *     Es steht in aoi_token.php und wird bei jeder Anfrage geprüft.
 *     Ohne Token kommt niemand rein – kein Fremder kann die Buddy-Liste
 *     auslesen oder Signale einschleusen.
 *   • PHP-Schutz    –  Zustandsdateien haben .php-Endung und beginnen
 *     mit <?php exit; ?> – der Server führt sie aus statt sie auszuliefern.
 *   • .htaccess     –  zweite Schranke; greift auch wenn der PHP-Schutz
 *     durch einen kaputten Upload wegfällt.
 *   • TTL           –  alte Einträge werden automatisch bereinigt.
 *     Kein Aufräumjob nötig.
 *   • Kein Inhalt   –  SDP und ICE-Kandidaten sind kurzlebige Metadaten,
 *     kein Chat-Inhalt. Die eigentliche Verschlüsselung macht WebRTC (DTLS).
 *
 * EINRICHTEN
 * ----------
 * 1. Beide Dateien hochladen: aoi_signal.php  und  .htaccess (s.u.)
 * 2. aoi_token.php anlegen:
 *      (keine PHP-Tags, nur das Geheimnis in der ersten Zeile)
 *      z.B.:  mein-super-geheimes-passwort-2026
 * 3. Im AOI-9.0-Client die URL eintragen:
 *      https://mein-webspace.de/aoi/aoi_signal.php
 *    und denselben Token wie in aoi_token.php.
 * 4. Fertig. Das aoi_data/-Verzeichnis legt das Script selbst an.
 *
 * .htaccess-INHALT (separat hochladen als ".htaccess" im selben Verzeichnis)
 * ---------------------------------------------------------------------------
 *   <IfModule mod_authz_core.c>
 *     <Directory "aoi_data">
 *       Require all denied
 *     </Directory>
 *   </IfModule>
 *   <IfModule !mod_authz_core.c>
 *     <Directory "aoi_data">
 *       Order deny,allow
 *       Deny from all
 *     </Directory>
 *   </IfModule>
 */

declare(strict_types=1);

// ── HTTP-Header ───────────────────────────────────────────────────────────
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, X-AOI-Token');
header('Cache-Control: no-store, no-cache');
header('X-Content-Type-Options: nosniff');

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'OPTIONS') {
    http_response_code(204);
    exit;
}

// ── Konfiguration ─────────────────────────────────────────────────────────
define('DATEN_DIR',     __DIR__ . '/aoi_data');
define('PRESENCE_FILE', DATEN_DIR . '/presence.php');
define('INBOX_PREFIX',  DATEN_DIR . '/inbox_');
define('TOKEN_DATEI',   __DIR__ . '/aoi_token.php');

define('PRESENCE_TTL',  45);     // s – ohne Herzschlag gilt Buddy als offline
define('SIGNAL_TTL',    120);    // s – ältere Signale werden weggeräumt
define('MAX_SIGNALE',   64);     // Signale je Inbox bevor sie voll ist
define('MAX_NAME',      32);     // Zeichen – maximale Screen-Name-Länge
define('MAX_SDP',       16384);  // Bytes – SDP-Offer/Answer (kann groß sein)
define('MAX_ICE',        2048);  // Bytes – einzelner ICE-Kandidat
define('MAX_BODY',      32768);  // Bytes – gesamter Anfrage-Body

// ── Hilfsfunktionen ───────────────────────────────────────────────────────

function ok(array $daten = []): void
{
    echo json_encode(['ok' => true] + $daten, JSON_UNESCAPED_UNICODE);
    exit;
}

function fehler(string $text, int $code = 400): never
{
    http_response_code($code);
    echo json_encode(['ok' => false, 'fehler' => $text], JSON_UNESCAPED_UNICODE);
    exit;
}

/** Schreibt atomar: erst tmp, dann rename – kein halbfertiger Zustand. */
function schreibe_atomar(string $ziel, string $inhalt): bool
{
    if (!is_dir(DATEN_DIR)) {
        @mkdir(DATEN_DIR, 0750, true);
    }
    $tmp = $ziel . '.' . bin2hex(random_bytes(4)) . '.tmp';
    if (@file_put_contents($tmp, $inhalt, LOCK_EX) === false) return false;
    if (!@rename($tmp, $ziel)) { @unlink($tmp); return false; }
    return true;
}

/**
 * Liest eine PHP-geschützte Datei und gibt den JSON-Inhalt als Array zurück.
 * Die erste Zeile (<?php exit; ?>) wird weggeworfen.
 */
function lies(string $pfad): array
{
    if (!is_file($pfad)) return [];
    $roh = @file_get_contents($pfad);
    if ($roh === false || $roh === '') return [];
    // BOM entfernen (manche FTP-Clients setzen ihn)
    if (str_starts_with($roh, "\xEF\xBB\xBF")) $roh = substr($roh, 3);
    // Erste Zeile (PHP-Schutzzeile) abschneiden
    $zeilenende = strcspn($roh, "\r\n");
    if ($zeilenende >= strlen($roh)) return [];
    $json = ltrim(substr($roh, $zeilenende), "\r\n");
    $data = @json_decode($json, true);
    return is_array($data) ? $data : [];
}

/** Schreibt eine PHP-geschützte Datei mit JSON-Inhalt. */
function schreibe(string $pfad, array $data): bool
{
    return schreibe_atomar(
        $pfad,
        "<?php exit; ?>\n" . json_encode($data, JSON_UNESCAPED_UNICODE)
    );
}

/** Pfad zur Inbox eines Buddys (kein Klarname im Dateinamen). */
function inbox(string $name): string
{
    return INBOX_PREFIX . substr(hash('sha256', mb_strtolower($name)), 0, 16) . '.php';
}

/** Prüft ob ein Screen-Name gültig ist. */
function name_ok(string $name): bool
{
    return strlen($name) >= 1
        && strlen($name) <= MAX_NAME
        && preg_match('/^[a-zA-Z0-9_\-\.]+$/', $name) === 1;
}

/**
 * Prüft den Shared Token.
 * Ist aoi_token.php leer oder fehlt sie, ist der Server offen –
 * nützlich beim ersten Einrichten, danach unbedingt Token setzen.
 */
function token_ok(string $eingabe): bool
{
    if (!is_file(TOKEN_DATEI)) return true;
    $soll = trim((string)(@file_get_contents(TOKEN_DATEI) ?: ''));
    if ($soll === '') return true; // Noch kein Token eingerichtet
    return hash_equals($soll, $eingabe);
}

// ── Anfrage einlesen ──────────────────────────────────────────────────────

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    fehler('Nur POST erlaubt.', 405);
}

$body = (string)file_get_contents('php://input');
if (strlen($body) > MAX_BODY) fehler('Anfrage zu groß.');

$ein = @json_decode($body, true);
if (!is_array($ein)) fehler('Kein gültiges JSON.');

$aktion  = (string)($ein['aktion'] ?? '');
$name    = (string)($ein['name']   ?? '');
$token   = (string)($ein['token']  ?? $_SERVER['HTTP_X_AOI_TOKEN'] ?? '');

// Token und Name prüfen (für alle Aktionen außer 'info')
if ($aktion !== 'info') {
    if (!token_ok($token))  fehler('Ungültiger Token.',       403);
    if (!name_ok($name))    fehler('Ungültiger Screen-Name.');
}

// ── Aktionen ──────────────────────────────────────────────────────────────

// INFO – Selbsttest (kein Token nötig)
if ($aktion === 'info') {
    ok([
        'server'    => 'AOI 9.0 Signal',
        'version'   => '1.0',
        'token_set' => is_file(TOKEN_DATEI) && trim((string)@file_get_contents(TOKEN_DATEI)) !== '',
        'zeit'      => date('c'),
    ]);
}

// PRESENCE – Herzschlag: "Ich bin online"
// Gibt Liste aller aktuell online Buddys zurück (außer dem Absender selbst).
if ($aktion === 'presence') {
    $session = (string)($ein['session'] ?? '');
    if (strlen($session) < 8 || strlen($session) > 64) {
        fehler('Ungültige Session-ID (8–64 Zeichen).');
    }

    $jetzt    = time();
    $presence = lies(PRESENCE_FILE);

    // Veraltete Einträge entfernen
    $presence = array_filter(
        $presence,
        fn($p) => is_array($p) && ($p['ts'] ?? 0) + PRESENCE_TTL > $jetzt
    );

    // Eigenen Eintrag aktualisieren
    $presence[$name] = ['ts' => $jetzt, 'session' => $session];

    schreibe(PRESENCE_FILE, $presence);

    // Buddy-Liste: alle außer mir selbst
    $buddies = [];
    foreach ($presence as $n => $p) {
        if ($n !== $name) {
            $buddies[] = $n;
        }
    }

    ok(['buddies' => $buddies]);
}

// SIGNAL – WebRTC-Signal an einen anderen Buddy zustellen
// typ: 'offer' | 'answer' | 'ice'
if ($aktion === 'signal') {
    $an  = (string)($ein['an']  ?? '');
    $typ = (string)($ein['typ'] ?? '');

    if (!name_ok($an))                                  fehler('Ungültiger Empfänger.');
    if ($an === $name)                                  fehler('Kann nicht an sich selbst senden.');
    if (!in_array($typ, ['offer', 'answer', 'ice'], true)) fehler('Unbekannter Signaltyp.');

    $daten = $ein['daten'] ?? null;
    if ($daten === null)                                fehler('Kein Signal-Inhalt (daten fehlt).');

    $daten_json = json_encode($daten);
    if ($daten_json === false)                          fehler('Signal-Daten nicht serialisierbar.');

    $limit = ($typ === 'ice') ? MAX_ICE : MAX_SDP;
    if (strlen($daten_json) > $limit)                  fehler('Signal-Daten zu groß.');

    // Inbox des Empfängers laden
    $pfad  = inbox($an);
    $inbox = lies($pfad);
    $jetzt = time();

    // Veraltete Signale bereinigen
    $inbox = array_values(array_filter(
        $inbox,
        fn($s) => is_array($s) && ($s['ts'] ?? 0) + SIGNAL_TTL > $jetzt
    ));

    if (count($inbox) >= MAX_SIGNALE) fehler('Posteingang des Empfängers ist voll.');

    $inbox[] = [
        'von'   => $name,
        'typ'   => $typ,
        'daten' => $daten,
        'ts'    => $jetzt,
    ];

    if (!schreibe($pfad, $inbox)) fehler('Konnte Signal nicht speichern.', 500);

    ok(['zugestellt' => true]);
}

// POLL – Eigene eingegangene Signale abholen (Inbox wird danach geleert)
if ($aktion === 'poll') {
    $pfad  = inbox($name);
    $inbox = lies($pfad);
    $jetzt = time();

    // Nur frische Signale
    $frisch = array_values(array_filter(
        $inbox,
        fn($s) => is_array($s) && ($s['ts'] ?? 0) + SIGNAL_TTL > $jetzt
    ));

    // Inbox leeren – Signale sind einmalig
    schreibe($pfad, []);

    ok(['signale' => $frisch]);
}

// BYE – Sauber abmelden (optional – TTL räumt sowieso auf)
if ($aktion === 'bye') {
    $presence = lies(PRESENCE_FILE);
    unset($presence[$name]);
    schreibe(PRESENCE_FILE, $presence);
    ok(['tschuess' => true]);
}

fehler('Unbekannte Aktion: ' . htmlspecialchars($aktion, ENT_QUOTES));
