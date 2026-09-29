'use strict';
// AOI P2P: Noise IK (X25519 + AES-256-GCM + SHA-256) über IPv6-UDP
// Für CGNAT/DS-Lite Nutzer als Upgrade über den Relay-Kanal.
const dgram  = require('dgram');
const crypto = require('crypto');
const os     = require('os');

// ── Krypto-Primitive ───────────────────────────────────────────────────────

const PROTO   = Buffer.from('Noise_IK_25519_AESGCM_SHA256');
const SPKI_HDR = Buffer.from('302a300506032b656e032100', 'hex'); // 12 Byte Prefix für X25519 raw→SPKI

const sha256 = d => crypto.createHash('sha256').update(d).digest();
const hmac   = (k, d) => crypto.createHmac('sha256', k).update(d).digest();

function hkdf2(ck, ikm) {
  const tk = hmac(ck, ikm.length ? ikm : Buffer.alloc(0));
  const o1 = hmac(tk, Buffer.from([1]));
  return [o1, hmac(tk, Buffer.concat([o1, Buffer.from([2])]))];
}

const mh = (h, d) => sha256(Buffer.concat([h, Buffer.isBuffer(d) ? d : Buffer.from(d)]));

function rawPub(r32) {
  return crypto.createPublicKey({ key: Buffer.concat([SPKI_HDR, r32]), format: 'der', type: 'spki' });
}

function xdh(priv, pub32) {
  return crypto.diffieHellman({ privateKey: priv, publicKey: rawPub(pub32) });
}

function gcmEnc(k, n, ad, pt) {
  const iv = Buffer.alloc(12); iv.writeBigUInt64BE(BigInt(n), 4);
  const c = crypto.createCipheriv('aes-256-gcm', k, iv);
  if (ad.length) c.setAAD(ad);
  const ct = Buffer.concat([c.update(pt), c.final()]);
  return Buffer.concat([ct, c.getAuthTag()]); // ciphertext + 16-byte tag
}

function gcmDec(k, n, ad, buf) {
  if (buf.length < 16) return null;
  const iv = Buffer.alloc(12); iv.writeBigUInt64BE(BigInt(n), 4);
  const d = crypto.createDecipheriv('aes-256-gcm', k, iv);
  if (ad.length) d.setAAD(ad);
  d.setAuthTag(buf.slice(-16));
  try { return Buffer.concat([d.update(buf.slice(0, -16)), d.final()]); }
  catch { return null; }
}

// ── Noise IK Handshake ─────────────────────────────────────────────────────
// Pattern: <- s / -> e,es,s,ss / <- e,ee,se

function hsMsg1(sPriv, sPub, rs) {
  // Initiator → Responder (96 Byte)
  let h = sha256(PROTO), ck = Buffer.from(h);
  h = mh(h, rs);                                   // pre-message: responder's static

  const ep   = crypto.generateKeyPairSync('x25519');
  const ePub = ep.publicKey.export({ type: 'spki', format: 'der' }).slice(12); // raw 32 B

  h = mh(h, ePub);
  let k; [ck, k] = hkdf2(ck, xdh(ep.privateKey, rs)); // es
  const encS  = gcmEnc(k, 0, h, sPub);                 // encrypt our static pub
  h = mh(h, encS);
  [ck, k] = hkdf2(ck, xdh(sPriv, rs));                 // ss
  const encPl = gcmEnc(k, 0, h, Buffer.alloc(0));
  h = mh(h, encPl);

  return {
    msg1:  Buffer.concat([ePub, encS, encPl]),  // 32+48+16 = 96 B
    state: { h, ck, ePriv: ep.privateKey, rs }
  };
}

function hsMsg1Finish(st, msg2) {
  // Initiator liest Responder-Antwort (48 Byte), gibt Transport-Keys zurück
  if (msg2.length < 48) return null;
  let { h, ck, ePriv, rs } = st;
  const rePub = msg2.slice(0, 32);
  const encPl = msg2.slice(32, 48);

  h = mh(h, rePub);
  let k; [ck, k] = hkdf2(ck, xdh(ePriv, rePub)); // ee: DH(init_e, resp_e)
  [ck, k]        = hkdf2(ck, xdh(ePriv, rs));     // se: DH(init_e, resp_s)  [sym. mit resp_s * init_e]
  if (!gcmDec(k, 0, h, encPl)) return null;

  const [k1, k2] = hkdf2(ck, Buffer.alloc(0));
  return { tx: k1, rx: k2 };                       // Initiator sendet mit k1
}

function hsMsg2(msg1, sPriv, sPub) {
  // Responder verarbeitet msg1, gibt {msg2, keys, initiatorPub} zurück
  if (msg1.length < 96) return null;
  let h = sha256(PROTO), ck = Buffer.from(h);
  h = mh(h, sPub);                                  // pre-message: unser static pub

  const iEPub = msg1.slice(0, 32);
  const encS  = msg1.slice(32, 80);
  const encPl = msg1.slice(80, 96);

  h = mh(h, iEPub);
  let k; [ck, k] = hkdf2(ck, xdh(sPriv, iEPub));   // es: DH(resp_s, init_e)
  const iSPub = gcmDec(k, 0, h, encS);
  if (!iSPub) return null;
  h = mh(h, encS);
  [ck, k] = hkdf2(ck, xdh(sPriv, iSPub));           // ss: DH(resp_s, init_s)
  if (!gcmDec(k, 0, h, encPl)) return null;
  h = mh(h, encPl);

  const ep   = crypto.generateKeyPairSync('x25519');
  const ePub = ep.publicKey.export({ type: 'spki', format: 'der' }).slice(12);
  h = mh(h, ePub);
  [ck, k] = hkdf2(ck, xdh(ep.privateKey, iEPub));   // ee: DH(resp_e, init_e)
  [ck, k] = hkdf2(ck, xdh(sPriv, iEPub));            // se: DH(resp_s, init_e)
  const encPl2 = gcmEnc(k, 0, h, Buffer.alloc(0));
  h = mh(h, encPl2);

  const [k1, k2] = hkdf2(ck, Buffer.alloc(0));
  return {
    msg2:         Buffer.concat([ePub, encPl2]),  // 32+16 = 48 B
    keys:         { tx: k2, rx: k1 },             // Responder sendet mit k2
    initiatorPub: iSPub
  };
}

// ── Transport ──────────────────────────────────────────────────────────────

const T_PROBE = 0x00; // Firewall-Pinhole öffnen (unverschlüsselt)
const T_HS1   = 0x01; // Noise msg1
const T_HS2   = 0x02; // Noise msg2
const T_DATA  = 0x03; // Datennachricht (seq 4 B + verschlüsselt)
const T_ACK   = 0x04; // Bestätigung    (seq 4 B)
const T_PING  = 0x05;

class PeerConn {
  constructor(name, addr, port, pubRaw, isInit) {
    this.name    = name;
    this.addr    = addr;
    this.port    = port;
    this.pubRaw  = pubRaw;
    this.isInit  = isInit;
    this.state        = 'connecting'; // connecting | ready
    this.txKey        = null; this.rxKey = null;
    this.txSeq        = 0;    this.rxSeen = new Set();
    this.pendingTimers = new Map(); // seq → [t1, t2]
    this.timer        = null;
    this.hsCtx        = null;
  }

  // seq als Nonce → kein Drift bei Paketverlust (Fix für Desynchronisation)
  enc(payload, seq) { return gcmEnc(this.txKey, BigInt(seq), Buffer.alloc(0), payload); }
  dec(buf, seq)     { return gcmDec(this.rxKey, BigInt(seq), Buffer.alloc(0), buf); }
}

// ── P2P State ─────────────────────────────────────────────────────────────

let sock     = null;
let privKey  = null;  // Node.js KeyObject (X25519)
let pubRaw   = null;  // Buffer 32 B
let localIPv6 = null;
let localPort = 0;
let emit      = () => {};  // Callback → Electron main

const byAddr = new Map(); // '[addr]:port' → PeerConn
const byName = new Map(); // name          → PeerConn

function pkey(addr, port) { return `[${addr}]:${port}`; }

function globalIPv6() {
  for (const addrs of Object.values(os.networkInterfaces())) {
    for (const a of addrs) {
      if (!a.internal && a.family === 'IPv6' && /^[23]/.test(a.address))
        return a.address;
    }
  }
  return null;
}

function tx(buf, port, addr) {
  // IPv4-mapped IPv6 wenn nötig
  const target = addr.includes(':') ? addr : `::ffff:${addr}`;
  sock.send(buf, port, target, err => { if (err) console.error('[P2P] send', err.message); });
}

function onPacket(buf, ri) {
  if (!buf.length) return;
  const type = buf[0];
  const key  = pkey(ri.address, ri.port);
  let   peer = byAddr.get(key);

  // ── Handshake ──────────────────────────────────────────────────────────
  if (type === T_HS1) {
    const res = hsMsg2(buf.slice(1), privKey, pubRaw);
    if (!res) return;
    // Peer muss bekannt sein (wurde über relay p2p_addr angekündigt)
    if (!peer) {
      const name = findByPub(res.initiatorPub);
      if (!name) return;
      peer = new PeerConn(name, ri.address, ri.port, res.initiatorPub, false);
      byAddr.set(key, peer);
      byName.set(name, peer);
    }
    peer.txKey = res.keys.tx; peer.rxKey = res.keys.rx; peer.state = 'ready';
    if (peer.timer) { clearInterval(peer.timer); peer.timer = null; }
    const pkt = Buffer.concat([Buffer.from([T_HS2]), res.msg2]);
    for (let i = 0; i < 3; i++) setTimeout(() => tx(pkt, peer.port, peer.addr), i * 200);
    emit('p2p-connected', { peer: peer.name });
    return;
  }

  if (type === T_HS2 && peer && peer.state === 'connecting' && peer.hsCtx) {
    const keys = hsMsg1Finish(peer.hsCtx, buf.slice(1));
    if (!keys) return;
    peer.txKey = keys.tx; peer.rxKey = keys.rx; peer.state = 'ready';
    if (peer.timer) { clearInterval(peer.timer); peer.timer = null; }
    emit('p2p-connected', { peer: peer.name });
    return;
  }

  // ── Transport ──────────────────────────────────────────────────────────
  if (type === T_DATA && peer && peer.state === 'ready') {
    if (buf.length < 6) return;
    const seq = buf.readUInt32BE(1);
    if (peer.rxSeen.has(seq)) {
      // Duplikat: ACK trotzdem senden
      tx(Buffer.from([T_ACK, (seq>>24)&0xff, (seq>>16)&0xff, (seq>>8)&0xff, seq&0xff]),
         peer.port, peer.addr);
      return;
    }
    peer.rxSeen.add(seq);
    if (peer.rxSeen.size > 512) {
      const arr = [...peer.rxSeen]; peer.rxSeen = new Set(arr.slice(-256));
    }
    const pt = peer.dec(buf.slice(5), seq);  // seq als Nonce
    if (!pt || pt.length < 1) return;
    // ACK
    const ack = Buffer.alloc(5); ack[0] = T_ACK; ack.writeUInt32BE(seq, 1);
    tx(ack, peer.port, peer.addr);
    if (pt[0] === 0x01) {  // TEXT
      emit('p2p-message', { peer: peer.name, data: pt.slice(1).toString('utf8') });
    }
    return;
  }

  if (type === T_ACK && peer) {
    if (buf.length >= 5) {
      const seq = buf.readUInt32BE(1);
      const timers = peer.pendingTimers.get(seq);
      if (timers) { timers.forEach(t => clearTimeout(t)); peer.pendingTimers.delete(seq); }
    }
    return;
  }

  if (type === T_PING && peer && peer.state === 'ready') {
    const pong = Buffer.concat([Buffer.from([0x06]), buf.slice(1)]);
    tx(pong, peer.port, peer.addr);
  }
}

function findByPub(pub32) {
  for (const [, p] of byName) {
    if (p.pubRaw && p.pubRaw.equals(pub32)) return p.name;
  }
  return null;
}

// ── Öffentliche API ────────────────────────────────────────────────────────

function init(privPkcs8B64, pubRawB64, cb) {
  try {
    const pkcs8 = Buffer.from(privPkcs8B64, 'base64');
    privKey = crypto.createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
    pubRaw  = Buffer.from(pubRawB64, 'base64');
  } catch (e) { if (cb) cb(e); return; }

  if (sock) { if (cb) cb(null, { addr: localIPv6, port: localPort }); return; }

  const s = dgram.createSocket({ type: 'udp6', ipv6Only: true });
  s.on('error', e => console.error('[P2P] socket:', e.message));
  s.on('message', onPacket);
  s.bind(0, '::', () => {
    localPort = s.address().port;
    localIPv6 = globalIPv6();
    sock = s;
    if (cb) cb(null, { addr: localIPv6, port: localPort });
  });
}

function getAddr() {
  return localIPv6 ? { addr: localIPv6, port: localPort } : null;
}

function connect(name, peerPubB64, peerAddr, peerPort) {
  if (!sock || !privKey) return false;
  const pub = Buffer.from(peerPubB64, 'base64');
  const key = pkey(peerAddr, peerPort);

  // Bereits verbunden?
  const existing = byName.get(name);
  if (existing && existing.state === 'ready') return true;
  if (existing) { // laufender Versuch
    if (existing.timer) clearInterval(existing.timer);
    byAddr.delete(pkey(existing.addr, existing.port));
    byName.delete(name);
  }

  // Rolle: kleinerer Public Key = Initiator (deterministisch)
  const isInit = Buffer.compare(pubRaw, pub) < 0;
  const peer = new PeerConn(name, peerAddr, peerPort, pub, isInit);
  byAddr.set(key, peer);
  byName.set(name, peer);

  // Probes: Firewall auf UNSERER Seite öffnen (eingehende Pakete autorisieren)
  const probe = Buffer.from([T_PROBE]);
  for (let i = 0; i < 8; i++) setTimeout(() => tx(probe, peerPort, peerAddr), i * 80);

  if (isInit) {
    const { msg1, state } = hsMsg1(privKey, pubRaw, pub);
    peer.hsCtx = state;
    const pkt  = Buffer.concat([Buffer.from([T_HS1]), msg1]);
    let tries  = 0;
    tx(pkt, peerPort, peerAddr);
    peer.timer = setInterval(() => {
      if (peer.state === 'ready') { clearInterval(peer.timer); return; }
      if (++tries > 25) {        // ~15s
        clearInterval(peer.timer);
        byAddr.delete(key); byName.delete(name);
        emit('p2p-error', { peer: name, msg: 'timeout' });
        return;
      }
      tx(pkt, peerPort, peerAddr);
    }, 600);
  } else {
    // Responder: wartet auf msg1; timeout nach 20s
    peer.timer = setTimeout(() => {
      if (peer.state !== 'ready') {
        byAddr.delete(key); byName.delete(name);
        emit('p2p-error', { peer: name, msg: 'no_handshake' });
      }
    }, 20000);
  }
  return true;
}

function send(name, text) {
  const peer = byName.get(name);
  if (!peer || peer.state !== 'ready') return false;
  const payload = Buffer.concat([Buffer.from([0x01]), Buffer.from(text, 'utf8')]);
  const seq = peer.txSeq++;
  const ct  = peer.enc(payload, seq);  // seq IS die Nonce
  const pkt = Buffer.alloc(5 + ct.length);
  pkt[0] = T_DATA; pkt.writeUInt32BE(seq, 1); ct.copy(pkt, 5);
  tx(pkt, peer.port, peer.addr);
  // 2× Retransmit, abgebrochen wenn ACK eintrifft
  const t1 = setTimeout(() => { if (peer.state === 'ready' && peer.pendingTimers.has(seq)) tx(pkt, peer.port, peer.addr); }, 600);
  const t2 = setTimeout(() => { if (peer.state === 'ready' && peer.pendingTimers.has(seq)) { tx(pkt, peer.port, peer.addr); peer.pendingTimers.delete(seq); } }, 1800);
  peer.pendingTimers.set(seq, [t1, t2]);
  return true;
}

function disconnect(name) {
  const peer = byName.get(name);
  if (!peer) return;
  if (peer.timer) { clearInterval(peer.timer); clearTimeout(peer.timer); }
  byAddr.delete(pkey(peer.addr, peer.port));
  byName.delete(name);
}

function isReady(name) {
  const p = byName.get(name);
  return p ? p.state === 'ready' : false;
}

function setEmitter(fn) { emit = fn; }

module.exports = { init, getAddr, connect, send, disconnect, isReady, setEmitter };
