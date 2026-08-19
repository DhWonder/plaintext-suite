/* =====================================================================
   traffic-analyzer, the part that does the work.

   This runs in a Web Worker, on its own thread, for one reason: a capture
   worth analysing is often hundreds of megabytes, and doing that on the
   page's thread freezes the tab until it finishes. Here the page stays
   responsive and shows a progress bar, which is the difference between
   "it broke" and "it is working".

   It streams the file rather than loading it. Memory stays flat whether
   the capture is two megabytes or two gigabytes.

   The analysis matches flood_watch.py rule for rule. That is tested, not
   assumed: tests/test_browser_parity.py runs both over the same files and
   compares the numbers.
   ===================================================================== */

const AMPLIFIER_PORTS = {53:"DNS",123:"NTP",1900:"SSDP",11211:"memcached",161:"SNMP",
  389:"CLDAP",19:"chargen",111:"portmapper",137:"NetBIOS",27015:"game server"};
const SENSITIVE_PORTS = {22:"SSH remote access",3389:"Remote Desktop",445:"Windows file sharing",
  25:"mail",80:"website",443:"website (secure)",3306:"database",5432:"database",1433:"database"};
const PORT_NAMES = Object.assign({}, SENSITIVE_PORTS, {53:"DNS",123:"NTP",143:"IMAP",
  993:"IMAP (secure)",995:"POP3 (secure)",110:"POP3",587:"mail submission",21:"FTP",23:"Telnet",
  161:"SNMP",389:"LDAP",636:"LDAP (secure)",1900:"SSDP",11211:"memcached",5060:"SIP",
  8080:"web (alternate)",8443:"web (secure, alternate)",27015:"game server",19:"chargen",
  111:"portmapper",137:"NetBIOS",139:"NetBIOS",6379:"Redis",27017:"MongoDB",
  9200:"Elasticsearch",5900:"VNC"});
// Doors that should never face the open internet.
const ADMIN_PORTS = new Set([22, 3389, 445, 3306, 5432, 1433, 5900, 23]);

const PROTO_NAMES = {1:"ICMP",6:"TCP",17:"UDP",47:"GRE",50:"ESP",58:"ICMPv6",132:"SCTP"};

const SYN=0x02, RST=0x04, ACK=0x10, FIN=0x01;

const MAX_SOURCES = 150000, MAX_COUNTER = 400, COUNTER_KEEP = 120;
const MAX_BUCKETS = 900, RECENT_PACKETS = 12;

const LINK_NAMES = {0:"BSD loopback",1:"Ethernet",9:"PPP",12:"raw IP",14:"raw IP",101:"raw IP",
  105:"bare 802.11 wireless",108:"OpenBSD loopback",113:"Linux cooked capture",
  127:"802.11 with radiotap headers",228:"raw IPv4",229:"raw IPv6",276:"Linux cooked capture v2"};

/* --------------------------------------------------------------------
   Regions, worked out from how IANA handed out the address space. Offline,
   no database, roughly right at continent level. The page says so.
   -------------------------------------------------------------------- */
const REGION_BLOCKS = [
 ["AFRINIC (Africa)",[41,102,105,154,196,197]],
 ["LACNIC (Latin America)",[177,179,181,186,187,189,190,191,200,201]],
 ["APNIC (Asia Pacific)",[1,14,27,36,39,42,43,49,58,59,60,61,101,103,106,110,111,112,113,114,115,
   116,117,118,119,120,121,122,123,124,125,126,133,150,153,163,171,175,180,182,183,202,203,210,
   211,218,219,220,221,222,223]],
 ["RIPE (Europe, Middle East)",[2,5,25,31,37,46,51,53,57,62,77,78,79,80,81,82,83,84,85,86,87,88,
   89,90,91,92,93,94,95,109,141,145,151,176,178,185,188,193,194,195,212,213,217]]
];
const REGION_LOOKUP = {};
for(const [name, blocks] of REGION_BLOCKS){ for(const b of blocks) REGION_LOOKUP[b] = name; }

function regionOf(ip){
  if(ip.indexOf(":") >= 0) return regionOfV6(ip);
  const first = parseInt(ip, 10);
  if(first === 10 || first === 127 || first === 172 || first === 192 || first === 169)
    return "private or local";
  return REGION_LOOKUP[first] || "ARIN (North America)";
}
function regionOfV6(ip){
  const low = ip.toLowerCase();
  if(low === "::1" || low.startsWith("fe80") || low.startsWith("fc") || low.startsWith("fd"))
    return "private or local";
  if(low.startsWith("2001:db8")) return "documentation range";
  const head = parseInt(low.split(":")[0] || "0", 16);
  if(head === 0x2001) return "RIPE (Europe, Middle East)";
  if(head >= 0x2400 && head < 0x2500) return "APNIC (Asia Pacific)";
  if(head >= 0x2600 && head < 0x2700) return "ARIN (North America)";
  if(head >= 0x2800 && head < 0x2900) return "LACNIC (Latin America)";
  if(head >= 0x2a00 && head < 0x2b00) return "RIPE (Europe, Middle East)";
  if(head >= 0x2c00 && head < 0x2d00) return "AFRINIC (Africa)";
  return "unknown";
}
function networkOf(ip){
  if(ip.indexOf(":") >= 0) return ip.split(":").slice(0,3).join(":") + "::/48";
  const parts = ip.split(".");
  if(parts.length !== 4) return ip;
  return parts.slice(0,3).join(".") + ".0/24";
}
function isLoopback(ip){
  if(ip.indexOf(":") >= 0) return ip === "::1" || ip === "0:0:0:0:0:0:0:1";
  return ip.indexOf("127.") === 0;
}
function isPrivate(ip){
  if(ip.indexOf(":") >= 0){
    const low = ip.toLowerCase();
    return low === "::1" || low.startsWith("fe80") || low.startsWith("fc") || low.startsWith("fd");
  }
  const p = ip.split(".").map(Number);
  return p[0]===10 || p[0]===127 || (p[0]===172 && p[1]>=16 && p[1]<=31)
      || (p[0]===192 && p[1]===168) || p[0]===169;
}
function guessInitialTtl(ttl){
  if(ttl <= 64)  return [64,  "Linux, Unix or a phone", 64 - ttl];
  if(ttl <= 128) return [128, "Windows", 128 - ttl];
  if(ttl <= 255) return [255, "network equipment or an appliance", 255 - ttl];
  return [255, "unknown", 0];
}

/* --------------------------------------------------------------------
   A byte feed that can be topped up from a stream and read across the
   chunk boundaries the stream hands us, which never line up with packets.
   -------------------------------------------------------------------- */
class Feed {
  constructor(){ this.buf = new Uint8Array(1 << 20); this.len = 0; this.pos = 0; this.eof = false; }
  push(chunk){
    if(this.len + chunk.length > this.buf.length){
      this.compact(true);
      if(this.len + chunk.length > this.buf.length){
        let size = this.buf.length;
        while(size < this.len + chunk.length) size *= 2;
        const grown = new Uint8Array(size);
        grown.set(this.buf.subarray(0, this.len));
        this.buf = grown;
      }
    }
    this.buf.set(chunk, this.len);
    this.len += chunk.length;
  }
  get available(){ return this.len - this.pos; }
  compact(force){
    if(this.pos === 0) return;
    if(!force && this.pos < (1 << 19)) return;
    this.buf.copyWithin(0, this.pos, this.len);
    this.len -= this.pos;
    this.pos = 0;
  }
  u32(offset, little){
    const p = this.pos + offset, b = this.buf;
    return little ? ((b[p]) | (b[p+1]<<8) | (b[p+2]<<16) | (b[p+3]<<24)) >>> 0
                  : ((b[p]<<24) | (b[p+1]<<16) | (b[p+2]<<8) | (b[p+3])) >>> 0;
  }
  u16(offset, little){
    const p = this.pos + offset, b = this.buf;
    return little ? (b[p] | (b[p+1]<<8)) : ((b[p]<<8) | b[p+1]);
  }
  skip(n){ this.pos += n; }
}

/* --------------------------------------------------------------------
   Frame decoding. Same link types and the same IPv6 walk as the Python.
   -------------------------------------------------------------------- */
const V4 = new Array(256);
for(let i=0;i<256;i++) V4[i] = String(i);

function ipv4Str(b, o){ return V4[b[o]]+"."+V4[b[o+1]]+"."+V4[b[o+2]]+"."+V4[b[o+3]]; }

function ipv6Str(b, o){
  const groups = [];
  for(let i=0;i<8;i++) groups.push(((b[o+i*2]<<8) | b[o+i*2+1]));
  // Compress the longest run of zero groups, the way every other tool prints it.
  let bestStart = -1, bestLen = 0, runStart = -1, runLen = 0;
  for(let i=0;i<8;i++){
    if(groups[i] === 0){
      if(runStart < 0){ runStart = i; runLen = 1; } else runLen++;
      if(runLen > bestLen){ bestLen = runLen; bestStart = runStart; }
    } else { runStart = -1; runLen = 0; }
  }
  const parts = [];
  for(let i=0;i<8;i++){
    if(bestLen > 1 && i === bestStart){ parts.push(""); i += bestLen - 1; continue; }
    parts.push(groups[i].toString(16));
  }
  let out = parts.join(":");
  if(bestLen > 1){
    if(bestStart === 0) out = ":" + out;
    if(bestStart + bestLen === 8) out = out + ":";
  }
  return out;
}

const IPV6_EXT = {0:1, 43:1, 60:1, 51:1, 135:1};

function readPorts(b, pay, end, proto, pkt){
  if(proto === 6 && pay + 20 <= end){
    pkt.sport = (b[pay]<<8)|b[pay+1];
    pkt.dport = (b[pay+2]<<8)|b[pay+3];
    pkt.flags = b[pay+13];
  } else if(proto === 17 && pay + 8 <= end){
    pkt.sport = (b[pay]<<8)|b[pay+1];
    pkt.dport = (b[pay+2]<<8)|b[pay+3];
  }
}

function parseIPv4(b, o, end, stats){
  if(o + 20 > end){ skip(stats, "frames cut short before the IP header finished"); return null; }
  if((b[o] >> 4) !== 4) return null;
  const ihl = (b[o] & 0x0F) * 4;
  if(ihl < 20 || o + ihl > end){ skip(stats, "frames with a damaged IP header"); return null; }
  const total = (b[o+2]<<8) | b[o+3];
  const frag = (((b[o+6]<<8) | b[o+7]) & 0x1FFF);
  const proto = b[o+9];
  const pkt = { src: ipv4Str(b, o+12), dst: ipv4Str(b, o+16), proto: proto, ttl: b[o+8],
                size: total || (end - o), sport: null, dport: null, flags: 0, family: 4 };
  if(frag === 0) readPorts(b, o + ihl, end, proto, pkt);
  else pkt.fragment = true;
  return pkt;
}

function parseIPv6(b, o, end, stats){
  if(o + 40 > end){ skip(stats, "frames cut short before the IPv6 header finished"); return null; }
  if((b[o] >> 4) !== 6) return null;
  const payloadLen = (b[o+4]<<8) | b[o+5];
  let proto = b[o+6];
  const pkt = { src: ipv6Str(b, o+8), dst: ipv6Str(b, o+24), proto: proto, ttl: b[o+7],
                size: payloadLen + 40, sport: null, dport: null, flags: 0, family: 6 };
  let pay = o + 40, walked = 0;
  while(walked < 8){
    if(IPV6_EXT[proto]){
      if(pay + 2 > end) return pkt;
      const len = (b[pay+1] + 1) * 8;
      proto = b[pay]; pay += len; walked++; continue;
    }
    if(proto === 44){
      if(pay + 8 > end) return pkt;
      const fragOffset = (((b[pay+2]<<8) | b[pay+3]) & 0xFFF8);
      proto = b[pay]; pay += 8; walked++;
      if(fragOffset){ pkt.fragment = true; pkt.proto = proto; return pkt; }
      continue;
    }
    break;
  }
  if(proto === 59) return pkt;
  pkt.proto = proto;
  readPorts(b, pay, end, proto, pkt);
  return pkt;
}

function skip(stats, reason){ stats.skipped[reason] = (stats.skipped[reason] || 0) + 1; }

function parseFrame(b, start, length, linkType, stats){
  let o = start;
  const end = start + length;

  if(linkType === 1){
    if(length < 14){ skip(stats, "frames shorter than an Ethernet header"); return null; }
    let et = (b[o+12]<<8) | b[o+13];
    o += 14;
    let hops = 0;
    while((et === 0x8100 || et === 0x88A8) && o + 4 <= end && hops < 4){
      et = (b[o+2]<<8) | b[o+3]; o += 4; hops++;
    }
    if(et === 0x8847){
      while(o + 4 <= end){ const bottom = b[o+2] & 1; o += 4; if(bottom) break; }
      if(o >= end) return null;
      et = (b[o] >> 4) === 4 ? 0x0800 : 0x86DD;
    }
    if(et === 0x0800) return parseIPv4(b, o, end, stats);
    if(et === 0x86DD) return parseIPv6(b, o, end, stats);
    skip(stats, "frames carrying something other than IP, such as ARP");
    return null;
  }
  if(linkType === 12 || linkType === 14 || linkType === 101){
    if(o >= end) return null;
    const version = b[o] >> 4;
    if(version === 4) return parseIPv4(b, o, end, stats);
    if(version === 6) return parseIPv6(b, o, end, stats);
    skip(stats, "raw frames that are neither IPv4 nor IPv6");
    return null;
  }
  if(linkType === 228) return parseIPv4(b, o, end, stats);
  if(linkType === 229) return parseIPv6(b, o, end, stats);
  if(linkType === 0 || linkType === 108){
    if(length < 4) return null;
    // Link type 0 writes the family in host order, 108 in big endian. Almost
    // every capture in the wild is little endian, so try that first and fall
    // back, rather than guessing wrong and dropping the whole file.
    let family = linkType === 108
      ? ((b[o]<<24)|(b[o+1]<<16)|(b[o+2]<<8)|b[o+3]) >>> 0
      : (b[o] | (b[o+1]<<8) | (b[o+2]<<16) | (b[o+3]<<24)) >>> 0;
    if(family > 0xFFFF) family = ((b[o]<<24)|(b[o+1]<<16)|(b[o+2]<<8)|b[o+3]) >>> 0;
    o += 4;
    if(family === 2) return parseIPv4(b, o, end, stats);
    if(family === 24 || family === 28 || family === 30) return parseIPv6(b, o, end, stats);
    skip(stats, "loopback frames that are not IP");
    return null;
  }
  if(linkType === 113){
    if(length < 16) return null;
    const proto = (b[o+14]<<8) | b[o+15];
    o += 16;
    if(proto === 0x0800) return parseIPv4(b, o, end, stats);
    if(proto === 0x86DD) return parseIPv6(b, o, end, stats);
    skip(stats, "frames carrying something other than IP, such as ARP");
    return null;
  }
  if(linkType === 276){
    if(length < 20) return null;
    const proto = (b[o]<<8) | b[o+1];
    o += 20;
    if(proto === 0x0800) return parseIPv4(b, o, end, stats);
    if(proto === 0x86DD) return parseIPv6(b, o, end, stats);
    skip(stats, "frames carrying something other than IP, such as ARP");
    return null;
  }
  if(linkType === 9){
    if(length < 4) return null;
    const proto = (b[o+2]<<8) | b[o+3];
    o += 4;
    if(proto === 0x0021) return parseIPv4(b, o, end, stats);
    if(proto === 0x0057) return parseIPv6(b, o, end, stats);
    skip(stats, "PPP frames that are not carrying IP");
    return null;
  }
  skip(stats, "frames from a link type this tool does not decode");
  return null;
}

/* --------------------------------------------------------------------
   The analyser. Same counters and the same scoring as the Python.
   -------------------------------------------------------------------- */
function bump(map, key){ map.set(key, (map.get(key) || 0) + 1); }

function topOf(map){
  let bestKey = null, bestValue = -1;
  for(const [k, v] of map){ if(v > bestValue){ bestValue = v; bestKey = k; } }
  return [bestKey, bestValue];
}
function sortedPairs(map, limit){
  const out = [...map.entries()].sort((a,b) => b[1] - a[1]);
  return limit ? out.slice(0, limit) : out;
}
function pruneMap(map){
  if(map.size <= MAX_COUNTER) return map;
  return new Map(sortedPairs(map, COUNTER_KEEP));
}

class Analyzer {
  constructor(){
    this.sources = new Map();
    this.perSecond = new Map();
    this.destCounter = new Map();
    this.totalPackets = 0;
    this.totalBytes = 0;
    this.firstSeen = null;
    this.lastSeen = null;
    this.overflowNetworks = new Map();
    this.overflowPackets = 0;
    this.overflowSources = new Set();
    this.capped = false;
    this.names = {};

    // Who this machine is, and what kind of capture this is. A file read in a
    // browser knows neither, so these stay empty and nothing changes. A live
    // capture fills them in, and that is what stops the tool calling your own
    // laptop an attacker.
    this.localIps = new Set();
    this.mode = "file";
    this.dropLoopback = false;
    this.sentTo = new Map();
    this.droppedLoopback = 0;
  }

  ingest(ts, p){
    if(this.dropLoopback && (isLoopback(p.src) || isLoopback(p.dst))){
      this.droppedLoopback++;
      return;
    }
    bump(this.sentTo, p.dst);   // what was addressed to each machine

    let s = this.sources.get(p.src);
    if(s === undefined){
      if(this.sources.size >= MAX_SOURCES){
        this.capped = true;
        bump(this.overflowNetworks, networkOf(p.src));
        this.overflowPackets++;
        if(this.overflowSources.size < 100000) this.overflowSources.add(p.src);
        this.totals(ts, p);
        return;
      }
      s = { packets:0, bytes:0, first:null, last:null,
            protocols:new Map(), dports:new Map(), sports:new Map(),
            sizes:new Map(), ttls:new Map(), targets:new Map(),
            syn:0, ack:0, rst:0, fin:0, otherFlags:0,
            buckets:new Map(), recent:[], pruned:false,
            family:p.family, fragments:0 };
      this.sources.set(p.src, s);
    }

    s.packets++;
    s.bytes += p.size;
    if(s.first === null || ts < s.first) s.first = ts;
    if(s.last === null || ts > s.last) s.last = ts;
    bump(s.protocols, PROTO_NAMES[p.proto] || String(p.proto));
    bump(s.sizes, p.size);
    bump(s.ttls, p.ttl);
    bump(s.targets, p.dst);
    if(p.fragment) s.fragments++;
    if(p.dport !== null) bump(s.dports, p.dport);
    if(p.sport !== null) bump(s.sports, p.sport);

    const f = p.flags;
    if(f){
      if((f & SYN) && !(f & ACK)) s.syn++;
      else if(f & ACK) s.ack++;
      else if(f & RST) s.rst++;
      else s.otherFlags++;
      if(f & FIN) s.fin++;
    }
    bump(s.buckets, Math.floor(ts));

    if(s.recent.length < RECENT_PACKETS){
      s.recent.push({ ts: Math.round(ts*10000)/10000, dst:p.dst, proto:p.proto,
                      sport:p.sport, dport:p.dport, flags:p.flags, size:p.size, ttl:p.ttl });
    }

    if(s.packets % 512 === 0){
      for(const key of ["dports","sports","sizes","targets"]){
        if(s[key].size > MAX_COUNTER){ s[key] = pruneMap(s[key]); s.pruned = true; }
      }
      if(s.buckets.size > MAX_BUCKETS){
        const merged = new Map();
        for(const [b, c] of s.buckets) merged.set(Math.floor(b/2), (merged.get(Math.floor(b/2))||0) + c);
        s.buckets = merged;
      }
    }
    this.totals(ts, p);
  }

  totals(ts, p){
    bump(this.destCounter, p.dst);
    bump(this.perSecond, Math.floor(ts));
    this.totalPackets++;
    this.totalBytes += p.size;
    if(this.firstSeen === null || ts < this.firstSeen) this.firstSeen = ts;
    if(this.lastSeen === null || ts > this.lastSeen) this.lastSeen = ts;
  }

  isConversation(ip, s){
    const outbound = this.sentTo.get(ip) || 0;
    if(outbound < 3) return false;
    // A flood gets answers too. Answers are not agreement.
    if(s.syn >= 15 && s.ack === 0) return false;
    const [topDport] = s.dports.size ? topOf(s.dports) : [null];
    if(topDport !== null && ADMIN_PORTS.has(topDport) && s.syn >= 15) return false;
    if(topDport === 53 && s.packets >= 80 && (s.bytes / s.packets) > 110) return false;
    const [topSport] = s.sports.size ? topOf(s.sports) : [null];
    if(topSport !== null && AMPLIFIER_PORTS[topSport] && outbound < s.packets * 0.02) return false;
    return true;
  }

  score(s, ip){
    // Our own address is not a visitor.
    if(ip !== undefined && this.localIps.has(ip)){
      return { level:"normal", score:0,
               reasons:["this is this machine's own traffic going out, not somebody sending to you"],
               rate: s.packets / Math.max((s.last||0) - (s.first||0), 1.0), isScan:false };
    }

    let score = 0;
    const reasons = [];
    const duration = Math.max((s.last || 0) - (s.first || 0), 0.001);
    const rate = s.packets / Math.max(duration, 1.0);

    // A device on your own network is not a visitor, so "busier than a
    // visitor" says nothing about it.
    const indoors = ip !== undefined && isPrivate(ip) && !this.localIps.has(ip);
    let indoorsNote = "";

    if(indoors){
      if(rate >= 50) indoorsNote = "busy, at about " + Math.floor(rate) + " packets a second, which "
        + "is normal for a device on your own network rather than something to worry about";
    } else if(rate >= 200){ score += 45; reasons.push("sending about "+Math.floor(rate)+" packets a second, far above anything a normal visitor does"); }
    else if(rate >= 50){ score += 30; reasons.push("sending about "+Math.floor(rate)+" packets a second, much faster than a person browsing"); }
    else if(rate >= 12){ score += 12; reasons.push("sending about "+Math.floor(rate)+" packets a second, busier than a typical visitor"); }

    const distinctPorts = s.dports.size;
    const isScan = s.syn >= 15 && distinctPorts >= 10;
    if(isScan){
      score += 45;
      reasons.push("knocked on "+distinctPorts+" different ports without completing a single connection, which is somebody mapping out what you have running rather than flooding you");
    } else if(s.syn >= 20 && s.ack === 0 && distinctPorts <= 3){
      score += 40;
      reasons.push("opened "+s.syn+" connections and never completed a single one, all against the same service, which is the signature of a SYN flood");
    } else if(s.syn >= 10 && s.ack < s.syn/10 && distinctPorts <= 3){
      score += 25;
      reasons.push("started "+s.syn+" connections but finished almost none of them");
    }

    const [topSport, sportCount] = topOf(s.sports);
    if(topSport !== null && AMPLIFIER_PORTS[topSport] && sportCount > 5){
      const avg = s.bytes / s.packets;
      score += 40;
      reasons.push("traffic is arriving from "+AMPLIFIER_PORTS[topSport]+" (port "+topSport+") at an average of "+Math.floor(avg)+" bytes a packet, which means this server is being used to reflect and amplify an attack");
    }

    if(!indoors && s.packets >= 20 && s.sizes.size){
      const [, topSizeCount] = topOf(s.sizes);
      if(topSizeCount / s.packets > 0.95){
        score += 15;
        reasons.push("every packet is exactly the same size, so this is generated by a tool rather than a real browser");
      }
    }

    const topDportAll = s.dports.size ? topOf(s.dports)[0] : null;
    for(const [port, count] of sortedPairs(s.dports, 3)){
      if(SENSITIVE_PORTS[port] && count > 5){
        if(port === 22 || port === 3389 || port === 445){
          score += 20;
          reasons.push("aimed at "+SENSITIVE_PORTS[port]+" (port "+port+"), which should not be open to the whole internet in the first place");
        } else {
          score += 5;
          reasons.push("aimed at your "+SENSITIVE_PORTS[port]+" (port "+port+")");
        }
        break;
      }
    }

    // Knocking on a remote access door over and over is password guessing.
    if(topDportAll !== null && ADMIN_PORTS.has(topDportAll) && s.syn >= 20){
      score += 35;
      reasons.push("opened " + s.syn + " separate connections to "
        + (SENSITIVE_PORTS[topDportAll] || "a remote access port")
        + ". Traffic this repetitive against a login is password guessing, not somebody using the service");
    }

    // Far more name lookups than looking up names needs.
    if(topDportAll === 53 && s.packets >= 80){
      const average = s.bytes / s.packets;
      if(average > 110){
        score += 45;
        reasons.push("sent " + s.packets.toLocaleString() + " name lookups averaging "
          + Math.floor(average) + " bytes each. Real hostnames are short, so questions this long "
          + "usually mean data is being carried out of the network inside DNS");
      }
    }

    const reflected = topSport !== null && !!AMPLIFIER_PORTS[topSport];
    if(!indoors && !isScan && !reflected && distinctPorts >= 15 && s.packets >= 30){
      score += 15;
      reasons.push("spread its traffic across "+distinctPorts+" different ports, so a simple rule blocking one port will not stop it");
    }

    if((s.protocols.get("ICMP") || 0) + (s.protocols.get("ICMPv6") || 0) > 50){
      score += 20;
      reasons.push("flooding with ping traffic, which is only ever used to consume your bandwidth");
    }

    if(ip !== undefined && this.isConversation(ip, s)){
      score = Math.min(score, 12);
      const outbound = this.sentTo.get(ip) || 0;
      reasons.unshift("your machine sent " + outbound.toLocaleString() + " packets to this address "
        + "as well, so this is a two way conversation your side started rather than traffic being "
        + "aimed at you");
    }
    if(indoorsNote) reasons.push(indoorsNote);

    let level;
    if(score >= 70) level = "critical";
    else if(score >= 40) level = "high";
    else if(score >= 15) level = "watch";
    else { level = "normal"; if(!reasons.length) reasons.push("behaving like an ordinary visitor"); }

    return { level, score: Math.min(score, 100), reasons, rate, isScan };
  }

  fingerprint(row, s){
    const [topSize] = s.sizes.size ? topOf(s.sizes) : [0];
    const [topTtl] = s.ttls.size ? topOf(s.ttls) : [0];
    const initial = guessInitialTtl(topTtl)[0];
    let shape = "stateless";
    if(row.syn && !row.ack) shape = "syn-only";
    else if(row.ack) shape = "established";
    else if(s.rst) shape = "reset";
    let band = "slow";
    if(row.rate >= 200) band = "very-fast";
    else if(row.rate >= 50) band = "fast";
    else if(row.rate >= 12) band = "steady";
    const sport = s.sports.size > 20 ? "random"
                : (row.top_sport !== null ? row.top_sport : "-");
    return [row.protocol, "dport:"+(row.top_dport !== null ? row.top_dport : "-"),
            "sport:"+sport, "size:"+(topSize||0), "ttl:"+initial, shape, band].join("|");
  }

  rows(){
    const out = [];
    for(const [ip, s] of this.sources){
      const verdict = this.score(s, ip);
      const [topDport] = s.dports.size ? topOf(s.dports) : [null];
      const [topSport] = s.sports.size ? topOf(s.sports) : [null];
      const [protocol] = s.protocols.size ? topOf(s.protocols) : ["none"];
      const row = {
        ip, scan: verdict.isScan, region: regionOf(ip), network: networkOf(ip),
        level: verdict.level, score: verdict.score, reasons: verdict.reasons,
        packets: s.packets, bytes: s.bytes, rate: Math.round(verdict.rate*10)/10,
        first: s.first, last: s.last, protocol,
        top_dport: topDport, top_sport: topSport,
        ports_touched: s.dports.size, targets_touched: s.targets.size,
        syn: s.syn, ack: s.ack, rst: s.rst, family: s.family,
        hostname: this.names[ip] || ""
      };
      row.fingerprint = this.fingerprint(row, s);
      out.push(row);
    }
    out.sort((a,b) => (b.score - a.score) || (b.packets - a.packets));
    return out;
  }

  detail(ip){
    const s = this.sources.get(ip);
    if(!s) return null;
    const verdict = this.score(s, ip);
    const [topDport] = s.dports.size ? topOf(s.dports) : [null];
    const [topSport] = s.sports.size ? topOf(s.sports) : [null];
    const [protocol] = s.protocols.size ? topOf(s.protocols) : ["none"];
    const row = { protocol, top_dport: topDport, top_sport: topSport,
                  syn: s.syn, ack: s.ack, rate: verdict.rate };
    const [topTtl] = s.ttls.size ? topOf(s.ttls) : [0];
    const [initial, osGuess, hops] = guessInitialTtl(topTtl);
    const base = Math.floor(this.firstSeen || 0);
    const timeline = [...s.buckets.entries()].map(([b,c]) => [b - base, c]).sort((a,b)=>a[0]-b[0]);

    return {
      ip, hostname: this.names[ip] || "", family: s.family,
      level: verdict.level, score: verdict.score, reasons: verdict.reasons,
      rate: Math.round(verdict.rate*10)/10, packets: s.packets, bytes: s.bytes,
      first: s.first, last: s.last,
      duration: Math.round(((s.last||0) - (s.first||0))*1000)/1000,
      share_of_capture: Math.round(1000 * s.packets / Math.max(this.totalPackets,1))/10,
      region: regionOf(ip), network: networkOf(ip), private: isPrivate(ip),
      fingerprint: this.fingerprint(row, s), scan: verdict.isScan,
      fragments: s.fragments, counters_pruned: s.pruned,
      host: { observed_ttl: topTtl, initial_ttl: initial, os_guess: osGuess,
              hops_away: hops, distinct_ttls: s.ttls.size },
      flags: { syn:s.syn, ack:s.ack, rst:s.rst, fin:s.fin, other:s.otherFlags },
      protocols: sortedPairs(s.protocols, 6),
      dports: sortedPairs(s.dports, 12).map(([p,n]) => [p, n, PORT_NAMES[p] || null]),
      sports: sortedPairs(s.sports, 8).map(([p,n]) => [p, n, PORT_NAMES[p] || null]),
      targets: sortedPairs(s.targets, 10),
      sizes: sortedPairs(s.sizes, 6),
      timeline, recent: s.recent
    };
  }

  cohorts(rows, minimum){
    minimum = minimum || 3;
    const groups = new Map();
    for(const r of rows){
      if(!groups.has(r.fingerprint)) groups.set(r.fingerprint, []);
      groups.get(r.fingerprint).push(r);
    }
    const out = [];
    for(const [signature, members] of groups){
      if(members.length < minimum) continue;
      const regions = new Map();
      for(const m of members) bump(regions, m.region);
      out.push({
        fingerprint: signature, members: members.length,
        packets: members.reduce((n,m) => n + m.packets, 0),
        hostile: members.filter(m => m.level === "critical" || m.level === "high").length,
        level: members[0].level, example: members[0].ip,
        description: describeFingerprint(signature),
        regions: sortedPairs(regions, 3)
      });
    }
    out.sort((a,b) => b.packets - a.packets);
    return out;
  }

  summarise(rows, topN){
    topN = topN || 40;
    const window = Math.max((this.lastSeen || 0) - (this.firstSeen || 0), 1.0);
    const counts = {};
    for(const r of rows) counts[r.level] = (counts[r.level] || 0) + 1;
    const hostile = rows.filter(r => r.level === "critical" || r.level === "high");
    const hostilePackets = hostile.reduce((n,r) => n + r.packets, 0);

    const vectors = new Set();
    for(const r of hostile){
      if(r.scan) vectors.add("port_scan");
      else if(r.syn > 10 && r.ack === 0) vectors.add("syn_flood");
      if(AMPLIFIER_PORTS[r.top_sport]) vectors.add("amplification_" + AMPLIFIER_PORTS[r.top_sport]);
      if(r.protocol === "ICMP" || r.protocol === "ICMPv6") vectors.add("icmp_flood");
      if(ADMIN_PORTS.has(r.top_dport)){
        vectors.add("exposed_admin_port");
        if(r.syn >= 20) vectors.add("brute_force");
      }
      if(r.top_dport === 53 && r.packets >= 80) vectors.add("dns_tunnel");
      if(r.protocol === "UDP" && !AMPLIFIER_PORTS[r.top_sport]) vectors.add("udp_flood");
    }

    const timeline = [];
    let step = 1;
    if(this.perSecond.size){
      const seconds = [...this.perSecond.keys()];
      const start = Math.min(...seconds), end = Math.max(...seconds);
      const span = end - start + 1;
      step = Math.max(1, Math.floor(span / 4000));
      for(let sec = start; sec <= end; sec += step){
        let total = 0;
        for(let o = 0; o < step; o++) total += this.perSecond.get(sec + o) || 0;
        timeline.push(total);
      }
    }

    const regions = new Map(), hostileRegions = new Map();
    for(const r of rows){
      regions.set(r.region, (regions.get(r.region)||0) + r.packets);
      if(r.level === "critical" || r.level === "high")
        hostileRegions.set(r.region, (hostileRegions.get(r.region)||0) + r.packets);
    }
    const protocols = new Map(), ports = new Map();
    for(const [, s] of this.sources){
      for(const [n, c] of s.protocols) protocols.set(n, (protocols.get(n)||0) + c);
      for(const [p, c] of s.dports) ports.set(p, (ports.get(p)||0) + c);
    }

    const [mainTarget] = this.destCounter.size ? topOf(this.destCounter) : ["unknown"];
    const vectorList = [...vectors].sort();

    const summary = {
      duration_seconds: Math.round(window*10)/10,
      started_at: this.firstSeen, ended_at: this.lastSeen,
      total_packets: this.totalPackets, total_bytes: this.totalBytes,
      sources_total: this.sources.size + this.overflowSources.size,
      mode: this.mode,
      local_ips: [...this.localIps].sort(),
      dropped_loopback: this.droppedLoopback,
      counts, hostile_sources: hostile.length, hostile_packets: hostilePackets,
      hostile_share: Math.round(1000 * hostilePackets / Math.max(this.totalPackets,1))/10,
      peak_per_second: timeline.length ? Math.max(...timeline) : 0,
      average_per_second: Math.round(10 * this.totalPackets / Math.max(window,1))/10,
      main_target: mainTarget || "unknown",
      targets: sortedPairs(this.destCounter, 8),
      timeline, timeline_step: step,
      sources: rows.slice(0, topN),
      all_source_count: rows.length,
      regions: sortedPairs(regions, 8),
      hostile_regions: sortedPairs(hostileRegions, 8),
      protocols: sortedPairs(protocols, 6),
      ports: sortedPairs(ports, 8),
      vectors: vectorList,
      cohorts: this.cohorts(rows).slice(0, 6),
      verdict: verdictFor(vectorList, hostile.length, hostilePackets, this.totalPackets,
                          hostile, this.localIps),
      recommendations: recommendationsFor(vectorList, sortedPairs(hostileRegions, 8), rows)
    };

    if(this.capped){
      summary.capped = {
        tracked: this.sources.size,
        extra_sources_seen: this.overflowSources.size,
        extra_packets: this.overflowPackets,
        top_networks: sortedPairs(this.overflowNetworks, 8),
        note: "This capture had more source addresses than the tool tracks individually ("
              + MAX_SOURCES.toLocaleString() + "). Everything past that point is still counted, "
              + "but grouped by network instead of by address. The totals are right, the per "
              + "address list is the busiest ones."
      };
    }
    return summary;
  }
}

function describeFingerprint(signature){
  const chunks = signature.split("|");
  const parts = {};
  const order = [];
  for(const chunk of chunks){
    const at = chunk.indexOf(":");
    if(at >= 0) parts[chunk.slice(0, at)] = chunk.slice(at+1);
    else order.push(chunk);
  }
  const protocol = chunks[0];
  const dport = parts.dport || "-", sport = parts.sport || "-", size = parts.size || "0";
  const shape = order[1] || "", band = order[2] || "";
  const where = (dport !== "-" && dport !== "null") ? "port " + dport : "no fixed port";
  const how = {"syn-only":"opening connections and never finishing them",
    "established":"completing normal connections","reset":"sending resets",
    "stateless":"sending one way traffic"}[shape] || shape;
  const speed = {"very-fast":"very fast","fast":"fast","steady":"steadily","slow":"slowly"}[band] || band;
  const initial = parseInt(parts.ttl || "0", 10);
  const system = {64:"Linux or Unix",128:"Windows",255:"network gear"}[initial] || "an unknown system";
  const fromWhere = sport === "random" ? "from random source ports"
    : ((sport !== "-" && sport !== "null") ? "from port " + sport : "with no source port");
  return protocol + " at " + where + " " + fromWhere + ", " + how + ", " + speed
       + ", packets of " + size + " bytes, sent by " + system;
}

function ruleFor(row){
  if(row.scan) return ["FLOOD.SCAN.PORTSWEEP",
    "walked across " + (row.ports_touched || 0) + " ports looking for something open"];
  if(AMPLIFIER_PORTS[row.top_sport]) return [
    "FLOOD.AMP." + AMPLIFIER_PORTS[row.top_sport].toUpperCase().replace(/ /g, ""),
    "reflected off a " + AMPLIFIER_PORTS[row.top_sport] + " server, arriving already multiplied"];
  if(row.syn > 10 && !row.ack) return ["FLOOD.TCP.SYN",
    "opened " + row.syn + " connections and finished none of them"];
  if(row.protocol === "ICMP" || row.protocol === "ICMPv6")
    return ["FLOOD.ICMP.ECHO", "ping traffic sent only to use up bandwidth"];
  if(row.top_dport === 22 || row.top_dport === 3389 || row.top_dport === 445)
    return ["PROBE.ADMIN.PORT", "probing " + (SENSITIVE_PORTS[row.top_dport] || "a remote access port")
            + ", which should not face the internet"];
  if(row.protocol === "UDP") return ["FLOOD.UDP.GENERIC", "one way UDP aimed at filling the line"];
  if(row.level === "critical" || row.level === "high")
    return ["TRAFFIC.HOSTILE", "behaving unlike a normal visitor"];
  return ["TRAFFIC.OBSERVED", "ordinary traffic"];
}

function verdictFor(vectors, hostileCount, hostilePackets, total, hostile, localIps){
  /* Say what this is, and do not say more than the evidence supports.

     The word "attack" has to be earned. Traffic that does not look like a
     person browsing is also what a backup, a game, a software update and a
     smart TV look like. Calling all of that an attack trains people to ignore
     the warning that matters. */
  hostile = hostile || [];
  localIps = localIps || new Set();

  const outside = hostile.filter(r => !isPrivate(r.ip) && !isLoopback(r.ip) && !localIps.has(r.ip));
  const indoors = hostile.filter(r => outside.indexOf(r) < 0);

  if(!vectors.length || hostileCount === 0)
    return ["Nothing here looks like an attack",
      "Every address in this capture behaves the way ordinary use looks. That is the answer most "
      + "of the time, and it is worth having in writing."];

  if(!outside.length){
    const misbehaving = indoors.filter(r => r.scan || (r.syn || 0) > 20);
    if(misbehaving.length){
      const which = misbehaving.slice(0,3).map(r => r.ip).join(", ");
      return ["Nobody is attacking you, but look at one of your own devices",
        "Nothing is coming at you from outside. What did stand out is on your own network: "
        + which + (misbehaving.length === 1 ? " is" : " are") + " behaving in a way an ordinary "
        + "device does not, by knocking on many ports or opening connections it never finishes. "
        + "That is worth identifying. It is usually a scanner somebody installed, a security tool "
        + "doing its job, or a device that has been taken over. Open it in the list to see exactly "
        + "what it did."];
    }
    const where = indoors.length ? "your own network" : "this machine";
    return ["Nothing here looks like an attack",
      "Some addresses are busier than a person browsing, but all of them are on " + where + ". "
      + "Devices on your own network are busy for ordinary reasons: backups, updates, streaming, "
      + "phones syncing photos. Have a look at the list if you want to know what yours are doing, "
      + "but there is no sign of anybody attacking you here."];
  }

  const share = 100 * hostilePackets / Math.max(total, 1);
  const amplified = vectors.some(v => v.startsWith("amplification_"));
  // Volume is not the only thing that makes something an attack. Password
  // guessing and data leaving the building are both quiet by design.
  const deliberate = vectors.includes("brute_force") || vectors.includes("dns_tunnel");
  const realFlood = outside.length >= 5 || amplified || deliberate
                 || (share > 50 && outside.length >= 2);

  if(!realFlood){
    const names = outside.slice(0,3).map(r => r.ip).join(", ");
    return ["Worth a look, but not an attack",
      outside.length + " address" + (outside.length === 1 ? "" : "es") + " from outside your "
      + "network (" + names + ") sent traffic that does not look like ordinary browsing. That is "
      + "not enough to call it an attack. One busy address is usually a download, an update "
      + "server, a badly behaved app or a scanner having a quick look at everything on the "
      + "internet. Open it in the list and the reasons are spelled out."];
  }

  const kinds = [];
  if(vectors.includes("syn_flood"))
    kinds.push("a SYN flood, which fills up the connection table so real customers cannot get in");
  const amp = vectors.filter(v => v.startsWith("amplification_")).map(v => v.split("_")[1]).sort();
  if(amp.length){
    const names = amp.length < 3 ? amp.join(" and ")
                : amp.slice(0,-1).join(", ") + " and " + amp[amp.length-1];
    kinds.push("a reflection attack bounced off " + names
      + " servers, which multiplies the attacker's bandwidth against you");
  }
  if(vectors.includes("udp_flood")) kinds.push("a plain UDP flood aimed at saturating the line");
  if(vectors.includes("icmp_flood")) kinds.push("a ping flood");
  if(vectors.includes("port_scan"))
    kinds.push("at least one host scanning your ports, which is a separate problem from the flood and worth looking at once the dust settles");
  if(vectors.includes("brute_force"))
    kinds.push("password guessing against a login that faces the internet, which is patient rather than loud and works eventually if nobody is watching");
  else if(vectors.includes("exposed_admin_port"))
    kinds.push("probing of remote access ports that are open to the internet");
  if(vectors.includes("dns_tunnel"))
    kinds.push("name lookups being used to carry data out of the network, which is how information leaves a building that blocks everything else");

  let what, lead;
  if(kinds.length === 1){ what = kinds[0]; lead = "What is happening: "; }
  else { what = kinds.slice(0,-1).join(", ") + ", and finally " + kinds[kinds.length-1];
         lead = "There is more than one thing going on at once here: "; }

  let body = "About " + Math.round(share) + "% of all traffic in this capture comes from addresses "
    + "that do not behave like visitors. " + lead + what + ". It is arriving from several "
    + "addresses at the same time, which is what makes it distributed, and why blocking them by "
    + "hand as they appear will never catch up.";
  if(indoors.length)
    body += " " + indoors.length + " busy address" + (indoors.length === 1 ? "" : "es")
      + " on your own network " + (indoors.length === 1 ? "is" : "are") + " counted separately, "
      + "because a device of yours being busy is not an attack.";

  const headline = (deliberate && outside.length < 5 && !amplified)
    ? "Deliberate, and not loud enough to notice by accident"
    : "Under attack from " + outside.length + " source" + (outside.length === 1 ? "" : "s");
  return [headline, body];
}

function recommendationsFor(vectors, hostileRegions, rows){
  const out = [];
  if(vectors.includes("syn_flood")) out.push(["Turn on SYN cookies and connection rate limits",
    "Your server is holding open thousands of half finished connections. Enabling SYN cookies lets it answer without reserving memory for each one, and a connection rate limit per address stops one machine opening thousands. Both are settings you already have, on the firewall or the server itself.","high"]);
  const amp = vectors.filter(v => v.startsWith("amplification_")).map(v => v.split("_")[1]);
  if(amp.length) out.push(["Ask your provider to filter reflected " + [...new Set(amp)].join(", ") + " traffic upstream",
    "This traffic arrives already multiplied, so blocking it at your own firewall does not help, the line is full before it gets there. It has to be filtered before it reaches you, and your hosting or internet provider is the one who can do that.","high"]);
  if(vectors.includes("port_scan")) out.push(["Look at what the scanner found, not just that it scanned",
    "Somebody walked across your ports looking for something to talk to. That is reconnaissance and it usually comes before an attempt rather than during one. The useful question is what answered.","medium"]);
  if(vectors.includes("exposed_admin_port")) out.push(["Close remote access to the open internet",
    "Remote Desktop, SSH or Windows file sharing were being probed from outside. None of those should be reachable from the whole internet. Put them behind a VPN, or limit them to the addresses your own people use.","high"]);
  if(vectors.includes("udp_flood")) out.push(["Drop unexpected UDP at the edge",
    "Plain UDP flooding aims to fill the line rather than break anything clever. Rate limiting it upstream is what helps, for the same reason as above.","medium"]);
  if(vectors.includes("icmp_flood")) out.push(["Rate limit ping traffic",
    "Ping has legitimate uses so blocking it entirely causes its own problems. Rate limiting it does not.","low"]);

  const hostile = rows.filter(r => r.level === "critical" || r.level === "high");
  if(hostile.length){
    const nets = new Map();
    for(const r of hostile) nets.set(r.network, (nets.get(r.network)||0) + 1);
    const clustered = sortedPairs(nets, 5).filter(([, c]) => c >= 3).map(([n]) => n);
    if(clustered.length) out.push(["Block by network, not by address",
      "The hostile addresses cluster into a few networks (" + clustered.slice(0,3).join(", ")
      + "). Blocking those ranges stops more of this than blocking addresses one at a time, which you will never keep up with when they rotate.","medium"]);
  }
  if(hostileRegions.length){
    const [topRegion, topCount] = hostileRegions[0];
    const totalHostile = hostileRegions.reduce((n, r) => n + r[1], 0);
    if(totalHostile && topCount/totalHostile > 0.6 && topRegion.indexOf("private") < 0)
      out.push(["Consider limiting traffic from " + topRegion + " while the attack is running",
        "Most of the hostile traffic here was allocated in " + topRegion + ". If you have no customers there, geographic filtering at the edge is a blunt tool that works. If you do have customers there, do not do this.","medium"]);
  }
  out.push(["Write down what normal looks like",
    "Take a capture on an ordinary day and keep it. Half the difficulty in reading a capture like this one is not knowing what your own quiet traffic looks like. Ten minutes on a normal Tuesday is enough.","low"]);
  out.push(["Keep this capture",
    "Save the file somewhere safe with today's date. If this turns into an insurance claim, a police report or a conversation with your provider, the capture is the evidence and it cannot be recreated afterwards.","low"]);
  return out;
}

/* --------------------------------------------------------------------
   Reading the file. Streamed, so a huge capture works the same as a
   small one and the page can show honest progress while it happens.
   -------------------------------------------------------------------- */
function newStats(){
  return { frames:0, used:0, linkTypes:{}, skipped:{}, truncated:false,
           format:"unknown", compressed:false, names:{}, interfaces:[] };
}

function explain(stats){
  if(stats.used) return "";
  if(!stats.frames) return "The file opened but contained no packet records at all.";
  const parts = [];
  const reasons = Object.entries(stats.skipped).sort((a,b) => b[1]-a[1]);
  for(const [reason, count] of reasons) parts.push(reason + " (" + count.toLocaleString() + " frames)");
  const supported = {0:1,1:1,9:1,12:1,14:1,101:1,108:1,113:1,228:1,229:1,276:1};
  const unknown = Object.keys(stats.linkTypes).filter(lt => !supported[lt]);
  if(unknown.length){
    parts.push("the capture is " + unknown.map(lt =>
      (LINK_NAMES[lt] || "an unrecognised link layer") + " (link type " + lt + ")").join(", ")
      + ", which this tool does not decode");
  }
  if(!parts.length) return "The frames were readable but none of them carried IP traffic.";
  return "Read " + stats.frames.toLocaleString() + " frames, used none. " + parts.join("; ") + ".";
}

let analyzer = null;
let lastRows = null;
let lastStats = null;

/* Hand back the file a piece at a time, then one null to say that is the lot.

   The good path is file.stream(), which never holds more than a chunk. Safari
   does not always give us that on a page opened from disk, so there is a second
   way that slices the file by hand. Both keep memory flat; the fallback just
   has to un-gzip in one go first, because a slice of a gzip stream means
   nothing on its own. */
async function* fileChunks(file, gzipped){
  const CHUNK = 4 << 20;
  let delivered = 0;

  if(typeof file.stream === "function" && typeof ReadableStream !== "undefined"){
    let reader = null;
    try {
      let stream = file.stream();
      if(gzipped) stream = stream.pipeThrough(new DecompressionStream("gzip"));
      reader = stream.getReader();
    } catch(err){
      reader = null;                       // no stream here, try the other way
    }
    if(reader){
      try {
        while(true){
          const { done, value } = await reader.read();
          if(done) break;
          delivered++;
          yield value;
        }
        yield null;
        return;
      } catch(err){
        // Failing part way through means we cannot start again cleanly.
        if(delivered) throw err;
      }
    }
  }

  let source = file;
  if(gzipped){
    const whole = await file.arrayBuffer();
    const plain = await new Response(
      new Blob([whole]).stream().pipeThrough(new DecompressionStream("gzip"))
    ).arrayBuffer();
    source = new Blob([plain]);
  }
  for(let offset = 0; offset < source.size; offset += CHUNK){
    yield new Uint8Array(await source.slice(offset, offset + CHUNK).arrayBuffer());
  }
  yield null;
}

async function parseFile(file){
  const stats = newStats();
  analyzer = new Analyzer();

  const head = new Uint8Array(await file.slice(0, 4).arrayBuffer());
  if(head.length < 4) throw new Error("That file is too short to be a capture.");

  const gzipped = head[0] === 0x1f && head[1] === 0x8b;
  if(gzipped){
    stats.compressed = true;
    if(typeof DecompressionStream === "undefined")
      throw new Error("That file is gzipped and this browser cannot un-gzip it. Unzip it first and try again.");
  }

  const feed = new Feed();
  let rawRead = 0, lastPost = 0;
  const total = file.size;

  const post = (force) => {
    const now = Date.now();
    if(!force && now - lastPost < 120) return;
    lastPost = now;
    self.postMessage({ type:"progress", frames: stats.frames, used: stats.used,
      bytes: rawRead, total: stats.compressed ? 0 : total,
      sources: analyzer.sources.size, packets: analyzer.totalPackets });
  };

  // Work out which format we are in from the first four bytes.
  let mode = null, little = true, divisor = 1e6, linkType = 1;
  let pcapngEndian = true, interfaces = [];

  for await (const value of fileChunks(file, gzipped)){
    if(value === null){ feed.eof = true; }
    else { feed.push(value); rawRead += value.length; }
    const done = value === null;

    if(mode === null && feed.available >= 4){
      const magic = feed.u32(0, false);
      if(magic === 0x0a0d0d0a){ mode = "pcapng"; stats.format = "pcapng"; }
      else if(magic === 0xa1b2c3d4){ mode="pcap"; little=false; divisor=1e6; stats.format="pcap"; }
      else if(magic === 0xd4c3b2a1){ mode="pcap"; little=true;  divisor=1e6; stats.format="pcap"; }
      else if(magic === 0xa1b23c4d){ mode="pcap"; little=false; divisor=1e9; stats.format="pcap"; }
      else if(magic === 0x4d3cb2a1){ mode="pcap"; little=true;  divisor=1e9; stats.format="pcap"; }
      else throw new Error("That does not look like a capture file. traffic-analyzer reads pcap and pcapng files, the kind Wireshark and tcpdump write, optionally gzipped.");

      if(mode === "pcap"){
        if(feed.available < 24) { if(feed.eof) throw new Error("That file has a capture header but nothing after it."); continue; }
        linkType = feed.u32(20, little);
        stats.interfaces.push({ link_type: linkType, name: LINK_NAMES[linkType] || ("link type " + linkType) });
        feed.skip(24);
      }
    }

    if(mode === "pcap") readPcapRecords(feed, stats, little, divisor, linkType);
    else if(mode === "pcapng"){
      const result = readPcapngBlocks(feed, stats, pcapngEndian, interfaces);
      pcapngEndian = result.little;
      interfaces = result.interfaces;
    }

    feed.compact(false);
    post(false);
    if(done) break;
  }

  if(feed.available > 0 && stats.frames) stats.truncated = true;
  post(true);

  analyzer.names = stats.names;
  lastStats = stats;
  lastRows = analyzer.rows();
  const summary = analyzer.summarise(lastRows, 40);
  summary.read = {
    format: stats.format, compressed: stats.compressed, frames: stats.frames,
    used: stats.used, truncated: stats.truncated, skipped: stats.skipped,
    interfaces: stats.interfaces, link_types: stats.linkTypes, explain: explain(stats)
  };
  summary.origin = file.name;
  return summary;
}

function readPcapRecords(feed, stats, little, divisor, linkType){
  while(feed.available >= 16){
    const inclLen = feed.u32(8, little);
    if(inclLen > 0x400000){
      skip(stats, "a packet claimed an impossible size, so reading stopped here");
      stats.truncated = true;
      feed.pos = feed.len;
      return;
    }
    if(feed.available < 16 + inclLen) return;
    const sec = feed.u32(0, little), frac = feed.u32(4, little);
    const start = feed.pos + 16;
    stats.frames++;
    stats.linkTypes[linkType] = (stats.linkTypes[linkType] || 0) + 1;
    const packet = parseFrame(feed.buf, start, inclLen, linkType, stats);
    if(packet){
      stats.used++;
      analyzer.ingest(sec + frac/divisor, packet);
    }
    feed.skip(16 + inclLen);
  }
}

function readPcapngBlocks(feed, stats, little, interfaces){
  while(feed.available >= 12){
    const blockType = feed.u32(0, little);

    // The section header carries its own byte order mark. It is the one block
    // whose length we cannot read until we know which way round it is.
    if(blockType === 0x0a0d0d0a){
      if(feed.available < 12) return { little, interfaces };
      const markLittle = feed.buf[feed.pos+8] === 0x4d;
      little = markLittle;
      const total = feed.u32(4, little);
      if(total < 16 || feed.available < total) return { little, interfaces };
      feed.skip(total);
      interfaces = [];
      continue;
    }

    const total = feed.u32(4, little);
    if(total < 12 || total > 0x4000000){ stats.truncated = true; feed.pos = feed.len; return { little, interfaces }; }
    if(feed.available < total) return { little, interfaces };

    const body = feed.pos + 8;

    if(blockType === 1){                       // interface description
      const lt = feed.u16(8, little);
      let resolution = 1e6;
      let offset = body + 8;
      const optionEnd = feed.pos + total - 4;
      while(offset + 4 <= optionEnd){
        const code = little ? (feed.buf[offset] | (feed.buf[offset+1]<<8))
                            : ((feed.buf[offset]<<8) | feed.buf[offset+1]);
        const len  = little ? (feed.buf[offset+2] | (feed.buf[offset+3]<<8))
                            : ((feed.buf[offset+2]<<8) | feed.buf[offset+3]);
        offset += 4;
        if(code === 0) break;
        if(code === 9 && len >= 1){
          const value = feed.buf[offset];
          resolution = (value & 0x80) ? Math.pow(2, value & 0x7F) : Math.pow(10, value);
        }
        offset += len + ((4 - len % 4) % 4);
      }
      interfaces.push({ linkType: lt, resolution });
      stats.interfaces.push({ link_type: lt, name: LINK_NAMES[lt] || ("link type " + lt) });

    } else if(blockType === 6 || blockType === 2){   // enhanced or legacy packet
      let ifaceId, tsHi, tsLo, inclLen, dataAt;
      if(blockType === 6){
        ifaceId = feed.u32(8, little);
        tsHi = feed.u32(12, little); tsLo = feed.u32(16, little);
        inclLen = feed.u32(20, little);
        dataAt = body + 20;
      } else {
        ifaceId = feed.u16(8, little);
        tsHi = feed.u32(12, little); tsLo = feed.u32(16, little);
        inclLen = feed.u32(20, little);
        dataAt = body + 20;
      }
      const iface = interfaces[ifaceId] || { linkType: 1, resolution: 1e6 };
      stats.frames++;
      stats.linkTypes[iface.linkType] = (stats.linkTypes[iface.linkType] || 0) + 1;
      if(dataAt + inclLen <= feed.pos + total - 4){
        const packet = parseFrame(feed.buf, dataAt, inclLen, iface.linkType, stats);
        if(packet){
          stats.used++;
          analyzer.ingest((tsHi * 4294967296 + tsLo) / iface.resolution, packet);
        }
      }

    } else if(blockType === 3){                 // simple packet block
      const iface = interfaces[0] || { linkType: 1, resolution: 1e6 };
      stats.frames++;
      stats.linkTypes[iface.linkType] = (stats.linkTypes[iface.linkType] || 0) + 1;
      const length = total - 16;
      const packet = parseFrame(feed.buf, body + 4, length, iface.linkType, stats);
      if(packet){ stats.used++; analyzer.ingest(0, packet); }

    } else if(blockType === 4){                 // name resolution
      readNameRecords(feed, body, feed.pos + total - 4, little, stats);
    }

    feed.skip(total);
  }
  return { little, interfaces };
}

function readNameRecords(feed, start, end, little, stats){
  let offset = start;
  const b = feed.buf;
  while(offset + 4 <= end){
    const type = little ? (b[offset] | (b[offset+1]<<8)) : ((b[offset]<<8) | b[offset+1]);
    const len  = little ? (b[offset+2] | (b[offset+3]<<8)) : ((b[offset+2]<<8) | b[offset+3]);
    offset += 4;
    if(type === 0) break;
    if(type === 1 && len >= 5){
      const ip = ipv4Str(b, offset);
      let stop = offset + 4;
      while(stop < offset + len && b[stop] !== 0) stop++;
      const name = new TextDecoder().decode(b.subarray(offset+4, stop));
      if(name) stats.names[ip] = name;
    } else if(type === 2 && len >= 17){
      const ip = ipv6Str(b, offset);
      let stop = offset + 16;
      while(stop < offset + len && b[stop] !== 0) stop++;
      const name = new TextDecoder().decode(b.subarray(offset+16, stop));
      if(name) stats.names[ip] = name;
    }
    offset += len + ((4 - len % 4) % 4);
  }
}

/* --------------------------------------------------------------------
   Answering the page's questions once the file has been read. The page
   never holds the whole source list, it asks for a slice at a time, the
   same way the command line tool asks the database.
   -------------------------------------------------------------------- */
function pageOf(request){
  if(!lastRows) return { total: 0, rows: [], offset: 0 };
  let rows = lastRows;

  if(request.level && request.level !== "all") rows = rows.filter(r => r.level === request.level);
  if(request.network) rows = rows.filter(r => r.network === request.network);
  if(request.fingerprint) rows = rows.filter(r => r.fingerprint === request.fingerprint);
  if(request.q){
    const needle = request.q.toLowerCase();
    rows = rows.filter(r => r.ip.toLowerCase().indexOf(needle) >= 0
      || (r.hostname && r.hostname.toLowerCase().indexOf(needle) >= 0)
      || r.region.toLowerCase().indexOf(needle) >= 0
      || r.network.toLowerCase().indexOf(needle) >= 0);
  }

  const order = request.order || "score";
  if(order !== "score"){
    const compare = {
      packets:(a,b) => b.packets - a.packets,
      bytes:  (a,b) => b.bytes - a.bytes,
      rate:   (a,b) => b.rate - a.rate,
      ports:  (a,b) => b.ports_touched - a.ports_touched,
      ip:     (a,b) => compareIp(a.ip, b.ip)
    }[order];
    if(compare) rows = rows.slice().sort(compare);
  }

  const offset = request.offset || 0, limit = request.limit || 100;
  return { total: rows.length, offset, rows: rows.slice(offset, offset + limit) };
}

/* --------------------------------------------------------------------
   The replay: the capture laid out as a sequence of moments, so the page
   can play it back at whatever speed you like instead of only showing the
   finished total. Each step carries how many packets went past in that
   slice of time, and which addresses turned up for the first time.

   Only first-appearance is sent, not a full per second history for every
   address. A capture with a hundred thousand sources would be enormous
   that way, and the thing worth watching is when each one arrives.
   -------------------------------------------------------------------- */
function buildReplay(maxSteps){
  if(!analyzer || !lastRows || !analyzer.perSecond.size) return null;

  const seconds = [...analyzer.perSecond.keys()];
  const first = Math.min(...seconds), last = Math.max(...seconds);
  const span = Math.max(1, last - first + 1);
  const perStep = Math.max(1, Math.ceil(span / (maxSteps || 400)));
  const count = Math.ceil(span / perStep);

  const steps = [];
  for(let i = 0; i < count; i++) steps.push({ packets: 0, sources: [] });

  for(const [second, n] of analyzer.perSecond){
    const at = Math.min(count - 1, Math.floor((second - first) / perStep));
    steps[at].packets += n;
  }

  for(const row of lastRows){
    const seen = row.first === null || row.first === undefined ? first : Math.floor(row.first);
    const at = Math.min(count - 1, Math.max(0, Math.floor((seen - first) / perStep)));
    const [rule, message] = ruleFor(row);
    steps[at].sources.push({
      ip: row.ip, level: row.level, score: row.score, packets: row.packets,
      rate: row.rate, region: row.region, protocol: row.protocol,
      reason: (row.reasons && row.reasons[0]) || "", rule, message
    });
  }

  // Worst first inside a step, so the alert feed reads sensibly.
  for(const step of steps){
    step.sources.sort((a, b) => b.score - a.score || b.packets - a.packets);
  }

  return { first, seconds_per_step: perStep, total_seconds: span, steps };
}


function compareIp(a, b){
  const pa = a.split("."), pb = b.split(".");
  if(pa.length === 4 && pb.length === 4){
    for(let i=0;i<4;i++){ const d = (+pa[i]) - (+pb[i]); if(d) return d; }
    return 0;
  }
  return a < b ? -1 : (a > b ? 1 : 0);
}

function relatedTo(ip){
  if(!lastRows || !analyzer) return null;
  const me = lastRows.find(r => r.ip === ip);
  if(!me) return null;
  const peers = [], neighbours = [];
  for(const r of lastRows){
    if(r.ip === ip) continue;
    if(r.fingerprint === me.fingerprint) peers.push(r);
    if(r.network === me.network) neighbours.push(r);
  }
  const source = analyzer.sources.get(ip);
  let mainTarget = null;
  if(source && source.targets.size) mainTarget = topOf(source.targets)[0];
  const coTargets = [];
  if(mainTarget){
    for(const r of lastRows){
      if(r.ip === ip) continue;
      const other = analyzer.sources.get(r.ip);
      if(other && other.targets.has(mainTarget)) coTargets.push(r);
    }
  }
  const trim = list => list.slice(0, 8).map(r => ({ ip:r.ip, level:r.level, packets:r.packets,
    rate:r.rate, region:r.region, score:r.score }));
  return {
    peers: trim(peers), peer_total: peers.length,
    peer_packets: peers.reduce((n,r) => n + r.packets, 0),
    neighbours: trim(neighbours), neighbour_total: neighbours.length,
    co_targets: trim(coTargets), co_target_total: coTargets.length,
    main_target: mainTarget
  };
}

self.onmessage = async (event) => {
  const message = event.data;
  try {
    if(message.cmd === "ping"){
      // Used at startup to find out whether this engine is actually alive.
      self.postMessage({ type:"pong", id: message.id });
    } else if(message.cmd === "parse"){
      const summary = await parseFile(message.file);
      self.postMessage({ type:"done", summary, id: message.id });
    } else if(message.cmd === "page"){
      self.postMessage({ type:"page", page: pageOf(message), id: message.id });
    } else if(message.cmd === "detail"){
      self.postMessage({ type:"detail", id: message.id,
        detail: analyzer ? analyzer.detail(message.ip) : null,
        related: relatedTo(message.ip),
        rule: (() => { const r = lastRows && lastRows.find(x => x.ip === message.ip);
                       return r ? ruleFor(r) : null; })() });
    } else if(message.cmd === "alerts"){
      const hostile = (lastRows || []).filter(r => r.level === "critical" || r.level === "high");
      self.postMessage({ type:"alerts", id: message.id,
        alerts: hostile.slice(0, message.limit || 150).map(r => {
          const [rule, text] = ruleFor(r);
          return { ip:r.ip, level:r.level, rule, message:text, at:r.first, packets:r.packets };
        }) });
    } else if(message.cmd === "replay"){
      self.postMessage({ type:"replay", id: message.id, replay: buildReplay(message.steps) });
    } else if(message.cmd === "mapPoints"){
      const rows = lastRows || [];
      self.postMessage({ type:"mapPoints", id: message.id,
        points: rows.map(r => ({ ip:r.ip, level:r.level, region:r.region,
                                 packets:r.packets, score:r.score })) });
    }
  } catch(err){
    self.postMessage({ type:"error", id: message.id,
      message: (err && err.message) ? err.message : String(err) });
  }
};
