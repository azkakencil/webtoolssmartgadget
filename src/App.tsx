import { useState, useCallback, useRef, useEffect } from "react";

// ─────────────────────────────────────────────
//  TYPES
// ─────────────────────────────────────────────
type Tab = "html" | "css" | "js" | "all";


interface ExternalFile {
  url: string;
  content: string;
  size: string;
  ok: boolean;
}

interface ScrapedData {
  html: string;
  cssFiles: ExternalFile[];
  jsFiles: ExternalFile[];
  title: string;
  url: string;
  proxyUsed: string;
  fetchedAt: string;
}

// ─────────────────────────────────────────────
//  PROXY STRATEGIES
// ─────────────────────────────────────────────
type ProxyStrategy = {
  name: string;
  build: (url: string) => string;
  extract: (res: Response) => Promise<string>;
};

const PROXY_STRATEGIES: ProxyStrategy[] = [
  {
    name: "AllOrigins (raw)",
    build: (u) => `https://api.allorigins.win/raw?url=${encodeURIComponent(u)}`,
    extract: (r) => r.text(),
  },
  {
    name: "AllOrigins (json)",
    build: (u) => `https://api.allorigins.win/get?url=${encodeURIComponent(u)}`,
    extract: async (r) => {
      const j = await r.json();
      if (!j?.contents) throw new Error("empty contents");
      return j.contents;
    },
  },
  {
    name: "CorsProxy.io",
    build: (u) => `https://corsproxy.io/?url=${encodeURIComponent(u)}`,
    extract: (r) => r.text(),
  },
  {
    name: "CorsProxy.io (direct)",
    build: (u) => `https://corsproxy.io/?${encodeURIComponent(u)}`,
    extract: (r) => r.text(),
  },
  {
    name: "Cloudflare CORS-Anywhere",
    build: (u) => `https://test.cors.workers.dev/?${u}`,
    extract: (r) => r.text(),
  },
  {
    name: "CodeTabs",
    build: (u) => `https://api.codetabs.com/v1/proxy?quest=${encodeURIComponent(u)}`,
    extract: (r) => r.text(),
  },
  {
    name: "ThingProxy",
    build: (u) => `https://thingproxy.freeboard.io/fetch/${u}`,
    extract: (r) => r.text(),
  },
];

// ─────────────────────────────────────────────
//  HELPERS
// ─────────────────────────────────────────────
async function fetchViaProxy(targetUrl: string, timeoutMs = 12000): Promise<{ content: string; proxyName: string }> {
  for (const proxy of PROXY_STRATEGIES) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(proxy.build(targetUrl), { signal: controller.signal });
      clearTimeout(timer);
      if (!res.ok) continue;
      const content = await proxy.extract(res);
      if (!content || content.length < 20) continue;
      return { content, proxyName: proxy.name };
    } catch {
      clearTimeout(timer);
    }
  }
  throw new Error("Semua proxy gagal. Website mungkin memblokir semua permintaan eksternal.");
}

function resolveUrl(href: string, base: string): string {
  try {
    if (href.startsWith("//")) return "https:" + href;
    if (href.startsWith("http")) return href;
    return new URL(href, base).href;
  } catch { return href; }
}

function extractLinks(html: string, baseUrl: string, type: "css" | "js"): string[] {
  const seen = new Set<string>();
  const result: string[] = [];
  const patterns = type === "css"
    ? [/href=["']([^"'?#]*\.css[^"']*)/gi, /<link[^>]+href=["']([^"']+)["'][^>]*>/gi]
    : [/src=["']([^"'?#]*\.js[^"']*)/gi];
  for (const re of patterns) {
    let m: RegExpExecArray | null;
    while ((m = re.exec(html)) !== null) {
      const raw = m[1].trim();
      if (!raw || raw.startsWith("data:")) continue;
      if (type === "css" && !raw.includes(".css")) continue;
      if (type === "js" && !raw.includes(".js")) continue;
      const resolved = resolveUrl(raw, baseUrl);
      if (!seen.has(resolved)) { seen.add(resolved); result.push(resolved); }
    }
  }
  return result;
}

function extractTitle(html: string): string {
  const m = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  return m ? m[1].replace(/\s+/g, " ").trim() : "—";
}

function formatBytes(str: string): string {
  const b = new Blob([str]).size;
  if (b < 1024) return `${b} B`;
  if (b < 1048576) return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / 1048576).toFixed(2)} MB`;
}

// ─────────────────────────────────────────────
//  SECURITY TYPES & ENGINE
// ─────────────────────────────────────────────
type RiskLevel = "safe" | "suspicious" | "dangerous" | "unknown";

interface SecurityCheck {
  id: string;
  label: string;
  description: string;
  status: "pass" | "warn" | "fail" | "info";
  detail?: string;
}

interface SecurityResult {
  url: string;
  riskLevel: RiskLevel;
  riskScore: number;       // 0–100
  checks: SecurityCheck[];
  scannedAt: string;
  urlscanResult?: { verdict: string; screenshot?: string; reportUrl?: string } | null;
  safeBrowsingResult?: { threat: string } | null;
}

// ── Known-safe top domains ──
const KNOWN_SAFE_DOMAINS = new Set([
  "google.com","youtube.com","facebook.com","twitter.com","x.com",
  "instagram.com","linkedin.com","github.com","wikipedia.org","apple.com",
  "microsoft.com","amazon.com","netflix.com","reddit.com","tiktok.com",
  "whatsapp.com","zoom.us","dropbox.com","paypal.com","stripe.com",
  "shopify.com","wordpress.com","blogger.com","medium.com","substack.com",
  "cloudflare.com","vercel.app","netlify.app","heroku.com","digitalocean.com",
  "tokopedia.com","shopee.co.id","bukalapak.com","gojek.com","grab.com",
  "bca.co.id","bni.co.id","bri.co.id","mandiri.co.id","bankbsi.co.id",
]);

// ── Brand phishing keywords ──
const BRAND_KEYWORDS = [
  "paypal","amazon","apple","microsoft","google","facebook","instagram",
  "netflix","bank","secure","account","login","signin","verify","wallet",
  "crypto","coinbase","binance","blockchain","update","confirm","suspended",
  "tokopedia","shopee","bukalapak","gojek","grab","bca","bni","bri","mandiri",
  "icloud","steam","roblox","ebay","alibaba","lazada","traveloka",
];

// ── Suspicious TLDs ──
const SUSPICIOUS_TLDS = [".tk",".ml",".ga",".cf",".gq",".xyz",".top",".click",".loan",".work",".party",".icu",".pw",".cc",".su",".buzz"];

// ── Phishing HTML patterns ──
const PHISHING_HTML_PATTERNS = [
  { re: /<input[^>]+type=["']?password["']?/i,       label: "Form password", weight: 8 },
  { re: /document\.cookie/i,                          label: "Cookie stealing", weight: 12 },
  { re: /window\.location\s*=|location\.href\s*=/i,  label: "JS redirect", weight: 6 },
  { re: /base64_decode|eval\s*\(/i,                  label: "Obfuscated code", weight: 10 },
  { re: /<form[^>]+action=["'][^"']*http/i,          label: "External form action", weight: 10 },
  { re: /verify.{0,20}account|account.{0,20}suspend/i, label: "Urgent account text", weight: 8 },
  { re: /\bcaptcha\b|\bverif(y|ication)\b/i,         label: "CAPTCHA/verifikasi", weight: 4 },
  { re: /confirm.{0,20}(identity|payment|info)/i,    label: "Konfirmasi mencurigakan", weight: 8 },
  { re: /<iframe[^>]+src=["']https?:\/\/(?!(?:www\.)?(?:youtube|google|maps))/i, label: "Iframe eksternal", weight: 6 },
  { re: /phishing|malware|blocked|reported/i,        label: "Kata blokir", weight: 5 },
];

// ── URL-only checks ──
function analyzeUrlSecurity(rawUrl: string): SecurityCheck[] {
  const checks: SecurityCheck[] = [];
  let parsed: URL | null = null;
  try { parsed = new URL(rawUrl); } catch {
    checks.push({ id:"invalid", label:"URL tidak valid", description:"URL tidak dapat diurai.", status:"fail" });
    return checks;
  }

  const hostname = parsed.hostname.toLowerCase();
  const href = rawUrl.toLowerCase();
  const parts = hostname.split(".");
  const tld = "." + parts.slice(-1)[0];
  const domain = parts.slice(-2).join(".");
  const isKnownSafe = KNOWN_SAFE_DOMAINS.has(domain);

  // 1. HTTPS
  checks.push({
    id:"https", label:"HTTPS",
    description:"Koneksi terenkripsi melindungi data pengguna.",
    status: parsed.protocol==="https:" ? "pass" : "fail",
    detail: parsed.protocol==="https:" ? "Menggunakan HTTPS ✓" : "HTTP — tidak terenkripsi!",
  });

  // 2. IP langsung
  const isIP = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
  checks.push({
    id:"ip", label:"IP Langsung",
    description:"Website asli jarang menggunakan IP mentah.",
    status: isIP ? "fail" : "pass",
    detail: isIP ? `Host adalah IP: ${hostname} — sangat mencurigakan!` : "Nama domain normal ✓",
  });

  // 3. Panjang domain
  checks.push({
    id:"domainlen", label:"Panjang Domain",
    description:"Domain sangat panjang sering dipakai phishing.",
    status: hostname.length>50?"fail":hostname.length>30?"warn":"pass",
    detail: `${hostname.length} karakter${hostname.length>50?" — sangat mencurigakan!":hostname.length>30?" — cukup panjang":" ✓"}`,
  });

  // 4. TLD mencurigakan
  const isSuspTld = SUSPICIOUS_TLDS.some(t=>hostname.endsWith(t));
  checks.push({
    id:"tld", label:"TLD Mencurigakan",
    description:"TLD seperti .tk .ml .xyz sering dipakai situs palsu.",
    status: isSuspTld?"warn":"pass",
    detail: isSuspTld?`TLD '${tld}' sering dipakai phishing`:`TLD '${tld}' normal ✓`,
  });

  // 5. Subdomain berlebih
  const subCount = parts.length-2;
  checks.push({
    id:"subdomain", label:"Subdomain Berlebih",
    description:"Banyak subdomain menyamarkan domain asli.",
    status: subCount>3?"fail":subCount>1?"warn":"pass",
    detail: `${subCount} level${subCount>3?" — mencurigakan!":subCount>1?" — perlu dicek":" ✓"}`,
  });

  // 6. Brand spoofing di domain
  const brandHit = !isKnownSafe && BRAND_KEYWORDS.filter(b=>hostname.includes(b));
  const hasBrand = Array.isArray(brandHit)&&brandHit.length>0;
  checks.push({
    id:"brand", label:"Brand Spoofing",
    description:"Domain mengandung nama brand tapi bukan situs resminya.",
    status: hasBrand?"fail":"pass",
    detail: hasBrand
      ? `Nama '${brandHit[0]}' ditemukan di domain — bukan situs resmi!`
      : "Tidak ada indikasi brand spoofing ✓",
  });

  // 7. @ di URL
  const hasAt = href.includes("@");
  checks.push({
    id:"at", label:"Karakter '@' di URL",
    description:"Trik klasik phishing untuk menyembunyikan host asli.",
    status: hasAt?"fail":"pass",
    detail: hasAt?"Ditemukan '@' di URL — sangat mencurigakan!":"Tidak ada '@' ✓",
  });

  // 8. Panjang URL total
  checks.push({
    id:"urllen", label:"Panjang URL",
    description:"URL terlalu panjang biasanya mengaburkan tujuan asli.",
    status: rawUrl.length>200?"fail":rawUrl.length>100?"warn":"pass",
    detail: `${rawUrl.length} karakter${rawUrl.length>200?" — sangat panjang!":rawUrl.length>100?" — cukup panjang":" ✓"}`,
  });

  // 9. Banyak tanda hubung
  const hyphenCount=(hostname.match(/-/g)||[]).length;
  checks.push({
    id:"hyphen", label:"Tanda Hubung Berlebih",
    description:"Domain dengan banyak '-' sering dipakai typosquatting.",
    status: hyphenCount>3?"fail":hyphenCount>1?"warn":"pass",
    detail: `${hyphenCount} tanda '-'${hyphenCount>3?" — mencurigakan!":hyphenCount>1?" — perlu diperhatikan":" ✓"}`,
  });

  // 10. Karakter Unicode (homograph)
  const hasUnicode=/[^\x00-\x7F]/.test(hostname);
  checks.push({
    id:"unicode", label:"Karakter Unicode",
    description:"Karakter non-ASCII menyerupai huruf latin (homograph attack).",
    status: hasUnicode?"fail":"pass",
    detail: hasUnicode?"Ditemukan Unicode di domain — kemungkinan homograph attack!":"Karakter normal ✓",
  });

  // 11. Parameter redirect
  const hasRedirect=/(redirect|url=|next=|goto=|return=)/i.test(href);
  checks.push({
    id:"redirect", label:"Parameter Redirect",
    description:"Redirect param bisa mengarahkan ke situs berbahaya.",
    status: hasRedirect?"warn":"pass",
    detail: hasRedirect?"URL mengandung parameter redirect":"Tidak ada redirect param ✓",
  });

  // 12. Brand spoofing di PATH/query (lebih dalam)
  const pathQuery = (parsed.pathname+parsed.search).toLowerCase();
  const pathBrand = BRAND_KEYWORDS.filter(b=>pathQuery.includes(b));
  if (!hasBrand && pathBrand.length>0 && !isKnownSafe) {
    checks.push({
      id:"pathbrand", label:"Brand di Path URL",
      description:"Nama brand ditemukan di path/query padahal domain berbeda.",
      status:"warn",
      detail:`Kata '${pathBrand[0]}' ada di path URL — waspadai meski domain terlihat normal`,
    });
  }

  // 13. Double slash / obfuscation di URL
  const hasDoubleSlash=/https?:\/\/[^/]+\/.*\/\//.test(rawUrl);
  checks.push({
    id:"doubleslash", label:"Obfuskasi URL",
    description:"Double slash atau encoding tidak wajar bisa menyembunyikan tujuan.",
    status: hasDoubleSlash?"warn":"pass",
    detail: hasDoubleSlash?"Ditemukan double slash di path":"Struktur URL normal ✓",
  });

  // 14. Domain tepercaya
  if (isKnownSafe) {
    checks.push({
      id:"known", label:"Domain Tepercaya",
      description:"Domain ada dalam daftar situs terkenal & tepercaya.",
      status:"pass",
      detail:`${domain} adalah domain tepercaya ✓`,
    });
  }

  return checks;
}

// ── Analisis konten HTML (lebih dalam dari URL saja) ──
function analyzeHtmlContent(html: string, url: string): SecurityCheck[] {
  const checks: SecurityCheck[] = [];
  if (!html || html.length < 50) return checks;

  const hostname = (() => { try { return new URL(url).hostname.toLowerCase(); } catch { return ""; } })();
  const domain = hostname.split(".").slice(-2).join(".");
  const isKnownSafe = KNOWN_SAFE_DOMAINS.has(domain);

  // 1. Scan pola phishing di HTML
  let phishingHits: string[] = [];
  for (const p of PHISHING_HTML_PATTERNS) {
    if (p.re.test(html)) phishingHits.push(p.label);
  }
  if (phishingHits.length > 0) {
    checks.push({
      id:"htmlphish", label:"Pola Phishing di HTML",
      description:"Konten HTML mengandung pola yang sering dipakai phishing.",
      status: phishingHits.length>=3?"fail":"warn",
      detail:`Ditemukan: ${phishingHits.slice(0,3).join(", ")}${phishingHits.length>3?` (+${phishingHits.length-3} lagi)`:""}`
    });
  } else {
    checks.push({
      id:"htmlphish", label:"Pola Phishing di HTML",
      description:"Konten HTML tidak mengandung pola phishing umum.",
      status:"pass",
      detail:"Tidak ada pola phishing ditemukan di konten ✓"
    });
  }

  // 2. Form dengan action ke domain lain
  const formActions = [...html.matchAll(/<form[^>]+action=["']([^"']+)["']/gi)].map(m=>m[1]);
  const externalForms = formActions.filter(a=>{
    try { return new URL(a).hostname!==hostname; } catch { return false; }
  });
  checks.push({
    id:"formaction", label:"Form ke Domain Lain",
    description:"Form yang mengirim data ke domain berbeda — teknik phishing umum.",
    status: externalForms.length>0?"fail":"pass",
    detail: externalForms.length>0
      ? `${externalForms.length} form mengirim data ke domain lain: ${externalForms[0]}`
      : "Semua form aman (domain sama) ✓",
  });

  // 3. Password input
  const hasPassInput = /<input[^>]+type=["']?password["']?/i.test(html);
  checks.push({
    id:"passwordinput", label:"Input Password",
    description:"Ada field password — normal untuk login, tapi waspadai di situs tak dikenal.",
    status: hasPassInput && !isKnownSafe ? "warn" : "pass",
    detail: hasPassInput
      ? (isKnownSafe ? "Ada form login di domain tepercaya ✓" : "Ada field password — pastikan ini situs resmi!")
      : "Tidak ada input password di halaman ✓",
  });

  // 4. Meta refresh / auto redirect
  const hasMetaRefresh = /<meta[^>]+http-equiv=["']?refresh["']?/i.test(html);
  checks.push({
    id:"metarefresh", label:"Auto Redirect (Meta Refresh)",
    description:"Halaman otomatis redirect ke URL lain — teknik phishing.",
    status: hasMetaRefresh?"warn":"pass",
    detail: hasMetaRefresh?"Meta refresh ditemukan — halaman akan redirect otomatis":"Tidak ada auto redirect ✓",
  });

  // 5. Jumlah link eksternal mencurigakan
  const allLinks = [...html.matchAll(/href=["']([^"']+)["']/gi)].map(m=>m[1]);
  const extLinks = allLinks.filter(l=>{
    try { const h=new URL(l).hostname; return h&&h!==hostname&&!h.endsWith("."+domain); }
    catch { return false; }
  });
  const suspExtLinks = extLinks.filter(l=>BRAND_KEYWORDS.some(b=>l.toLowerCase().includes(b)));
  checks.push({
    id:"susplinks", label:"Link Mencurigakan",
    description:"Link ke domain lain yang mengandung nama brand — potensi phishing kit.",
    status: suspExtLinks.length>2?"fail":suspExtLinks.length>0?"warn":"pass",
    detail: suspExtLinks.length>0
      ? `${suspExtLinks.length} link mencurigakan ditemukan (mengandung nama brand)`
      : "Tidak ada link mencurigakan ✓",
  });

  // 6. Cloaking / user-agent check
  const hasCloaking = /navigator\.userAgent|screen\.width|window\.innerWidth/i.test(html);
  checks.push({
    id:"cloaking", label:"Deteksi Browser (Cloaking)",
    description:"Phishing kit sering cek user-agent untuk menyembunyikan diri dari scanner.",
    status: hasCloaking&&!isKnownSafe?"warn":"pass",
    detail: hasCloaking&&!isKnownSafe
      ? "Terdeteksi cek browser/layar — mungkin teknik cloaking"
      : "Tidak ada indikasi cloaking ✓",
  });

  // 7. Title brand mismatch
  const titleMatch = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  const pageTitle = (titleMatch?.[1]||"").toLowerCase();
  const titleBrands = BRAND_KEYWORDS.filter(b=>pageTitle.includes(b));
  if (titleBrands.length>0 && !isKnownSafe) {
    checks.push({
      id:"titlebrand", label:"Brand di Judul Halaman",
      description:"Judul halaman menyebut nama brand tapi bukan domain resminya.",
      status:"fail",
      detail:`Judul mengandung '${titleBrands[0]}' tapi domain bukan resmi — indikasi phishing kuat!`,
    });
  } else {
    checks.push({
      id:"titlebrand", label:"Brand di Judul Halaman",
      description:"Judul halaman tidak menyebut brand pada domain yang salah.",
      status:"pass",
      detail: isKnownSafe ? "Domain resmi, judul sesuai ✓" : "Tidak ada brand mismatch ✓",
    });
  }

  return checks;
}

// dangerScore mentah
function calcDangerScore(checks: SecurityCheck[]): number {
  const weights: Record<string, number> = {
    https:25, ip:22, brand:20, at:18, unicode:15, htmlphish:18,
    formaction:20, titlebrand:20, domainlen:10, tld:10, subdomain:8,
    urllen:8, hyphen:5, redirect:5, known:-35, passwordinput:5,
    metarefresh:6, susplinks:8, cloaking:5, pathbrand:6, doubleslash:5,
  };
  let score=0;
  for (const c of checks) {
    const w=weights[c.id]??0;
    if(c.status==="fail") score+=w;
    else if(c.status==="warn") score+=Math.round(w*0.45);
    else if(c.id==="known"&&c.status==="pass") score+=w;
  }
  return Math.max(0,Math.min(100,score));
}

function calcRiskScore(checks: SecurityCheck[]): number {
  return Math.max(0,100-calcDangerScore(checks));
}

function getRiskLevel(safetyScore: number): RiskLevel {
  if(safetyScore>=70) return "safe";
  if(safetyScore>=40) return "suspicious";
  return "dangerous";
}

// ── urlscan.io public search ──
async function checkUrlscan(url: string): Promise<SecurityResult["urlscanResult"]> {
  try {
    const domain=new URL(url).hostname;
    const res=await fetch(
      `https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(domain)}&size=1`,
      { headers:{"Accept":"application/json"} }
    );
    if(!res.ok) return null;
    const data=await res.json();
    const hit=data?.results?.[0];
    if(!hit) return null;
    return {
      verdict: hit.verdicts?.overall?.malicious?"malicious":hit.verdicts?.overall?.suspicious?"suspicious":"clean",
      reportUrl:`https://urlscan.io/result/${hit._id}/`,
    };
  } catch { return null; }
}



// ─────────────────────────────────────────────
//  PANEL TYPE
// ─────────────────────────────────────────────
type Panel = "scraper" | "settings" | "about" | "security" | "screenshot" | null;

// ─────────────────────────────────────────────
//  SCREENSHOT TYPES & ENGINE
// ─────────────────────────────────────────────
interface ScreenshotResult {
  imageUrl: string;
  sourceApi: string;
  width?: number;
  height?: number;
  takenAt: string;
  targetUrl: string;
}

// ─────────────────────────────────────────────
//  Screenshot API strategies (berurutan, fallback)
//  Semua return imageUrl langsung — tidak HEAD probe
//  karena CORS sering blokir HEAD tapi bukan img src
// ─────────────────────────────────────────────
interface SsApi {
  name: string;
  getUrl: (url: string, enc: string) => string;
  isJson?: boolean;
  jsonPath?: string[];
  width?: number;
  height?: number;
}

const SS_APIS: SsApi[] = [
  // 1. Microlink — paling reliable, return JSON dengan URL CDN
  {
    name: "Microlink.io",
    getUrl: (_u, enc) => `https://api.microlink.io/?url=${enc}&screenshot=true&meta=false`,
    isJson: true,
    jsonPath: ["data", "screenshot", "url"],
    width: 1920, height: 1080,
  },
  // 2. Thum.io — direct image URL, no key
  {
    name: "Thum.io",
    getUrl: (u) => `https://image.thum.io/get/width/1280/${u}`,
    width: 1280, height: 900,
  },
  // 3. Thum.io fullpage variant
  {
    name: "Thum.io (fullpage)",
    getUrl: (u) => `https://image.thum.io/get/width/1280/allowJPG/${u}`,
    width: 1280, height: 900,
  },
  // 4. screenshotmachine.com — free, direct image
  {
    name: "ScreenshotMachine",
    getUrl: (_u, enc) => `https://api.screenshotmachine.com/?dimension=1366x768&format=png&cacheLimit=0&url=${enc}`,
    width: 1366, height: 768,
  },
  // 5. S-Shot.ru — open, direct image
  {
    name: "S-Shot.ru",
    getUrl: (u) => `https://mini.s-shot.ru/1280x900/PNG/1280/Z100/?${u}`,
    width: 1280, height: 900,
  },
];

// Test apakah sebuah URL gambar bisa diload di browser
function testImageLoad(url: string, timeoutMs = 12000): Promise<boolean> {
  return new Promise((resolve) => {
    const img = new Image();
    const timer = setTimeout(() => { img.src = ""; resolve(false); }, timeoutMs);
    img.onload = () => { clearTimeout(timer); resolve(true); };
    img.onerror = () => { clearTimeout(timer); resolve(false); };
    img.src = url;
  });
}

async function captureScreenshot(targetUrl: string): Promise<ScreenshotResult> {
  const normalized = /^https?:\/\//i.test(targetUrl) ? targetUrl : "https://" + targetUrl;
  const encoded = encodeURIComponent(normalized);

  for (const api of SS_APIS) {
    try {
      const apiUrl = api.getUrl(normalized, encoded);

      if (api.isJson && api.jsonPath) {
        // Fetch JSON, extract image URL
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), 25000);
        const res = await fetch(apiUrl, { signal: ctrl.signal });
        clearTimeout(timer);
        if (!res.ok) continue;
        const j = await res.json();
        let val: any = j;
        for (const key of api.jsonPath) {
          val = val?.[key];
          if (!val) break;
        }
        if (typeof val === "string" && val.startsWith("http")) {
          // Verifikasi gambar bisa diload
          const ok = await testImageLoad(val, 15000);
          if (ok) {
            return {
              imageUrl: val,
              sourceApi: api.name,
              width: api.width,
              height: api.height,
              takenAt: new Date().toLocaleString("id-ID"),
              targetUrl: normalized,
            };
          }
        }
      } else {
        // Direct image URL — test load
        const ok = await testImageLoad(apiUrl, 15000);
        if (ok) {
          return {
            imageUrl: apiUrl,
            sourceApi: api.name,
            width: api.width,
            height: api.height,
            takenAt: new Date().toLocaleString("id-ID"),
            targetUrl: normalized,
          };
        }
      }
    } catch {
      continue;
    }
  }

  // Semua gagal — kembalikan Thum.io sebagai last resort (gambar mungkin tetap tampil)
  return {
    imageUrl: `https://image.thum.io/get/width/1280/${normalized}`,
    sourceApi: "Thum.io (fallback)",
    width: 1280,
    height: 900,
    takenAt: new Date().toLocaleString("id-ID"),
    targetUrl: normalized,
  };
}

// ─────────────────────────────────────────────
//  APP
// ─────────────────────────────────────────────
export default function App() {
  const [dark, setDark] = useState(true);
  const [panel, setPanel] = useState<Panel>(null);


  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [data, setData] = useState<ScrapedData | null>(null);
  const [activeTab, setActiveTab] = useState<Tab>("html");
  const [copied, setCopied] = useState(false);
  const [fetchCSS, setFetchCSS] = useState(true);
  const [fetchJS, setFetchJS] = useState(true);
  const [secResult, setSecResult] = useState<SecurityResult | null>(null);
  const [secLoading, setSecLoading] = useState(false);

  const [ssResult, setSsResult] = useState<ScreenshotResult | null>(null);
  const [ssLoading, setSsLoading] = useState(false);
  const [ssUrl, setSsUrl] = useState("");
  

  
  const abortRef = useRef(false);

  // ── screenshot handler ──
  const handleScreenshot = useCallback(async (targetUrl?: string) => {
    const scanUrl = (targetUrl ?? ssUrl ?? url).trim();
    if (!scanUrl) return;
    setSsLoading(true);
    setSsResult(null);
    try {
      const result = await captureScreenshot(scanUrl);
      setSsResult(result);
    } catch (e: any) {
      setSsResult(null);
    } finally {
      setSsLoading(false);
    }
  }, [ssUrl, url]);

  // ── security scan ──
  const handleSecScan = useCallback(async (targetUrl?: string) => {
    const scanUrl = (targetUrl ?? url).trim();
    if (!scanUrl) return;
    let normalized = scanUrl;
    if (!/^https?:\/\//i.test(normalized)) normalized = "https://" + normalized;

    setSecLoading(true);
    setSecResult(null);

    // 1. URL heuristic checks
    const urlChecks = analyzeUrlSecurity(normalized);

    // 2. Ambil HTML konten via proxy untuk analisis lebih dalam
    let htmlChecks: SecurityCheck[] = [];
    try {
      const { content } = await fetchViaProxy(normalized, 15000);
      htmlChecks = analyzeHtmlContent(content, normalized);
    } catch { /* lewati jika tidak bisa diambil */ }

    const allChecks = [...urlChecks, ...htmlChecks];
    let score = calcRiskScore(allChecks);

    // 3. urlscan.io
    const urlscanResult = await checkUrlscan(normalized);
    if (urlscanResult?.verdict === "malicious") score = Math.max(0, score - 30);
    else if (urlscanResult?.verdict === "suspicious") score = Math.max(0, score - 15);

    const finalScore = Math.max(0, Math.min(100, score));

    setSecResult({
      url: normalized,
      riskLevel: getRiskLevel(finalScore),
      riskScore: finalScore,
      checks: allChecks,
      scannedAt: new Date().toLocaleString("id-ID"),
      urlscanResult,
      safeBrowsingResult: null,
    });
    setSecLoading(false);
  }, [url]);

  // ── theme ──
  const bg       = dark ? "bg-[#0a0a0a]" : "bg-white";
  const text      = dark ? "text-white" : "text-black";
  const sub       = dark ? "text-zinc-500" : "text-zinc-400";
  const card      = dark ? "bg-zinc-900/60 border border-zinc-800" : "bg-zinc-50 border border-zinc-200";
  const inp       = dark ? "bg-zinc-900 border-zinc-700 text-white placeholder-zinc-600 focus:border-zinc-500"
                         : "bg-white border-zinc-300 text-black placeholder-zinc-400 focus:border-zinc-500";
  const codeBg    = dark ? "bg-[#0d0d0d] text-emerald-400" : "bg-zinc-100 text-emerald-700";
  const div       = dark ? "border-zinc-800" : "border-zinc-200";
  const btnPri    = dark ? "bg-white text-black hover:bg-zinc-200" : "bg-black text-white hover:bg-zinc-800";
  const btnOut    = dark ? "border border-zinc-700 hover:bg-zinc-800 text-zinc-300" : "border border-zinc-300 hover:bg-zinc-100 text-zinc-700";


  const fetchExternal = async (fileUrl: string): Promise<ExternalFile> => {
    try {
      const { content } = await fetchViaProxy(fileUrl, 10000);
      return { url: fileUrl, content, size: formatBytes(content), ok: true };
    } catch {
      return { url: fileUrl, content: `/* Gagal: ${fileUrl} */`, size: "—", ok: false };
    }
  };

  // ── scrape ──
  const handleScrape = useCallback(async () => {
    if (!url.trim()) { setError("Masukkan URL terlebih dahulu."); return; }
    let target = url.trim();
    if (!/^https?:\/\//i.test(target)) target = "https://" + target;

    abortRef.current = false;
    setLoading(true);
    setError("");
    setData(null);

    try {
      let html = "", proxyUsed = "";

      for (let i = 0; i < PROXY_STRATEGIES.length; i++) {
        if (abortRef.current) throw new Error("Dibatalkan.");
        const proxy = PROXY_STRATEGIES[i];
        try {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), 12000);
          const res = await fetch(proxy.build(target), { signal: controller.signal });
          clearTimeout(timer);
          if (!res.ok) throw new Error(`HTTP ${res.status}`);
          const content = await proxy.extract(res);
          if (!content || content.length < 50) throw new Error("Kosong");
          html = content; proxyUsed = proxy.name;
          break;
        } catch {
          continue;
        }
      }

      if (!html) throw new Error("Semua proxy gagal.");
      const title = extractTitle(html);

      let cssFiles: ExternalFile[] = [];
      if (fetchCSS) {
        const links = extractLinks(html, target, "css");
        cssFiles = await Promise.all(links.slice(0, 10).map(fetchExternal));
      }

      let jsFiles: ExternalFile[] = [];
      if (fetchJS) {
        const links = extractLinks(html, target, "js");
        jsFiles = await Promise.all(links.slice(0, 10).map(fetchExternal));
      }

      setData({ html, cssFiles, jsFiles, title, url: target, proxyUsed, fetchedAt: new Date().toLocaleString("id-ID") });
      setActiveTab("html");
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [url, fetchCSS, fetchJS]);

  // ── content ──
  const getContent = (): string => {
    if (!data) return "";
    switch (activeTab) {
      case "html": return data.html;
      case "css":  return data.cssFiles.length ? data.cssFiles.map((f) => `/* ===== ${f.url} ===== */\n${f.content}`).join("\n\n") : "/* Tidak ada CSS */";
      case "js":   return data.jsFiles.length  ? data.jsFiles.map((f) => `/* ===== ${f.url} ===== */\n${f.content}`).join("\n\n")  : "// Tidak ada JS";
      case "all":  return [
        `<!-- ===== HTML ===== -->`, data.html,
        data.cssFiles.length ? "\n/* ===== CSS ===== */\n" + data.cssFiles.map((f) => `/* ${f.url} */\n${f.content}`).join("\n\n") : "",
        data.jsFiles.length  ? "\n// ===== JS =====\n"  + data.jsFiles.map((f) => `/* ${f.url} */\n${f.content}`).join("\n\n")  : "",
      ].filter(Boolean).join("\n");
    }
  };
  const content = getContent();

  const handleCopy = async () => {
    await navigator.clipboard.writeText(content);
    setCopied(true); setTimeout(() => setCopied(false), 2000);
  };
  const handleDownload = () => {
    const ext: Record<Tab, string> = { html: "html", css: "css", js: "js", all: "txt" };
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([content], { type: "text/plain" }));
    a.download = `source.${ext[activeTab]}`; a.click();
  };

  const tabs: { key: Tab; label: string; count?: number }[] = [
    { key: "html", label: "HTML" },
    { key: "css",  label: "CSS",        count: data?.cssFiles.length },
    { key: "js",   label: "JavaScript", count: data?.jsFiles.length  },
    { key: "all",  label: "Semua" },
  ];

  // ─────────────────────────────────────────
  //  RENDER
  // ─────────────────────────────────────────

  // nav items config
  const navItems = [
    { id: "scraper" as Panel, label: "Web Scraper", badge: data ? 1 : undefined,
      icon: <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}><path strokeLinecap="round" strokeLinejoin="round" d="M17.25 6.75L22.5 12l-5.25 5.25m-10.5 0L1.5 12l5.25-5.25m7.5-3l-4.5 16.5" /></svg> },
    { id: "screenshot" as Panel, label: "Screenshot", badge: ssResult ? 1 : undefined,
      icon: <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}><path strokeLinecap="round" strokeLinejoin="round" d="M6.827 6.175A2.31 2.31 0 015.186 7.23c-.38.054-.757.112-1.134.175C2.999 7.58 2.25 8.507 2.25 9.574V18a2.25 2.25 0 002.25 2.25h15A2.25 2.25 0 0021.75 18V9.574c0-1.067-.75-1.994-1.802-2.169a47.865 47.865 0 00-1.134-.175 2.31 2.31 0 01-1.64-1.055l-.822-1.316a2.192 2.192 0 00-1.736-1.039 48.774 48.774 0 00-5.232 0 2.192 2.192 0 00-1.736 1.039l-.821 1.316z" /><path strokeLinecap="round" strokeLinejoin="round" d="M16.5 12.75a4.5 4.5 0 11-9 0 4.5 4.5 0 019 0zM18.75 10.5h.008v.008h-.008V10.5z" /></svg> },
    { id: "security" as Panel, label: "Cek Keamanan", badge: secResult ? (secResult.riskLevel !== "safe" ? 1 : undefined) : undefined,
      icon: <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}><path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" /></svg> },
    { id: "about" as Panel, label: "Tentang",
      icon: <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}><path strokeLinecap="round" strokeLinejoin="round" d="M11.25 11.25l.041-.02a.75.75 0 011.063.852l-.708 2.836a.75.75 0 001.063.853l.041-.021M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-9-3.75h.008v.008H12V8.25z" /></svg> },
  ];

  return (
    <div className={`flex flex-col h-screen overflow-hidden ${bg} ${text} font-mono transition-colors duration-300`}>

      {/* ══ TOP NAVBAR ══ */}
      <header className={`shrink-0 border-b ${div} ${dark ? "bg-[#0a0a0a]" : "bg-white"} z-40`}>
        {/* Row 1 — Logo + nav tabs + dark toggle */}
        <div className="flex items-center px-4 h-14 gap-4">
          {/* Logo */}
          <div className="flex items-center gap-2 shrink-0">
            <div className={`w-7 h-7 rounded-lg flex items-center justify-center text-[10px] font-black ${dark ? "bg-white text-black" : "bg-black text-white"}`}>{"</>"}</div>
            <div className="hidden sm:block leading-tight">
              <p className="font-bold text-sm tracking-tight">WebTools</p>
              <p className={`text-[10px] ${sub}`}>smartgadget</p>
            </div>
          </div>

          {/* Nav tabs */}
          <nav className="flex items-center gap-0.5 flex-1 overflow-x-auto scrollbar-none">
            {navItems.map((item) => {
              const isActive = panel === item.id;
              return (
                <button
                  key={item.id as string}
                  onClick={() => setPanel(item.id)}
                  className={`relative flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-semibold whitespace-nowrap transition-all shrink-0
                    ${isActive
                      ? dark ? "bg-zinc-800 text-white" : "bg-zinc-200 text-black"
                      : dark ? "text-zinc-400 hover:text-white hover:bg-zinc-800/60" : "text-zinc-500 hover:text-black hover:bg-zinc-100"
                    }`}
                >
                  {item.icon}
                  <span>{item.label}</span>
                  {item.badge ? (
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 shrink-0" />
                  ) : null}
                  {/* active underline */}
                  {isActive && (
                    <span className={`absolute bottom-0 left-2 right-2 h-0.5 rounded-full ${dark ? "bg-white" : "bg-black"}`} />
                  )}
                </button>
              );
            })}
          </nav>

          {/* Right: dark toggle */}
          <div className="ml-auto flex items-center gap-2 shrink-0">
            {loading && (
              <span className={`hidden sm:flex items-center gap-1.5 text-[11px] ${sub} animate-pulse`}>
                <svg className="w-3 h-3 animate-spin" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" /><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" /></svg>
                Memproses...
              </span>
            )}
            <button
              onClick={() => setDark(!dark)}
              className={`w-8 h-8 flex items-center justify-center rounded-lg border transition-all ${dark ? "border-zinc-700 hover:bg-zinc-800 text-amber-400" : "border-zinc-200 hover:bg-zinc-100 text-zinc-500"}`}
            >
              {dark
                ? <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20"><path fillRule="evenodd" d="M10 2a1 1 0 011 1v1a1 1 0 11-2 0V3a1 1 0 011-1zm4 8a4 4 0 11-8 0 4 4 0 018 0zm-.464 4.95l.707.707a1 1 0 001.414-1.414l-.707-.707a1 1 0 00-1.414 1.414zm2.12-10.607a1 1 0 010 1.414l-.706.707a1 1 0 11-1.414-1.414l.707-.707a1 1 0 011.414 0zM17 11a1 1 0 100-2h-1a1 1 0 100 2h1zm-7 4a1 1 0 011 1v1a1 1 0 11-2 0v-1a1 1 0 011-1zM5.05 6.464A1 1 0 106.465 5.05l-.708-.707a1 1 0 00-1.414 1.414l.707.707zm1.414 8.486l-.707.707a1 1 0 01-1.414-1.414l.707-.707a1 1 0 011.414 1.414zM4 11a1 1 0 100-2H3a1 1 0 000 2h1z" clipRule="evenodd" /></svg>
                : <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20"><path d="M17.293 13.293A8 8 0 016.707 2.707a8.001 8.001 0 1010.586 10.586z" /></svg>
              }
            </button>
          </div>
        </div>
      </header>

      {/* ══ PAGE CONTENT ══ */}
      <div className="flex-1 overflow-hidden flex flex-col">

        {/* ── Web Scraper page ── */}
        {panel === "scraper" && (
          <ScraperPanel
            dark={dark} sub={sub} div={div} inp={inp} btnPri={btnPri} btnOut={btnOut}
            card={card} codeBg={codeBg} text={text}
            url={url} setUrl={setUrl} loading={loading}
            fetchCSS={fetchCSS} setFetchCSS={setFetchCSS}
            fetchJS={fetchJS} setFetchJS={setFetchJS}
            handleScrape={handleScrape} abortRef={abortRef}
            data={data} activeTab={activeTab} setActiveTab={setActiveTab}
          />
        )}
        {/* ── Screenshot page ── */}
        {panel === "screenshot" && (
          <ScreenshotPanel
            dark={dark} sub={sub} div={div} inp={inp} btnPri={btnPri}
            url={url} ssUrl={ssUrl} setSsUrl={setSsUrl}
            ssResult={ssResult} ssLoading={ssLoading}
            handleScreenshot={handleScreenshot}
          />
        )}
        {/* ── Security page ── */}
        {panel === "security" && (
          <SecurityPanel
            dark={dark} sub={sub} div={div} inp={inp} btnPri={btnPri}
            url={url} secResult={secResult} secLoading={secLoading}
            handleSecScan={handleSecScan}
          />
        )}

        {/* ── About page ── */}
        {panel === "about" && (
          <AboutPanel dark={dark} sub={sub} div={div} />
        )}

        {/* ── Home (no panel selected) ── */}
        {!panel && (
          <div className="flex-1 overflow-y-auto">
          <div className="max-w-5xl mx-auto px-5 py-6 space-y-5">

            {/* Error */}
            {error && (
              <div className={`rounded-xl border border-red-500/30 px-4 py-3 flex gap-3 ${dark ? "bg-red-950/40" : "bg-red-50"}`}>
                <svg className="w-4 h-4 text-red-400 shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
                </svg>
                <div>
                  <p className="text-red-400 font-semibold text-sm">{error}</p>
                  <p className="text-red-400/70 text-xs mt-0.5">Pastikan URL valid & dapat diakses publik.</p>
                </div>
              </div>
            )}

            {/* Loading skeleton */}
            {loading && !data && (
              <div className={`rounded-2xl p-6 space-y-3 animate-pulse ${card}`}>
                <div className={`h-4 w-1/4 rounded ${dark ? "bg-zinc-800" : "bg-zinc-200"}`} />
                <div className={`h-3 w-3/5 rounded ${dark ? "bg-zinc-800" : "bg-zinc-200"}`} />
                <div className={`h-3 w-2/5 rounded ${dark ? "bg-zinc-800" : "bg-zinc-200"}`} />
                <div className={`h-56 w-full rounded-xl ${dark ? "bg-zinc-800/60" : "bg-zinc-100"}`} />
              </div>
            )}

            {/* Result */}
            {data && (
              <div className={`rounded-2xl overflow-hidden ${card}`}>
                {/* Meta bar */}
                <div className={`px-4 py-3 border-b ${div} ${dark ? "bg-zinc-900/40" : "bg-zinc-50"} flex flex-wrap gap-x-6 gap-y-1`}>
                  {[
                    { label: "Judul",   val: data.title, cls: "truncate max-w-[260px]" },
                    { label: "Proxy",   val: data.proxyUsed, cls: "text-emerald-500" },
                    { label: "HTML",    val: formatBytes(data.html) },
                    ...(data.cssFiles.length > 0 ? [{ label: "CSS", val: `${data.cssFiles.filter(f=>f.ok).length}/${data.cssFiles.length} file` }] : []),
                    ...(data.jsFiles.length  > 0 ? [{ label: "JS",  val: `${data.jsFiles.filter(f=>f.ok).length}/${data.jsFiles.length} file`  }] : []),
                    { label: "Diambil", val: data.fetchedAt },
                  ].map((m, i) => (
                    <div key={i}>
                      <p className={`text-[10px] uppercase tracking-wider ${sub}`}>{m.label}</p>
                      <p className={`text-xs font-semibold ${m.cls ?? ""}`}>{m.val}</p>
                    </div>
                  ))}
                </div>

                {/* Tabs + actions */}
                <div className={`flex items-center gap-1 px-3 py-2 border-b ${div} ${dark ? "bg-zinc-900/20" : ""}`}>
                  <div className="flex gap-1 flex-1 flex-wrap">
                    {tabs.map((t) => (
                      <button key={t.key} onClick={() => setActiveTab(t.key)}
                        className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center gap-1
                          ${activeTab === t.key ? dark ? "bg-white text-black" : "bg-black text-white" : `${sub} hover:${text}`}`}
                      >
                        {t.label}
                        {t.count !== undefined && t.count > 0 && (
                          <span className={`text-[10px] px-1 rounded ${activeTab === t.key ? "bg-black/10" : dark ? "bg-zinc-800" : "bg-zinc-200"}`}>
                            {t.count}
                          </span>
                        )}
                      </button>
                    ))}
                  </div>
                  <div className="flex gap-1.5 shrink-0">
                    <button onClick={handleCopy} className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${btnOut}`}>
                      {copied
                        ? <><svg className="w-3.5 h-3.5 text-emerald-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}><path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" /></svg><span className="text-emerald-500">Tersalin!</span></>
                        : <><svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" /></svg>Salin</>}
                    </button>
                    <button onClick={handleDownload} className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${btnOut}`}>
                      <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3" /></svg>
                      Unduh
                    </button>
                  </div>
                </div>

                {/* Code viewer */}
                <div className={`relative ${codeBg}`}>
                  <div className="absolute top-3 right-4 flex gap-1.5 z-10">
                    <span className="w-2.5 h-2.5 rounded-full bg-red-500/70" />
                    <span className="w-2.5 h-2.5 rounded-full bg-yellow-500/70" />
                    <span className="w-2.5 h-2.5 rounded-full bg-green-500/70" />
                  </div>
                  <pre className="text-[11px] leading-5 p-5 pt-8 overflow-auto max-h-[560px] whitespace-pre-wrap break-all select-all">
                    {content}
                  </pre>
                </div>

                {/* Status bar */}
                <div className={`px-4 py-2 border-t ${div} ${dark ? "bg-zinc-900/40" : "bg-zinc-50"} flex items-center justify-between`}>
                  <span className={`text-[11px] ${sub}`}>{content.split("\n").length.toLocaleString("id")} baris · {formatBytes(content)}</span>
                  <span className={`text-[11px] ${sub} uppercase tracking-wider`}>{activeTab}</span>
                </div>

                {/* File list */}
                {(activeTab === "css" || activeTab === "js") && (
                  <div className={`border-t ${div} p-4 space-y-2`}>
                    <p className={`text-[10px] uppercase tracking-widest ${sub} mb-3`}>Daftar File {activeTab.toUpperCase()}</p>
                    {(activeTab === "css" ? data.cssFiles : data.jsFiles).map((f, i) => (
                      <div key={i} className={`flex items-center justify-between text-xs px-3 py-2 rounded-lg ${dark ? "bg-zinc-800/60" : "bg-zinc-100"}`}>
                        <div className="flex items-center gap-2 overflow-hidden">
                          <span>{f.ok ? "✅" : "❌"}</span>
                          <span className={`truncate max-w-[420px] ${sub}`}>{f.url}</span>
                        </div>
                        <span className={`shrink-0 ml-3 ${sub}`}>{f.size}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* ── Screenshot Result Card ── */}
            {(ssResult || ssLoading) && (
              <ScreenshotResultCard dark={dark} sub={sub} div={div} card={card} result={ssResult} loading={ssLoading} />
            )}

            {/* ── Security Result Card ── */}
            {secResult && (
              <SecurityResultCard dark={dark} sub={sub} div={div} card={card} result={secResult} secLoading={secLoading} />
            )}

            {/* Empty state */}
            {!data && !loading && (
              <div className="flex flex-col items-center justify-center py-16 gap-6">
                <div className={`w-16 h-16 rounded-2xl flex items-center justify-center text-2xl font-black ${dark ? "bg-zinc-800 text-zinc-400" : "bg-zinc-100 text-zinc-400"}`}>
                  {"</>"}
                </div>
                <div className="text-center space-y-1.5">
                  <h1 className="text-2xl font-bold tracking-tight">WEB TOOLS SMART GADGET</h1>
                  <p className={`text-sm ${sub}`}>
                    WEB TOOLS BUATAN SMART GADGET UNTUK MEMBANTU HIDUP ANDA
                  </p>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 w-full max-w-xl">
                  {[
                    { emoji: "🔗", title: "Multi-Proxy", desc: `${PROXY_STRATEGIES.length} proxy fallback otomatis` },
                    { emoji: "📦", title: "HTML + CSS + JS", desc: "Semua source code sekaligus" },
                    { emoji: "💾", title: "Salin & Unduh", desc: "Export ke file atau clipboard" },
                  ].map((c, i) => (
                    <div key={i} className={`rounded-xl p-4 space-y-1.5 ${card}`}>
                      <span className="text-xl">{c.emoji}</span>
                      <p className="font-semibold text-xs">{c.title}</p>
                      <p className={`text-[11px] ${sub}`}>{c.desc}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

          </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────
//  SUB-COMPONENTS
// ─────────────────────────────────────────────



// Panel header
function PanelHeader({ title, div, right }: { title: string; sub?: string; div: string; right?: React.ReactNode }) {
  return (
    <div className={`shrink-0 flex items-center justify-between px-4 py-3 border-b ${div}`}>
      <p className="text-xs font-bold uppercase tracking-widest">{title}</p>
      {right}
    </div>
  );
}

// Settings panel
// ─────────────────────────────────────────────
//  SECURITY PANEL (sidebar)
// ─────────────────────────────────────────────
function SecurityPanel({ dark, sub, div, inp, btnPri, url, secResult, secLoading, handleSecScan }: any) {
  const [localUrl, setLocalUrl] = useState(url ?? "");
  return (
    <div className="flex flex-col h-full">
      <PanelHeader title="Cek Keamanan" div={div}
        right={<span className={`text-[10px] px-1.5 py-0.5 rounded-full border ${dark ? "border-zinc-700 text-zinc-500" : "border-zinc-300 text-zinc-400"}`}>Anti-Phishing</span>}
      />
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {/* URL input */}
        <div className="space-y-2">
          <label className={`text-[10px] uppercase tracking-widest font-semibold ${sub}`}>URL yang Dicek</label>
          <input
            type="text"
            placeholder="https://example.com"
            value={localUrl}
            onChange={(e: any) => setLocalUrl(e.target.value)}
            onKeyDown={(e: any) => e.key === "Enter" && !secLoading && handleSecScan(localUrl)}
            className={`w-full px-3 py-2.5 rounded-xl border text-xs outline-none transition-colors ${inp}`}
          />
        </div>

        {/* Scan button */}
        <button
          onClick={() => handleSecScan(localUrl)}
          disabled={secLoading || !localUrl.trim()}
          className={`w-full flex items-center justify-center gap-2 py-2.5 rounded-xl font-semibold text-xs transition-all disabled:opacity-40 ${btnPri}`}
        >
          {secLoading ? (
            <><svg className="w-3.5 h-3.5 animate-spin" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"/></svg>Memindai konten...</>
          ) : (
            <><svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z"/></svg>Pindai Sekarang</>
          )}
        </button>

        {/* Loading state */}
        {secLoading && (
          <div className={`rounded-xl p-4 border ${dark?"border-zinc-800 bg-zinc-800/20":"border-zinc-200 bg-zinc-50"} flex items-center gap-3`}>
            <svg className="w-5 h-5 animate-spin shrink-0 text-amber-400" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"/></svg>
            <div>
              <p className={`text-xs font-semibold`}>Menganalisis...</p>
              <p className={`text-[10px] ${sub}`}>URL + konten HTML + database publik</p>
            </div>
          </div>
        )}

        {/* ── HASIL LENGKAP DI BAWAH (inline) ── */}
        {secResult && !secLoading && (() => {
          const r = secResult;
          const riskColor = r.riskLevel==="dangerous"?"text-red-400":r.riskLevel==="suspicious"?"text-amber-400":"text-emerald-500";
          const barColor = r.riskScore>=70?"bg-emerald-500":r.riskScore>=40?"bg-amber-500":"bg-red-500";
          const statusIcon = (s: string) =>
            s==="pass"?<span className="text-emerald-500 font-bold">✓</span>:
            s==="fail"?<span className="text-red-400 font-bold">✗</span>:
            s==="warn"?<span className="text-amber-400 font-bold">!</span>:
            <span className={`${sub}`}>i</span>;

          // Kelompokkan checks
          const urlChecks = r.checks.filter((c: SecurityCheck) =>
            ["https","ip","domainlen","tld","subdomain","brand","at","urllen","hyphen","unicode","redirect","known","pathbrand","doubleslash"].includes(c.id)
          );
          const htmlChecks = r.checks.filter((c: SecurityCheck) =>
            ["htmlphish","formaction","passwordinput","metarefresh","susplinks","cloaking","titlebrand"].includes(c.id)
          );

          return (
            <div className="space-y-3">
              {/* Verdict */}
              <div className={`rounded-xl p-3 border ${
                r.riskLevel==="dangerous"?"border-red-500/40 bg-red-950/30":
                r.riskLevel==="suspicious"?"border-amber-500/40 bg-amber-950/30":
                dark?"border-emerald-800/60 bg-emerald-950/20":"border-emerald-300 bg-emerald-50"
              }`}>
                <div className="flex items-center gap-2.5 mb-2">
                  <span className="text-2xl">{r.riskLevel==="safe"?"✅":r.riskLevel==="suspicious"?"⚠️":"🚨"}</span>
                  <div className="flex-1">
                    <p className={`text-sm font-black ${riskColor}`}>
                      {r.riskLevel==="safe"?"AMAN":r.riskLevel==="suspicious"?"MENCURIGAKAN":"BERBAHAYA"}
                    </p>
                    <p className={`text-[10px] ${sub}`}>Skor Keamanan: {r.riskScore}/100</p>
                  </div>
                </div>
                {/* Bar */}
                <div className={`w-full h-1.5 rounded-full ${dark?"bg-zinc-700":"bg-zinc-200"}`}>
                  <div className={`h-1.5 rounded-full transition-all duration-700 ${barColor}`} style={{width:`${r.riskScore}%`}}/>
                </div>
                {/* urlscan result */}
                {r.urlscanResult && (
                  <div className="flex items-center gap-1.5 mt-2">
                    <span className="text-xs">🌐</span>
                    <span className={`text-[10px] ${sub}`}>urlscan.io:</span>
                    <span className={`text-[10px] font-semibold ${r.urlscanResult.verdict==="malicious"?"text-red-400":r.urlscanResult.verdict==="suspicious"?"text-amber-400":"text-emerald-500"}`}>
                      {r.urlscanResult.verdict==="malicious"?"Berbahaya":r.urlscanResult.verdict==="suspicious"?"Mencurigakan":"Bersih"}
                    </span>
                    {r.urlscanResult.reportUrl && <a href={r.urlscanResult.reportUrl} target="_blank" rel="noreferrer" className={`text-[10px] underline ${sub}`}>Laporan</a>}
                  </div>
                )}
                <p className={`text-[10px] ${sub} mt-1`}>Dipindai: {r.scannedAt}</p>
              </div>

              {/* URL checks */}
              <div>
                <p className={`text-[10px] uppercase tracking-widest font-semibold ${sub} mb-1.5`}>🔗 Analisis URL</p>
                <div className="space-y-1">
                  {urlChecks.map((c: SecurityCheck) => (
                    <div key={c.id} className={`flex items-start gap-2 px-2.5 py-2 rounded-lg text-[11px] ${
                      c.status==="pass"?dark?"bg-emerald-950/20":"bg-emerald-50/60":
                      c.status==="fail"?dark?"bg-red-950/20":"bg-red-50/60":
                      c.status==="warn"?dark?"bg-amber-950/20":"bg-amber-50/60":
                      dark?"bg-zinc-800/30":"bg-zinc-100"
                    }`}>
                      <span className="mt-0.5 shrink-0 text-sm">{statusIcon(c.status)}</span>
                      <div className="min-w-0">
                        <span className="font-semibold">{c.label}</span>
                        {c.detail && <span className={`ml-1.5 ${sub}`}>{c.detail}</span>}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* HTML content checks */}
              {htmlChecks.length > 0 && (
                <div>
                  <p className={`text-[10px] uppercase tracking-widest font-semibold ${sub} mb-1.5`}>📄 Analisis Konten HTML</p>
                  <div className="space-y-1">
                    {htmlChecks.map((c: SecurityCheck) => (
                      <div key={c.id} className={`flex items-start gap-2 px-2.5 py-2 rounded-lg text-[11px] ${
                        c.status==="pass"?dark?"bg-emerald-950/20":"bg-emerald-50/60":
                        c.status==="fail"?dark?"bg-red-950/20":"bg-red-50/60":
                        c.status==="warn"?dark?"bg-amber-950/20":"bg-amber-50/60":
                        dark?"bg-zinc-800/30":"bg-zinc-100"
                      }`}>
                        <span className="mt-0.5 shrink-0 text-sm">{statusIcon(c.status)}</span>
                        <div className="min-w-0">
                          <span className="font-semibold">{c.label}</span>
                          {c.detail && <span className={`ml-1.5 ${sub}`}>{c.detail}</span>}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Peringatan */}
              {r.riskLevel!=="safe" && (
                <div className={`rounded-xl px-3 py-2.5 border border-red-500/30 ${dark?"bg-red-950/20":"bg-red-50"}`}>
                  <p className="text-[11px] text-red-400 font-semibold">
                    ⚠️ {r.riskLevel==="dangerous"
                      ? `Skor ${r.riskScore}/100 — Website ini sangat mungkin PHISHING/MALWARE. Jangan masukkan data pribadi!`
                      : `Skor ${r.riskScore}/100 — Ada indikasi mencurigakan. Verifikasi sebelum digunakan.`
                    }
                  </p>
                </div>
              )}
            </div>
          );
        })()}

        {/* Info metode */}
        <div className={`rounded-xl p-3 space-y-1.5 border ${dark?"border-zinc-800 bg-zinc-800/30":"border-zinc-200 bg-zinc-50"}`}>
          <p className={`text-[10px] font-semibold ${sub} uppercase tracking-wider`}>Metode Deteksi</p>
          {[
            ["🔍","URL Heuristic","14 aturan analisis URL"],
            ["📄","Analisis HTML","Konten, form, script, link"],
            ["🌐","urlscan.io","Database publik gratis"],
          ].map(([e,t,d])=>(
            <div key={t} className="flex items-center gap-2">
              <span className="text-xs shrink-0">{e}</span>
              <div><span className="text-[11px] font-semibold">{t}</span><span className={`text-[10px] ${sub} ml-1.5`}>{d}</span></div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────
//  SECURITY RESULT CARD (main content)
// ─────────────────────────────────────────────
function SecurityResultCard({ dark, sub, div, card, result, secLoading }: any) {
  const r: SecurityResult = result;
  const riskColor =
    r.riskLevel === "dangerous" ? "text-red-400" :
    r.riskLevel === "suspicious" ? "text-amber-400" : "text-emerald-500";
  const riskBg =
    r.riskLevel === "dangerous" ? dark ? "bg-red-950/30 border-red-800" : "bg-red-50 border-red-200" :
    r.riskLevel === "suspicious" ? dark ? "bg-amber-950/30 border-amber-800" : "bg-amber-50 border-amber-200" :
    dark ? "bg-emerald-950/30 border-emerald-800" : "bg-emerald-50 border-emerald-200";

  const statusIcon = (s: string) =>
    s === "pass" ? <span className="text-emerald-500">✓</span> :
    s === "fail" ? <span className="text-red-400">✗</span> :
    s === "warn" ? <span className="text-amber-400">!</span> :
    <span className={sub}>i</span>;

  // skor keamanan: tinggi = aman, bar hijau jika aman
  const barWidth = `${r.riskScore}%`;
  const barColor =
    r.riskScore >= 70 ? "bg-emerald-500" :
    r.riskScore >= 40 ? "bg-amber-500" : "bg-red-500";

  if (secLoading) {
    return (
      <div className={`rounded-2xl p-6 space-y-3 animate-pulse ${card}`}>
        <div className={`h-4 w-1/3 rounded ${dark ? "bg-zinc-800" : "bg-zinc-200"}`} />
        <div className={`h-3 w-2/3 rounded ${dark ? "bg-zinc-800" : "bg-zinc-200"}`} />
        <div className={`h-20 w-full rounded-xl ${dark ? "bg-zinc-800/60" : "bg-zinc-100"}`} />
      </div>
    );
  }

  return (
    <div className={`rounded-2xl overflow-hidden border ${riskBg}`}>
      {/* Header */}
      <div className={`px-5 py-4 border-b ${div} flex items-center gap-4`}>
        <div className="text-3xl">
          {r.riskLevel === "safe" ? "✅" : r.riskLevel === "suspicious" ? "⚠️" : "🚨"}
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-3 flex-wrap">
            <p className={`text-lg font-black ${riskColor}`}>
              {r.riskLevel === "safe" ? "AMAN" : r.riskLevel === "suspicious" ? "MENCURIGAKAN" : "BERBAHAYA"}
            </p>
            <span className={`text-xs px-2 py-0.5 rounded-full border font-semibold ${riskColor} ${dark ? "border-current/30 bg-current/10" : "border-current/30 bg-current/10"}`}>
              Skor Keamanan: {r.riskScore}/100
            </span>
          </div>
          <p className={`text-xs truncate mt-0.5 ${sub}`}>{r.url}</p>
          <p className={`text-[10px] ${sub} mt-0.5`}>Dipindai: {r.scannedAt}</p>
        </div>
      </div>

      {/* Risk bar */}
      <div className="px-5 py-3">
        <div className={`flex items-center justify-between text-[10px] ${sub} mb-1`}>
          <span>Skor Keamanan</span><span>{r.riskScore}/100</span>
        </div>
        <div className={`w-full h-2 rounded-full ${dark ? "bg-zinc-800" : "bg-zinc-200"}`}>
          <div className={`h-2 rounded-full transition-all duration-700 ${barColor}`} style={{ width: barWidth }} />
        </div>
      </div>

      {/* External scan results — urlscan.io */}
      {r.urlscanResult && (
        <div className={`px-5 py-3 border-t ${div} flex flex-wrap gap-3`}>
          <div className={`flex items-center gap-2 text-xs px-3 py-1.5 rounded-lg ${dark ? "bg-zinc-800/60" : "bg-zinc-100"}`}>
            <span>🌐</span>
            <span className="font-semibold">urlscan.io:</span>
            <span className={r.urlscanResult.verdict === "malicious" ? "text-red-400" : r.urlscanResult.verdict === "suspicious" ? "text-amber-400" : "text-emerald-500"}>
              {r.urlscanResult.verdict === "malicious" ? "Berbahaya" : r.urlscanResult.verdict === "suspicious" ? "Mencurigakan" : "Bersih"}
            </span>
            {r.urlscanResult.reportUrl && (
              <a href={r.urlscanResult.reportUrl} target="_blank" rel="noreferrer" className={`underline ${sub}`}>Laporan</a>
            )}
          </div>
        </div>
      )}

      {/* Checks grid */}
      <div className={`px-5 py-4 border-t ${div}`}>
        <p className={`text-[10px] uppercase tracking-widest font-semibold ${sub} mb-3`}>Detail Pemeriksaan</p>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          {r.checks.map((c: SecurityCheck) => (
            <div key={c.id}
              className={`flex items-start gap-2.5 px-3 py-2.5 rounded-xl text-xs border transition-all
                ${c.status === "pass" ? dark ? "border-emerald-900/60 bg-emerald-950/20" : "border-emerald-200 bg-emerald-50/60"
                : c.status === "fail" ? dark ? "border-red-900/60 bg-red-950/20" : "border-red-200 bg-red-50/60"
                : c.status === "warn" ? dark ? "border-amber-900/60 bg-amber-950/20" : "border-amber-200 bg-amber-50/60"
                : dark ? "border-zinc-800" : "border-zinc-200"}`}
            >
              <span className="mt-0.5 font-bold text-sm shrink-0">{statusIcon(c.status)}</span>
              <div className="min-w-0">
                <p className="font-semibold truncate">{c.label}</p>
                {c.detail && <p className={`text-[10px] mt-0.5 ${sub} break-words`}>{c.detail}</p>}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Footer warning */}
      {r.riskLevel !== "safe" && (
        <div className={`px-5 py-3 border-t ${div} ${dark ? "bg-red-950/20" : "bg-red-50"}`}>
          <p className={`text-xs text-red-400 font-semibold`}>
            ⚠️ {r.riskLevel === "dangerous"
              ? `PERINGATAN: Skor keamanan ${r.riskScore}/100 — Website ini sangat mungkin berbahaya. Jangan masukkan data pribadi!`
              : `Hati-hati: Skor keamanan ${r.riskScore}/100 — Website ini memiliki beberapa indikator mencurigakan.`}
          </p>
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────
//  SCREENSHOT PANEL (sidebar)
// ─────────────────────────────────────────────
function ScreenshotPanel({ dark, sub, div, inp, btnPri, url, ssUrl, setSsUrl, ssResult, ssLoading, handleScreenshot }: any) {
  const [localUrl, setLocalUrl] = useState(ssUrl || url || "");

  const doShot = () => {
    setSsUrl(localUrl);
    handleScreenshot(localUrl);
  };

  const handleDownload = () => {
    if (!ssResult) return;
    const a = document.createElement("a");
    a.href = ssResult.imageUrl;
    a.download = `screenshot-${Date.now()}.png`;
    a.target = "_blank";
    a.click();
  };

  return (
    <div className="flex flex-col h-full">
      <PanelHeader title="Screenshot Web" div={div}
        right={<span className={`text-[10px] px-1.5 py-0.5 rounded-full border ${dark ? "border-zinc-700 text-zinc-500" : "border-zinc-300 text-zinc-400"}`}>Multi-API</span>}
      />
      <div className="flex-1 overflow-y-auto p-4 space-y-4">

        {/* URL */}
        <div className="space-y-2">
          <label className={`text-[10px] uppercase tracking-widest font-semibold ${sub}`}>URL Target</label>
          <input
            type="text"
            placeholder="https://example.com"
            value={localUrl}
            onChange={(e: any) => setLocalUrl(e.target.value)}
            onKeyDown={(e: any) => e.key === "Enter" && !ssLoading && doShot()}
            className={`w-full px-3 py-2.5 rounded-xl border text-xs outline-none transition-colors ${inp}`}
          />
        </div>

        {/* Capture button */}
        <button
          onClick={doShot}
          disabled={ssLoading || !localUrl.trim()}
          className={`w-full flex items-center justify-center gap-2 py-2.5 rounded-xl font-semibold text-xs transition-all disabled:opacity-40 ${btnPri}`}
        >
          {ssLoading ? (
            <><svg className="w-3.5 h-3.5 animate-spin" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" /><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" /></svg>Mengambil...</>
          ) : (
            <><svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M6.827 6.175A2.31 2.31 0 015.186 7.23c-.38.054-.757.112-1.134.175C2.999 7.58 2.25 8.507 2.25 9.574V18a2.25 2.25 0 002.25 2.25h15A2.25 2.25 0 0021.75 18V9.574c0-1.067-.75-1.994-1.802-2.169a47.865 47.865 0 00-1.134-.175 2.31 2.31 0 01-1.64-1.055l-.822-1.316a2.192 2.192 0 00-1.736-1.039 48.774 48.774 0 00-5.232 0 2.192 2.192 0 00-1.736 1.039l-.821 1.316z" /><path strokeLinecap="round" strokeLinejoin="round" d="M16.5 12.75a4.5 4.5 0 11-9 0 4.5 4.5 0 019 0zM18.75 10.5h.008v.008h-.008V10.5z" /></svg>Ambil Screenshot</>
          )}
        </button>

        {/* Download button — muncul setelah ada hasil */}
        {ssResult && !ssLoading && (
          <button
            onClick={handleDownload}
            className={`w-full flex items-center justify-center gap-2 py-2.5 rounded-xl font-semibold text-xs transition-all border ${dark ? "border-zinc-700 hover:bg-zinc-800 text-zinc-300" : "border-zinc-300 hover:bg-zinc-100 text-zinc-700"}`}
          >
            <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3" />
            </svg>
            Download Screenshot
          </button>
        )}

        {/* Mini preview */}
        {ssResult && !ssLoading && (
          <div className={`rounded-xl overflow-hidden border ${dark ? "border-zinc-700" : "border-zinc-200"}`}>
            {/* gambar full, tidak terpotong */}
            <img
              src={ssResult.imageUrl}
              alt="preview"
              className="w-full h-auto object-contain"
            />
            <div className={`px-3 py-2 text-[10px] ${sub} flex justify-between items-center`}>
              <span>via {ssResult.sourceApi}</span>
              <a href={ssResult.targetUrl} target="_blank" rel="noreferrer" className="underline opacity-60 hover:opacity-100 truncate max-w-[100px]">
                Kunjungi →
              </a>
            </div>
          </div>
        )}

        {/* API info */}
        <div className={`rounded-xl p-3 space-y-2 border ${dark ? "border-zinc-800 bg-zinc-800/30" : "border-zinc-200 bg-zinc-50"}`}>
          <p className={`text-[10px] font-semibold ${sub} uppercase tracking-wider`}>API Fallback (Otomatis)</p>
          {[
            ["🟢", "Microlink.io", "Hasil terbaik, full render"],
            ["🟡", "Thum.io", "Cepat, tanpa key"],
            ["🟠", "ScreenshotMachine", "Free tier"],
            ["🔵", "S-Shot.ru", "Last resort"],
          ].map(([e, t, d]) => (
            <div key={t} className="flex items-start gap-2">
              <span className="text-xs shrink-0">{e}</span>
              <div><p className="text-[11px] font-semibold">{t}</p><p className={`text-[10px] ${sub}`}>{d}</p></div>
            </div>
          ))}
          <p className={`text-[10px] ${sub} pt-1`}>Dicoba satu per satu hingga gambar berhasil ditampilkan.</p>
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────
//  SCREENSHOT RESULT CARD (main content)
// ─────────────────────────────────────────────
function ScreenshotResultCard({ dark, sub, div, card, result, loading }: any) {
  const [imgError, setImgError] = useState(false);
  const [imgLoaded, setImgLoaded] = useState(false);
  const [zoom, setZoom] = useState(false);

  // Reset state saat URL gambar berubah
  useEffect(() => {
    setImgError(false);
    setImgLoaded(false);
  }, [result?.imageUrl]);

  if (loading) {
    return (
      <div className={`rounded-2xl overflow-hidden ${card}`}>
        <div className="px-4 py-3 flex items-center gap-3">
          <div className={`w-8 h-8 rounded-xl shrink-0 ${dark ? "bg-zinc-800" : "bg-zinc-200"} animate-pulse`} />
          <div className="flex-1 space-y-1.5">
            <div className={`h-3 w-1/3 rounded animate-pulse ${dark ? "bg-zinc-800" : "bg-zinc-200"}`} />
            <div className={`h-2.5 w-2/3 rounded animate-pulse ${dark ? "bg-zinc-800" : "bg-zinc-200"}`} />
          </div>
        </div>
        <div className={`w-full flex flex-col items-center justify-center gap-3 py-16 ${dark ? "bg-zinc-900/40" : "bg-zinc-50"}`}>
          <svg className={`w-8 h-8 animate-spin ${dark ? "text-zinc-600" : "text-zinc-300"}`} fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
          </svg>
          <p className={`text-xs font-semibold ${dark ? "text-zinc-400" : "text-zinc-500"}`}>Mengambil screenshot...</p>
          <p className={`text-[10px] ${dark ? "text-zinc-600" : "text-zinc-400"}`}>Mencoba berbagai API, harap tunggu</p>
        </div>
      </div>
    );
  }

  if (!result) return null;
  const r: ScreenshotResult = result;

  const handleDownloadSS = () => {
    const a = document.createElement("a");
    a.href = r.imageUrl;
    a.download = `screenshot-${Date.now()}.png`;
    a.target = "_blank";
    a.click();
  };

  return (
    <>
      {/* Zoom overlay — fullscreen, gambar penuh */}
      {zoom && (
        <div
          className="fixed inset-0 z-[9999] bg-black/95 flex flex-col"
          onClick={() => setZoom(false)}
        >
          {/* Toolbar */}
          <div className="shrink-0 flex items-center justify-between px-4 py-3 bg-black/60 backdrop-blur-sm" onClick={(e) => e.stopPropagation()}>
            <p className="text-white text-xs font-semibold truncate max-w-xs opacity-70">{r.targetUrl}</p>
            <div className="flex items-center gap-2">
              <button
                onClick={handleDownloadSS}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-white text-black hover:bg-zinc-200 transition-colors"
              >
                <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3" /></svg>
                Download
              </button>
              <button onClick={() => setZoom(false)} className="w-8 h-8 rounded-full bg-zinc-800 text-white flex items-center justify-center hover:bg-zinc-700 transition-colors">
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
              </button>
            </div>
          </div>
          {/* Gambar fullscreen dengan scroll */}
          <div className="flex-1 overflow-auto flex items-start justify-center p-4" onClick={() => setZoom(false)}>
            <img
              src={r.imageUrl}
              alt="screenshot full"
              className="w-full max-w-5xl h-auto rounded-xl shadow-2xl"
              onClick={(e) => e.stopPropagation()}
            />
          </div>
        </div>
      )}

      <div className={`rounded-2xl overflow-hidden ${card}`}>
        {/* Header */}
        <div className={`px-4 py-3 border-b ${div} ${dark ? "bg-zinc-900/40" : "bg-zinc-50"} flex flex-wrap items-center gap-3`}>
          <div className={`w-8 h-8 rounded-xl flex items-center justify-center shrink-0 ${dark ? "bg-zinc-800" : "bg-zinc-100"}`}>
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M6.827 6.175A2.31 2.31 0 015.186 7.23c-.38.054-.757.112-1.134.175C2.999 7.58 2.25 8.507 2.25 9.574V18a2.25 2.25 0 002.25 2.25h15A2.25 2.25 0 0021.75 18V9.574c0-1.067-.75-1.994-1.802-2.169a47.865 47.865 0 00-1.134-.175 2.31 2.31 0 01-1.64-1.055l-.822-1.316a2.192 2.192 0 00-1.736-1.039 48.774 48.774 0 00-5.232 0 2.192 2.192 0 00-1.736 1.039l-.821 1.316z" />
              <path strokeLinecap="round" strokeLinejoin="round" d="M16.5 12.75a4.5 4.5 0 11-9 0 4.5 4.5 0 019 0zM18.75 10.5h.008v.008h-.008V10.5z" />
            </svg>
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-xs font-bold">Screenshot Website</p>
            <p className={`text-[10px] truncate ${sub}`}>{r.targetUrl}</p>
          </div>
          {/* Action buttons — responsif, wrap di mobile */}
          <div className="flex flex-wrap gap-1.5 shrink-0">
            <button
              onClick={() => setZoom(true)}
              className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-semibold border transition-all ${dark ? "border-zinc-700 hover:bg-zinc-800 text-zinc-300" : "border-zinc-300 hover:bg-zinc-100 text-zinc-700"}`}
            >
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M3.75 3.75v4.5m0-4.5h4.5m-4.5 0L9 9M3.75 20.25v-4.5m0 4.5h4.5m-4.5 0L9 15M20.25 3.75h-4.5m4.5 0v4.5m0-4.5L15 9m5.25 11.25h-4.5m4.5 0v-4.5m0 4.5L15 15" /></svg>
              <span className="hidden sm:inline">Zoom</span>
            </button>
            <button
              onClick={handleDownloadSS}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${dark ? "bg-white text-black hover:bg-zinc-200" : "bg-black text-white hover:bg-zinc-800"}`}
            >
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3" /></svg>
              Download
            </button>
          </div>
        </div>

        {/* Meta info */}
        <div className={`px-4 py-2 border-b ${div} flex flex-wrap gap-x-5 gap-y-1 text-[10px] ${dark ? "bg-zinc-900/20" : ""}`}>
          <span className={sub}>via <span className="font-semibold">{r.sourceApi}</span></span>
          {r.width && r.height && <span className={sub}>{r.width}×{r.height}px</span>}
          <span className={sub}>{r.takenAt}</span>
        </div>

        {/* Screenshot image — FULL, tidak terpotong, responsif */}
        <div className={`w-full ${dark ? "bg-zinc-950" : "bg-zinc-50"}`}>
          {!imgLoaded && !imgError && (
            <div className="flex items-center justify-center py-16 gap-2">
              <svg className={`w-5 h-5 animate-spin ${sub}`} fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
              </svg>
              <span className={`text-xs ${sub}`}>Memuat gambar...</span>
            </div>
          )}
          {imgError ? (
            <div className="flex flex-col items-center justify-center py-12 gap-3 px-4">
              <svg className={`w-10 h-10 ${sub}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M2.25 15.75l5.159-5.159a2.25 2.25 0 013.182 0l5.159 5.159m-1.5-1.5l1.409-1.409a2.25 2.25 0 013.182 0l2.909 2.909m-18 3.75h16.5a1.5 1.5 0 001.5-1.5V6a1.5 1.5 0 00-1.5-1.5H3.75A1.5 1.5 0 002.25 6v12a1.5 1.5 0 001.5 1.5zm10.5-11.25h.008v.008h-.008V8.25zm.375 0a.375.375 0 11-.75 0 .375.375 0 01.75 0z" />
              </svg>
              <p className={`text-sm font-semibold ${sub}`}>Gambar gagal dimuat</p>
              <p className={`text-xs ${sub} text-center`}>Website mungkin memblokir screenshot atau API sedang sibuk.</p>
              <a href={r.imageUrl} target="_blank" rel="noreferrer" className="text-xs underline text-blue-400">Buka URL gambar langsung →</a>
            </div>
          ) : (
            /* Gambar penuh — object-contain agar tidak ada bagian yang terpotong */
            <img
              key={r.imageUrl}
              src={r.imageUrl}
              alt={`Screenshot ${r.targetUrl}`}
              onLoad={() => setImgLoaded(true)}
              onError={() => { setImgError(true); setImgLoaded(true); }}
              onClick={() => setZoom(true)}
              className={`w-full h-auto object-contain cursor-zoom-in transition-opacity duration-500 ${imgLoaded ? "opacity-100" : "opacity-0"}`}
              referrerPolicy="no-referrer"
              crossOrigin="anonymous"
            />
          )}
        </div>

        {/* Footer */}
        {!imgError && imgLoaded && (
          <div className={`px-4 py-3 border-t ${div} ${dark ? "bg-zinc-900/40" : "bg-zinc-50"} flex flex-col sm:flex-row gap-2 sm:items-center sm:justify-between`}>
            <span className={`text-[11px] ${sub}`}>Klik gambar untuk zoom penuh</span>
            <div className="flex gap-2">
              <a
                href={r.targetUrl}
                target="_blank"
                rel="noreferrer"
                className={`text-[11px] px-3 py-1.5 rounded-lg border font-semibold transition-all ${dark ? "border-zinc-700 text-zinc-300 hover:bg-zinc-800" : "border-zinc-300 text-zinc-700 hover:bg-zinc-100"}`}
              >
                Kunjungi Website →
              </a>
              <button
                onClick={handleDownloadSS}
                className={`text-[11px] px-3 py-1.5 rounded-lg font-semibold transition-all ${dark ? "bg-white text-black hover:bg-zinc-200" : "bg-black text-white hover:bg-zinc-800"}`}
              >
                ⬇ Download
              </button>
            </div>
          </div>
        )}
      </div>
    </>
  );
}

// ─────────────────────────────────────────────
//  SCRAPER PANEL (fullscreen)
// ─────────────────────────────────────────────
function ScraperPanel({ dark, sub, div, inp, btnPri, btnOut, card, codeBg, text, url, setUrl, loading, fetchCSS, setFetchCSS, fetchJS, setFetchJS, handleScrape, abortRef, data, activeTab, setActiveTab }: any) {

  const tabs: { key: string; label: string; count?: number }[] = [
    { key: "html", label: "HTML" },
    { key: "css",  label: "CSS",        count: data?.cssFiles?.length },
    { key: "js",   label: "JavaScript", count: data?.jsFiles?.length },
    { key: "all",  label: "Semua" },
  ];

  const [copied, setCopied] = useState(false);

  const formatBytes = (str: string) => {
    const b = new Blob([str]).size;
    if (b < 1024) return `${b} B`;
    if (b < 1048576) return `${(b / 1024).toFixed(1)} KB`;
    return `${(b / 1048576).toFixed(2)} MB`;
  };

  const getContent = (): string => {
    if (!data) return "";
    switch (activeTab) {
      case "html": return data.html;
      case "css":  return data.cssFiles?.length ? data.cssFiles.map((f: any) => `/* ===== ${f.url} ===== */\n${f.content}`).join("\n\n") : "/* Tidak ada CSS */";
      case "js":   return data.jsFiles?.length  ? data.jsFiles.map((f: any) => `/* ===== ${f.url} ===== */\n${f.content}`).join("\n\n")  : "// Tidak ada JS";
      case "all":  return [
        `<!-- ===== HTML ===== -->`, data.html,
        data.cssFiles?.length ? "\n/* ===== CSS ===== */\n" + data.cssFiles.map((f: any) => `/* ${f.url} */\n${f.content}`).join("\n\n") : "",
        data.jsFiles?.length  ? "\n// ===== JS =====\n"    + data.jsFiles.map((f: any) => `/* ${f.url} */\n${f.content}`).join("\n\n")  : "",
      ].filter(Boolean).join("\n");
      default: return "";
    }
  };

  const content = getContent();

  const handleCopy = async () => {
    await navigator.clipboard.writeText(content);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const ext: Record<string, string> = { html: "html", css: "css", js: "js", all: "txt" };
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([content], { type: "text/plain" }));
    a.download = `source.${ext[activeTab] ?? "txt"}`;
    a.click();
  };

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Input area */}
      <div className={`shrink-0 px-5 py-4 border-b ${div} space-y-3 ${dark ? "bg-[#111]" : "bg-zinc-50"}`}>
        <div className="flex gap-2">
          <div className="relative flex-1">
            <span className={`absolute left-3 top-1/2 -translate-y-1/2 ${sub} pointer-events-none`}>
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
              </svg>
            </span>
            <input
              type="text"
              placeholder="https://example.com"
              value={url}
              onChange={(e: any) => setUrl(e.target.value)}
              onKeyDown={(e: any) => e.key === "Enter" && !loading && handleScrape()}
              className={`w-full pl-9 pr-3 py-2.5 rounded-xl border text-xs outline-none transition-colors ${inp}`}
            />
          </div>
          <button
            onClick={loading ? () => { abortRef.current = true; } : handleScrape}
            className={`flex items-center gap-1.5 px-4 py-2.5 rounded-xl text-xs font-semibold transition-all shrink-0 ${loading ? "bg-red-600 text-white hover:bg-red-700" : btnPri}`}
          >
            {loading ? (
              <><svg className="w-3.5 h-3.5 animate-spin" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" /><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" /></svg>Hentikan</>
            ) : (
              <><svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg>Ambil</>
            )}
          </button>
        </div>
        {/* Options */}
        <div className="flex items-center gap-5">
          <label className={`flex items-center gap-2 cursor-pointer text-xs ${sub}`}>
            <input type="checkbox" checked={fetchCSS} onChange={(e: any) => setFetchCSS(e.target.checked)} className="w-3.5 h-3.5 rounded accent-current" />
            Ambil CSS eksternal
          </label>
          <label className={`flex items-center gap-2 cursor-pointer text-xs ${sub}`}>
            <input type="checkbox" checked={fetchJS}  onChange={(e: any) => setFetchJS(e.target.checked)}  className="w-3.5 h-3.5 rounded accent-current" />
            Ambil JS eksternal
          </label>
          <span className={`text-[10px] ${sub} ml-auto`}>Maks. 10 file per jenis</span>
        </div>
      </div>

      {/* Result area */}
      {data ? (
        <div className="flex-1 overflow-hidden flex flex-col">
          {/* Meta bar */}
          <div className={`shrink-0 px-5 py-2.5 border-b ${div} ${dark ? "bg-zinc-900/40" : "bg-zinc-50"} flex flex-wrap gap-x-6 gap-y-1 items-center`}>
            <div><p className={`text-[10px] uppercase tracking-wider ${sub}`}>Judul</p><p className="text-xs font-semibold truncate max-w-[260px]">{data.title}</p></div>
            <div><p className={`text-[10px] uppercase tracking-wider ${sub}`}>Proxy</p><p className="text-xs font-semibold text-emerald-500">{data.proxyUsed}</p></div>
            <div><p className={`text-[10px] uppercase tracking-wider ${sub}`}>HTML</p><p className="text-xs font-semibold">{formatBytes(data.html)}</p></div>
            {data.cssFiles?.length > 0 && <div><p className={`text-[10px] uppercase tracking-wider ${sub}`}>CSS</p><p className="text-xs font-semibold">{data.cssFiles.filter((f: any) => f.ok).length}/{data.cssFiles.length} file</p></div>}
            {data.jsFiles?.length  > 0 && <div><p className={`text-[10px] uppercase tracking-wider ${sub}`}>JS</p><p className="text-xs font-semibold">{data.jsFiles.filter((f: any) => f.ok).length}/{data.jsFiles.length} file</p></div>}
            <div><p className={`text-[10px] uppercase tracking-wider ${sub}`}>Diambil</p><p className="text-xs font-semibold">{data.fetchedAt}</p></div>
          </div>

          {/* Tabs + actions */}
          <div className={`shrink-0 flex items-center gap-1 px-4 py-2 border-b ${div} ${dark ? "bg-zinc-900/20" : ""}`}>
            <div className="flex gap-1 flex-1 flex-wrap">
              {tabs.map((t) => (
                <button key={t.key} onClick={() => setActiveTab(t.key)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center gap-1 ${activeTab === t.key ? dark ? "bg-white text-black" : "bg-black text-white" : `${sub} hover:${text}`}`}
                >
                  {t.label}
                  {t.count !== undefined && t.count > 0 && (
                    <span className={`text-[10px] px-1 rounded ${activeTab === t.key ? "bg-black/10" : dark ? "bg-zinc-800" : "bg-zinc-200"}`}>{t.count}</span>
                  )}
                </button>
              ))}
            </div>
            <div className="flex gap-1.5 shrink-0">
              <button onClick={handleCopy} className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${btnOut}`}>
                {copied
                  ? <><svg className="w-3.5 h-3.5 text-emerald-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}><path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" /></svg><span className="text-emerald-500">Tersalin!</span></>
                  : <><svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" /></svg>Salin</>}
              </button>
              <button onClick={handleDownload} className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${btnOut}`}>
                <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3" /></svg>
                Unduh
              </button>
            </div>
          </div>

          {/* Code viewer */}
          <div className={`flex-1 overflow-hidden flex flex-col relative ${codeBg}`}>
            <div className="absolute top-3 right-4 flex gap-1.5 z-10">
              <span className="w-2.5 h-2.5 rounded-full bg-red-500/70" />
              <span className="w-2.5 h-2.5 rounded-full bg-yellow-500/70" />
              <span className="w-2.5 h-2.5 rounded-full bg-green-500/70" />
            </div>
            <pre className="flex-1 text-[11px] leading-5 p-5 pt-8 overflow-auto whitespace-pre-wrap break-all select-all">
              {content}
            </pre>
            {/* Status bar */}
            <div className={`shrink-0 px-4 py-1.5 border-t ${div} ${dark ? "bg-zinc-900/60" : "bg-zinc-100"} flex items-center justify-between`}>
              <span className={`text-[11px] ${sub}`}>{content.split("\n").length.toLocaleString("id")} baris · {formatBytes(content)}</span>
              <span className={`text-[11px] ${sub} uppercase tracking-wider`}>{activeTab}</span>
            </div>
          </div>

          {/* File list CSS/JS */}
          {(activeTab === "css" || activeTab === "js") && (
            <div className={`shrink-0 border-t ${div} p-4 space-y-2 max-h-40 overflow-y-auto`}>
              <p className={`text-[10px] uppercase tracking-widest ${sub} mb-2`}>Daftar File {activeTab.toUpperCase()}</p>
              {(activeTab === "css" ? data.cssFiles : data.jsFiles)?.map((f: any, i: number) => (
                <div key={i} className={`flex items-center justify-between text-xs px-3 py-2 rounded-lg ${dark ? "bg-zinc-800/60" : "bg-zinc-100"}`}>
                  <div className="flex items-center gap-2 overflow-hidden">
                    <span>{f.ok ? "✅" : "❌"}</span>
                    <span className={`truncate ${sub}`}>{f.url}</span>
                  </div>
                  <span className={`shrink-0 ml-3 ${sub}`}>{f.size}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      ) : (
        /* Empty state */
        <div className="flex-1 flex flex-col items-center justify-center gap-5 py-10">
          {loading ? (
            <div className={`w-full max-w-lg px-8 space-y-3 animate-pulse`}>
              <div className={`h-4 w-1/4 rounded ${dark ? "bg-zinc-800" : "bg-zinc-200"}`} />
              <div className={`h-3 w-3/5 rounded ${dark ? "bg-zinc-800" : "bg-zinc-200"}`} />
              <div className={`h-3 w-2/5 rounded ${dark ? "bg-zinc-800" : "bg-zinc-200"}`} />
              <div className={`h-52 w-full rounded-xl ${dark ? "bg-zinc-800/60" : "bg-zinc-100"}`} />
            </div>
          ) : (
            <>
              <div className={`w-14 h-14 rounded-2xl flex items-center justify-center text-xl font-black ${dark ? "bg-zinc-800 text-zinc-500" : "bg-zinc-100 text-zinc-400"}`}>{"</>"}</div>
              <div className="text-center space-y-1">
                <p className="font-bold text-sm">Ambil Source Code Website</p>
                <p className={`text-xs ${sub}`}>Masukkan URL lalu tekan <kbd className={`px-1.5 py-0.5 rounded text-[10px] border ${dark ? "border-zinc-700 bg-zinc-800" : "border-zinc-200 bg-zinc-100"}`}>Enter</kbd></p>
              </div>
              <div className="grid grid-cols-3 gap-3 max-w-sm w-full px-4">
                {[
                  { emoji: "🔗", title: "Multi-Proxy", desc: `${7} proxy fallback` },
                  { emoji: "📦", title: "HTML+CSS+JS", desc: "Semua sekaligus" },
                  { emoji: "💾", title: "Salin & Unduh", desc: "Export mudah" },
                ].map((c, i) => (
                  <div key={i} className={`rounded-xl p-3 space-y-1 ${card}`}>
                    <span className="text-lg">{c.emoji}</span>
                    <p className="font-semibold text-[11px]">{c.title}</p>
                    <p className={`text-[10px] ${sub}`}>{c.desc}</p>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}



// About panel
function AboutPanel({ dark, sub, div }: any) {
  return (
    <div className="flex flex-col h-full">
      <PanelHeader title="Tentang" sub={sub} div={div} />
      <div className="flex-1 overflow-y-auto p-4 space-y-5">
        <div className={`rounded-xl p-4 space-y-2 ${dark ? "bg-zinc-800/50" : "bg-zinc-100"}`}>
          <div className={`w-9 h-9 rounded-lg flex items-center justify-center font-black text-sm ${dark ? "bg-white text-black" : "bg-black text-white"}`}>{"</>"}</div>
          <p className="font-bold text-sm">WebTools</p>
          <p className={`text-[11px] ${sub}`}>smartgadget · v2.0</p>
        </div>
        {[
          { emoji: "🔗", title: "Multi-Proxy Fallback", desc: "7 proxy dicoba otomatis satu per satu hingga berhasil." },
          { emoji: "📦", title: "HTML + CSS + JS",      desc: "Ambil raw HTML, stylesheet & script eksternal sekaligus." },
          { emoji: "💾", title: "Salin & Unduh",        desc: "Export ke clipboard atau file .html / .css / .js / .txt." },
          { emoji: "🌙", title: "Dark / Light Mode",    desc: "Toggle tema gelap & terang kapan saja." },
        ].map((item, i) => (
          <div key={i} className="space-y-0.5">
            <p className="text-xs font-semibold">{item.emoji} {item.title}</p>
            <p className={`text-[11px] ${sub} leading-5`}>{item.desc}</p>
          </div>
        ))}
        <div className={`border-t ${div} pt-3 space-y-1`}>
          <p className={`text-[10px] ${sub}`}>Dibuat dengan React + Tailwind CSS</p>
          <p className={`text-[10px] ${sub}`}>Maks. 10 file CSS & JS per scraping</p>
        </div>
      </div>
    </div>
  );
}
