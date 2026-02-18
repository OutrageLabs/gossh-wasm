# Go WASM SSH Library & WebSocket Proxy — Descriptive Plan

**Cel:** Dwa osobne open-source projekty (MIT) dostarczające kompletny stos SSH w przeglądarce dla Subterm Web i innych projektów.

**Repozytoria:**
- `OutrageLabs/gossh-wasm` — Go SSH client kompilowany do WASM, z API dla JavaScript
- `OutrageLabs/wsproxy` — WebSocket↔TCP relay (proxy), zero-knowledge, Docker-ready

**Dlaczego osobne repo:** Lib i proxy są generyczne — nie są specyficzne dla Subterm. Mogą być użyte przez dowolny projekt potrzebujący SSH w przeglądarce. Open-source zwiększa audytowalność kodu i szansę na community contributions.

---

## Część 1: gossh-wasm (biblioteka WASM)

### 1.1 Co to robi

Biblioteka Go kompilowana do `GOOS=js GOARCH=wasm`, która daje przeglądarce pełnego klienta SSH z terminalem, SFTP, agent forwarding i port forwarding. Cała kryptografia SSH działa w przeglądarce — proxy nigdy nie widzi odszyfrowanych danych.

### 1.2 Fundamenty techniczne

| Komponent | Biblioteka | Rola |
|-----------|-----------|------|
| SSH protocol | `golang.org/x/crypto/ssh` | Oficjalna biblioteka Go — handshake, kanały, szyfrowanie |
| SFTP protocol | `github.com/pkg/sftp` | SFTP nad istniejącym `*ssh.Client` |
| SSH agent | `golang.org/x/crypto/ssh/agent` | In-memory keyring + agent forwarding |
| Transport | Własny `net.Conn` nad WebSocket | ~150 linii, wzorowane na sshterm/ssheasy |
| JS bridge | `syscall/js` | Expose API jako globalny obiekt JS |

**Żadna z tych bibliotek nie jest niszowa** — `golang.org/x/crypto/ssh` i `pkg/sftp` to standard w ekosystemie Go.

### 1.3 Architektura wewnętrzna

```
┌─────────────────────────────────────────────────┐
│  Przeglądarka (WASM)                            │
│                                                 │
│  ┌─────────────┐   ┌─────────────────────────┐  │
│  │ JS Bridge   │   │ WebSocket net.Conn      │  │
│  │ (syscall/js)│◄──│ adapter                 │  │
│  │             │   │ WS ↔ []byte ↔ net.Conn  │  │
│  └──────┬──────┘   └──────────┬──────────────┘  │
│         │                     │                  │
│  ┌──────▼──────────────────────▼──────────────┐  │
│  │         golang.org/x/crypto/ssh            │  │
│  │  ┌──────────┐ ┌──────┐ ┌───────────────┐  │  │
│  │  │ Sessions │ │ SFTP │ │ Agent         │  │  │
│  │  │ (PTY)    │ │      │ │ (in-memory)   │  │  │
│  │  └──────────┘ └──────┘ └───────────────┘  │  │
│  │  ┌──────────────────────────────────────┐  │  │
│  │  │ Port Forwarding (direct-tcpip)       │  │  │
│  │  └──────────────────────────────────────┘  │  │
│  └────────────────────────────────────────────┘  │
└──────────────────────┬──────────────────────────┘
                       │ WebSocket (wss://)
                       ▼
              ┌─────────────────┐
              │ wsproxy (relay) │
              │ WS ↔ TCP       │
              └────────┬────────┘
                       │ TCP (surowy SSH)
                       ▼
              ┌─────────────────┐
              │ SSH Server      │
              └─────────────────┘
```

### 1.4 WebSocket → net.Conn adapter

Kluczowy element łączący przeglądarkę z Go SSH. Implementacja `net.Conn` interfejsu nad przeglądarkowymi WebSocket. Wzorce z sshterm (czysta implementacja, ~120 linii):

- `New(url string)` — tworzy `new WebSocket(url)` via `syscall/js`, rejestruje `onmessage`/`onerror`/`onclose`
- `Read(p []byte)` — czyta z wewnętrznego `chan []byte` (bufferowany kanał, pojemność ~4096 wiadomości)
- `Write(p []byte)` — konwertuje `[]byte` → `Uint8Array` via `js.CopyBytesToJS`, wysyła `ws.send()`
- `Close()` — `ws.close()`
- `SetDeadline()` — zwraca nil (przeglądarki nie wspierają)

**Protokół proxy:** Adres docelowy (host:port) przekazywany w URL WebSocket jako query params: `wss://proxy.example.com/relay?host=server.com&port=22`. Żadnego in-band handshake — po nawiązaniu WebSocket, lecą surowe bajty SSH.

### 1.5 Wymagane funkcjonalności SSH

#### 1.5.1 Połączenie SSH (sesja terminala)

**Co musi działać:**
- Połączenie przez WebSocket → proxy → SSH server
- Autentykacja: hasło, klucz prywatny (z opcjonalnym passphrase), agent
- Negocjacja PTY (rozmiar terminala)
- Bidirectional data flow: stdin (klawiatura) → SSH → stdout (terminal output)
- Resize (WindowChange) — zmiana rozmiaru terminala w locie
- Graceful disconnect + wykrywanie utraty połączenia
- Banner SSH (wiadomość powitalna serwera)
- Host key verification — callback do JS z fingerprint, czeka na decyzję usera

**Obsługa wielu sesji:** Globalny `map[string]*Session` indeksowany UUID. Każda sesja = osobne WebSocket + SSH client + PTY. Pozwala na wiele tabów w przeglądarce.

**Jump hosts (ProxyJump / -J):** Połączenie z hostem A, potem `sshClient.Dial("tcp", "hostB:22")` przez tunel SSH hosta A. Rekursywne — dowolna liczba hopów. Każdy hop może mieć inną metodę autentykacji.

#### 1.5.2 SFTP (transfer plików)

**Co musi działać:**
- Otworzenie subsystemu SFTP na istniejącej sesji SSH (`sftp.NewClient(sshClient)`)
- Listowanie katalogów (nazwa, rozmiar, uprawnienia, data modyfikacji, typ: plik/katalog/symlink)
- Upload pliku z przeglądarki (File API → `Uint8Array` → Go → SFTP write)
- Download pliku do przeglądarki (SFTP read → Go → JS Blob → browser download)
- Mkdir, remove (plik i katalog rekurencyjnie), rename/move
- Chmod (zmiana uprawnień)
- Progress callback dla upload/download (procent, bytes/sec)
- Cancel transfer (context cancellation)

**Streaming downloads (krytyczne):** Nie buforować całego pliku w pamięci WASM — przy plikach >100MB to OOM. Dwa podejścia:
1. **Service Worker streaming** (jak sshterm) — rejestruje Service Worker, który przechwytuje fetch request i podaje `ReadableStream` z Go. Zero buforowania, działa dla plików dowolnego rozmiaru.
2. **Chunked Blob** (prostsze, mniej eleganckie) — czyta plik w kawałkach (np. 1MB), tworzy `Blob` z kawałków, triggeruje download. Buforuje całość, ale w JS Blob (poza WASM heap).

Rekomendacja: Service Worker streaming jako domyślne, chunked Blob jako fallback dla przeglądarek bez SW.

**Streaming uploads:** Przeglądarka daje `File` obiekt z `stream()` API. Czytamy kawałkami przez `ReadableStream`, każdy kawałek kopiujemy do Go i wysyłamy przez SFTP. Nie buforujemy całego pliku.

#### 1.5.3 SSH Agent Forwarding

**Co musi działać:**
- In-memory keyring (`agent.NewKeyring()`) żyjący przez czas sesji przeglądarki
- `agentAddKey(keyPEM, passphrase?)` — parsuje klucz PEM, dodaje do keyring
- `agentRemoveKey(fingerprint)` / `agentRemoveAll()`
- `agentListKeys()` — zwraca fingerprint + komentarz dla każdego klucza
- Przy połączeniu z `agentForward=true`:
  1. `agent.ForwardToAgent(sshClient, keyring)` — rejestruje handler
  2. `agent.RequestAgentForwarding(session)` — informuje serwer że agent jest dostępny
  3. Na zdalnym hoście `ssh-add -l` pokaże klucze z przeglądarki
  4. Na zdalnym hoście `ssh user@another-host` użyje tych kluczy

**Obsługiwane formaty kluczy:**
- RSA (PKCS#1 + PKCS#8)
- Ed25519
- ECDSA (P-256, P-384, P-521)
- Klucze OpenSSH format (`-----BEGIN OPENSSH PRIVATE KEY-----`)
- Klucze z passphrase (bcrypt KDF w formacie OpenSSH)

**Cykl życia kluczy:** Klucze żyją w pamięci WASM — page reload = wymazanie. Klucze są ładowane z Convex (zaszyfrowane) po zalogowaniu się użytkownika. Biblioteka NIE zarządza przechowywaniem kluczy — to odpowiedzialność aplikacji (Subterm).

#### 1.5.4 Port Forwarding (Local -L)

**Co musi działać:**

Standardowy SSH `-L` forward, ale zaadaptowany do przeglądarki (brak `net.Listen` w WASM):

1. **Subterm Web wysyła request** do Go WASM: "forwarduj `remoteHost:remotePort`"
2. **Go WASM** otwiera kanał SSH `direct-tcpip` do `remoteHost:remotePort`
3. **Go WASM** otwiera **drugi WebSocket** do proxy: `wss://proxy/tunnel?sessionId=xxx`
4. **Proxy** rejestruje tunel i alokuje:
   - **Subdomenę HTTP:** `abc123.tunnel.example.com` — proxy przyjmuje HTTP requesty na tej subdomenie i przekazuje je przez WebSocket do przeglądarki → Go WASM → SSH → remote service
   - **Raw port (opcjonalnie):** proxy otwiera TCP listener na losowym porcie (np. 10042), przekazuje bajty przez ten sam WebSocket → SSH → remote service
5. **Go WASM** zwraca do JS: `{ tunnelUrl: "https://abc123.tunnel.example.com", rawPort: 10042 }`
6. **Kiedy remote service odpowiada:** dane wracają tą samą ścieżką w drugą stronę

**Proxy musi wspierać:** rejestrację tuneli, subdomain routing, raw port allocation. To jest opisane w Części 2 (wsproxy).

**Ograniczenia:**
- Latency wyższa niż native port forwarding (HTTP request → proxy WS → browser WASM → SSH → remote)
- Wymaga współpracy proxy (nie jest self-contained w samej bibliotece)
- Raw TCP proxy port forwarding nie szyfruje ruchu między klientem a proxy (ale ten odcinek jest na localhost lub w zaufanej sieci)

### 1.6 API JavaScript (publiczne)

Biblioteka ekspozuje jeden globalny obiekt po załadowaniu WASM:

```typescript
// Po załadowaniu WASM, dostępne jako window.GoSSH
interface GoSSH {
  // === Połączenie SSH ===
  connect(config: {
    proxyUrl: string;           // wss://proxy.example.com/relay
    host: string;               // 192.168.1.1
    port: number;               // 22
    username: string;
    authMethod: 'password' | 'key' | 'agent';
    password?: string;
    keyPEM?: string;            // PEM-encoded private key
    keyPassphrase?: string;
    agentForward?: boolean;
    jumpHosts?: JumpHost[];     // ProxyJump chain
    onData: (data: Uint8Array) => void;       // stdout callback
    onClose: (reason: string) => void;        // disconnect callback
    onHostKey: (info: HostKeyInfo) => Promise<boolean>;  // host key verification
    onBanner: (banner: string) => void;       // SSH banner
  }): Promise<string>;  // → sessionId

  write(sessionId: string, data: Uint8Array): void;
  resize(sessionId: string, cols: number, rows: number): void;
  disconnect(sessionId: string): void;

  // === SFTP ===
  sftpOpen(sessionId: string): Promise<string>;  // → sftpId
  sftpClose(sftpId: string): void;
  sftpListDir(sftpId: string, path: string): Promise<FileInfo[]>;
  sftpMkdir(sftpId: string, path: string): Promise<void>;
  sftpRemove(sftpId: string, path: string, recursive: boolean): Promise<void>;
  sftpRename(sftpId: string, oldPath: string, newPath: string): Promise<void>;
  sftpChmod(sftpId: string, path: string, mode: number): Promise<void>;
  sftpStat(sftpId: string, path: string): Promise<FileInfo>;
  sftpUpload(sftpId: string, remotePath: string, data: Uint8Array,
    onProgress?: (bytes: number, total: number) => void): Promise<void>;
  sftpDownload(sftpId: string, remotePath: string,
    onProgress?: (bytes: number, total: number) => void): Promise<Uint8Array>;
  // Streaming download via Service Worker (large files):
  sftpDownloadStream(sftpId: string, remotePath: string,
    onProgress?: (bytes: number, total: number) => void): Promise<void>;  // triggers browser download

  // === Agent ===
  agentAddKey(keyPEM: string, passphrase?: string): Promise<string>;  // → fingerprint
  agentRemoveKey(fingerprint: string): void;
  agentRemoveAll(): void;
  agentListKeys(): KeyInfo[];

  // === Port Forwarding ===
  portForwardStart(sessionId: string, config: {
    remoteHost: string;
    remotePort: number;
    proxyTunnelUrl: string;   // wss://proxy.example.com/tunnel
  }): Promise<TunnelInfo>;
  portForwardStop(tunnelId: string): void;
  portForwardList(sessionId: string): TunnelInfo[];
}

interface JumpHost {
  proxyUrl: string;
  host: string;
  port: number;
  username: string;
  authMethod: 'password' | 'key' | 'agent';
  password?: string;
  keyPEM?: string;
  keyPassphrase?: string;
}

interface HostKeyInfo {
  hostname: string;
  fingerprint: string;   // SHA256:xxxxx
  keyType: string;        // ssh-ed25519, ssh-rsa, etc.
  randomArt: string;      // ASCII art
}

interface FileInfo {
  name: string;
  path: string;
  size: number;
  isDir: boolean;
  isSymlink: boolean;
  permissions: string;    // "rwxr-xr-x"
  modTime: number;        // Unix timestamp ms
}

interface KeyInfo {
  fingerprint: string;
  type: string;
  bits: number;
  comment: string;
}

interface TunnelInfo {
  id: string;
  remoteHost: string;
  remotePort: number;
  tunnelUrl: string;      // https://abc123.tunnel.example.com
  rawPort?: number;        // 10042 (for non-HTTP)
  active: boolean;
}
```

### 1.7 Callback vs Promise

Wszystkie operacje I/O zwracają **Promise** (nie callback). Wzorzec z sshterm:

```go
func newPromise(fn func() (interface{}, error)) js.Value {
    handler := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
        resolve, reject := args[0], args[1]
        go func() {
            result, err := fn()
            if err != nil {
                reject.Invoke(err.Error())
            } else {
                resolve.Invoke(result)
            }
        }()
        return nil
    })
    return js.Global().Get("Promise").New(handler)
}
```

Wyjątki: `onData`, `onClose`, `onBanner` to callbacki (ciągły strumień danych, nie jednorazowe operacje).

### 1.8 Host Key Verification

Callback `onHostKey` jest **async** (zwraca `Promise<boolean>`):

1. Go WASM: `HostKeyCallback` w `ssh.ClientConfig` jest wywoływany
2. Go wywołuje JS: `config.onHostKey({ hostname, fingerprint, keyType, randomArt })`
3. JS zwraca Promise — Go blokuje goroutine na kanale czekając na resolve
4. User widzi dialog "Trust this host?" z fingerprint i random art
5. User klika Yes/No → Promise resolve → Go kontynuuje lub przerywa

Biblioteka NIE przechowuje known hosts — to odpowiedzialność aplikacji. Biblioteka jedynie woła callback i respektuje odpowiedź.

### 1.9 Struktura repozytorium

```
gossh-wasm/
├── README.md
├── LICENSE (MIT)
├── go.mod
├── go.sum
├── Makefile                   # GOOS=js GOARCH=wasm go build
├── main.go                    # WASM entry point, JS API registration
├── ssh.go                     # SSH connect/write/resize/disconnect
├── sftp.go                    # SFTP operations
├── agent.go                   # In-memory SSH agent
├── portforward.go             # Port forwarding via SSH direct-tcpip
├── transport.go               # WebSocket net.Conn adapter
├── jsutil.go                  # Promise helper, Uint8Array conversion
├── stream_worker.js           # Service Worker for streaming SFTP downloads
├── wasm_exec.js               # Go WASM runtime (copied from Go SDK)
├── example/
│   ├── index.html             # Minimal working example
│   └── main.js                # Example usage of GoSSH API
└── tests/
    ├── integration_test.go    # Tests against real SSH server (Docker)
    └── testserver/            # Test SSH server for CI
```

### 1.10 Rozmiar WASM i optymalizacja

- Build: `GOOS=js GOARCH=wasm go build -ldflags="-s -w" -o gossh.wasm .`
- `-s -w` — strip symbols i DWARF, zmniejsza o ~30%
- Szacowany rozmiar: **8-12 MB** raw, **2-3 MB** po Brotli (na serwerze CDN)
- `wasm_exec.js`: ~20 KB (dostarczany z Go SDK)
- Serwer powinien ustawiać `Content-Encoding: br` i cache headers (`immutable`)

### 1.11 Czego biblioteka NIE robi (odpowiedzialność aplikacji)

- **Nie zarządza UI** — brak xterm.js, brak terminala. Tylko raw bytes in/out.
- **Nie przechowuje kluczy** — agentAddKey przyjmuje PEM string, nie wie skąd pochodzi
- **Nie przechowuje known hosts** — woła callback, nie zapisuje decyzji
- **Nie obsługuje auth UI** — nie wie o Clerk, Convex, ani żadnym systemie logowania
- **Nie decyduje o proxy URL** — otrzymuje URL jako parametr
- **Nie zarządza wieloma tabami** — zwraca sessionId, aplikacja zarządza mapą

---

## Część 2: wsproxy (WebSocket↔TCP relay)

### 2.1 Co to robi

Minimalistyczny serwer proxy, który:
1. Przyjmuje połączenie WebSocket z przeglądarki
2. Nawiązuje połączenie TCP do docelowego SSH serwera
3. Przekazuje bajty w obie strony (bidirectional relay)
4. Nie widzi, nie loguje, nie analizuje ruchu SSH (zero-knowledge)
5. Obsługuje subdomain tunneling dla port forwarding

### 2.2 Dlaczego nie tlsproxy/chisel/websockify

| Projekt | Problem dla nas |
|---------|----------------|
| c2FmZQ/tlsproxy | Zbyt skomplikowany (SSO, cert management, web server). 98 stars, 1 autor. Tight coupling z sshterm. |
| jpillora/chisel | 12k stars, ale model to klient-serwer (chisel client na maszynie usera). Nie wspiera dynamicznego tunneling z WebSocket. |
| novnc/websockify | Prosty relay, ale Python, brak tunnel subdomain, brak auth. |

Nasz proxy to **~300-500 linii Go** — prostszy niż jakikolwiek z powyższych. Specyficznie zaprojektowany pod browser SSH z tunneling.

### 2.3 Endpointy HTTP

```
GET /health                    → 200 "ok" (healthcheck)
GET /relay?host=X&port=Y       → Upgrade to WebSocket, relay to X:Y
GET /tunnel?id=X               → Upgrade to WebSocket, register tunnel X
```

Oba `/relay` i `/tunnel` wymagają uwierzytelnienia (JWT w query param lub Authorization header).

### 2.4 Relay (/relay)

Prosty bidirectional relay:

```
Browser ──WebSocket──► Proxy ──TCP──► SSH Server (host:port)
         encrypted SSH data          encrypted SSH data
```

Logika:
1. Parse `host` i `port` z query params
2. Walidacja JWT (Clerk-issued token) → deny jeśli nieprawidłowy
3. Walidacja target: blacklist `localhost`, `127.0.0.1`, `::1`, `169.254.x.x` (link-local), `10.x.x.x` (private ranges — opcjonalnie)
4. `websocket.Upgrade()` → WebSocket conn
5. `net.DialTimeout("tcp", host:port, 10s)` → TCP conn
6. Dwie goroutiny: `io.Copy(tcp, ws)` i `io.Copy(ws, tcp)`
7. Kiedy jedna strona zamknie — zamknij drugą

Proxy **nie** parsuje, nie buforuje, nie modyfikuje danych. Zero-knowledge.

### 2.5 Tunneling (/tunnel) — port forwarding

Bardziej złożony mechanizm dla HTTP port forwarding:

```
Zewnętrzny klient                     Przeglądarka (WASM)
        │                                     │
        │ HTTP request to                     │
        │ abc123.tunnel.example.com           │
        ▼                                     │
┌──────────────┐                              │
│ Proxy/Caddy  │ ──reverse proxy──►           │
│ (subdomain   │ ──WebSocket──────────────────┤
│  routing)    │                              │
└──────────────┘                              │
                                              ▼
                                    SSH direct-tcpip channel
                                              │
                                              ▼
                                     Remote service (localhost:8080)
```

**Rejestracja tunelu:**
1. Go WASM otwiera WebSocket do `/tunnel?id=<random-uuid>`
2. Proxy zapisuje mapping: `abc123 → WebSocket connection`
3. Proxy odpowiada: `{ "tunnelUrl": "https://abc123.tunnel.example.com", "rawPort": 10042 }`

**Obsługa HTTP requestów na subdomenach:**
1. Request do `abc123.tunnel.example.com` trafia do proxy (via Caddy/wildcard DNS)
2. Proxy szuka mappingu `abc123` → WebSocket conn
3. Proxy serializuje HTTP request i wysyła przez WebSocket do przeglądarki
4. Go WASM w przeglądarce: deserializuje HTTP, przekazuje przez SSH `direct-tcpip` do remote
5. Remote odpowiada → Go WASM → WebSocket → Proxy → klient HTTP

**Raw port fallback (non-HTTP):**
1. Proxy alokuje port z puli (np. 10000-10100)
2. `net.Listen("tcp", ":10042")` — nasłuchuje na tym porcie
3. Każde połączenie TCP → relay przez ten sam WebSocket tunnel → SSH → remote
4. Klient łączy się bezpośrednio na `proxy.example.com:10042`

**Protokół kontrolny (WebSocket):**
Wiadomości JSON przez tunel WebSocket:

```json
// Proxy → Browser (po rejestracji tunelu):
{ "type": "tunnel_ready", "tunnelUrl": "https://abc123.tunnel.example.com", "rawPort": 10042 }

// Proxy → Browser (przychodzący HTTP request):
{ "type": "http_request", "id": "req-1", "method": "GET", "path": "/api/data",
  "headers": {...}, "body": "..." }

// Browser → Proxy (odpowiedź HTTP):
{ "type": "http_response", "id": "req-1", "status": 200,
  "headers": {...}, "body": "..." }

// Proxy → Browser (przychodzące raw TCP connection):
{ "type": "tcp_open", "connId": "conn-1" }

// Bidirectional raw data (binary WebSocket frames z prefixem connId):
[4 bytes connId length][connId bytes][payload bytes]
```

### 2.6 Uwierzytelnienie

Proxy waliduje JWT (Clerk-issued) przy każdym nowym połączeniu:

1. Token w query param: `?token=eyJ...` (WebSocket nie wspiera custom headers)
2. Weryfikacja podpisu (Clerk JWKS endpoint, cachowane)
3. Sprawdzenie `exp`, `iss`, `aud`
4. Opcjonalnie: sprawdzenie subscription status (embedded claim lub query do Convex)

**Proxy NIE ma dostępu do Convex** — jeśli potrzebna walidacja subskrypcji, to Clerk JWT powinien zawierać custom claim `subscription: "active"` (konfigurowane w Clerk JWT templates).

### 2.7 Rate limiting i bezpieczeństwo

- **Per-IP connection limit:** max 10 jednoczesnych WebSocket per IP
- **Per-user connection limit:** max 20 jednoczesnych sesji per Clerk userId (z JWT)
- **Bandwidth:** brak limitu (zero-knowledge — proxy nie wie co przechodzi)
- **Target blacklist:** blokada połączeń do prywatnych zakresów IP (RFC 1918, loopback, link-local)
- **WebSocket ping:** co 30 sekund, timeout 60 sekund (utrzymanie połączenia przez NAT)
- **CORS:** `Access-Control-Allow-Origin` tylko `https://app.subterm.co` i `http://localhost:*` (dev)

### 2.8 Deployment model

Proxy jest zapakowany jako Docker image:

```dockerfile
FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY go.* ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o wsproxy .

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/wsproxy /wsproxy
EXPOSE 8080
ENTRYPOINT ["/wsproxy"]
```

Konfiguacja przez env vars:

| Zmienna | Domyślna | Opis |
|---------|----------|------|
| `PORT` | `8080` | Port HTTP/WebSocket |
| `CLERK_JWKS_URL` | — | URL do Clerk JWKS (weryfikacja JWT) |
| `ALLOWED_ORIGINS` | `*` | Dozwolone originy (CORS) |
| `TUNNEL_DOMAIN` | — | Domena dla subdomain tunneling (np. `tunnel.example.com`) |
| `TUNNEL_PORT_MIN` | `10000` | Początek zakresu portów dla raw TCP tunneli |
| `TUNNEL_PORT_MAX` | `10100` | Koniec zakresu portów |
| `MAX_CONNS_PER_IP` | `10` | Limit połączeń per IP |
| `MAX_CONNS_PER_USER` | `20` | Limit połączeń per user (JWT sub claim) |
| `BLOCKED_TARGETS` | `127.0.0.0/8,10.0.0.0/8,...` | Zablokowane zakresy docelowe IP |

### 2.9 Struktura repozytorium

```
wsproxy/
├── README.md
├── LICENSE (MIT)
├── go.mod
├── go.sum
├── Dockerfile
├── docker-compose.yml         # Przykładowy deploy z Caddy
├── main.go                    # Entry point, HTTP server
├── relay.go                   # WebSocket↔TCP bidirectional relay
├── tunnel.go                  # Subdomain + raw port tunnel manager
├── auth.go                    # JWT validation (Clerk JWKS)
├── ratelimit.go               # Per-IP, per-user rate limiting
├── config.go                  # Env var parsing
└── tests/
    ├── relay_test.go
    └── tunnel_test.go
```

### 2.10 Deployment na OVH (Subterm-specific)

Nie jest częścią open-source repo, ale Subterm wdraża wsproxy tak:

```
┌──────────────────────────────────────────────┐
│  OVH Dedicated Server (devserver2)           │
│                                              │
│  Caddy (port 443, TLS termination)           │
│  ├─ proxy.subterm.co → localhost:8080        │
│  ├─ *.tunnel.subterm.co → localhost:8080     │
│  └─ (inne serwisy)                           │
│                                              │
│  Docker: wsproxy (port 8080)                 │
│  ├─ /relay → WebSocket↔TCP relay             │
│  ├─ /tunnel → subdomain tunnel registration  │
│  └─ /health → healthcheck                   │
│                                              │
│  Raw TCP ports 10000-10100 (bypass Caddy)    │
└──────────────────────────────────────────────┘
```

---

## Część 3: Interakcja gossh-wasm ↔ wsproxy ↔ Subterm

### 3.1 Flow: Użytkownik łączy się z hostem

```
1. Subterm Web: user klika host w sidebar
2. Subterm: pobiera dane hosta z Convex (ip, port, login, authType, keys)
3. Subterm: jeśli authType=key, deszyfruje klucz master passwordem
4. Subterm: jeśli agentForward=true, ładuje klucze do agenta:
   GoSSH.agentAddKey(keyPEM, passphrase)
5. Subterm: wywołuje GoSSH.connect({
     proxyUrl: "wss://proxy.subterm.co/relay",
     host: "192.168.1.100",
     port: 22,
     username: "admin",
     authMethod: "key",
     keyPEM: decryptedKey,
     agentForward: true,
     onData: (data) => terminal.write(data),
     onClose: (reason) => showDisconnectDialog(reason),
     onHostKey: (info) => checkConvexKnownHosts(info),
   })
6. gossh-wasm: otwiera WebSocket do wss://proxy.subterm.co/relay?host=192.168.1.100&port=22&token=eyJ...
7. wsproxy: waliduje JWT, otwiera TCP do 192.168.1.100:22, zaczyna relay
8. gossh-wasm: SSH handshake przez WebSocket (cała kryptografia w WASM)
9. gossh-wasm: host key callback → Subterm sprawdza Convex knownHosts
10. gossh-wasm: autentykacja kluczem (klucz nigdy nie opuszcza WASM)
11. gossh-wasm: PTY request + shell
12. gossh-wasm: onData callback z danymi terminala → Subterm renderuje w ghostty/beamterm
```

### 3.2 Flow: Port forwarding

```
1. Subterm: user włącza port forward (np. localhost:3000 na remote)
2. Subterm: GoSSH.portForwardStart(sessionId, {
     remoteHost: "localhost",
     remotePort: 3000,
     proxyTunnelUrl: "wss://proxy.subterm.co/tunnel",
   })
3. gossh-wasm: otwiera WebSocket do wss://proxy.subterm.co/tunnel?id=abc123&token=eyJ...
4. wsproxy: rejestruje tunel abc123, alokuje subdomenę + raw port
5. wsproxy → gossh-wasm: { tunnelUrl: "https://abc123.tunnel.subterm.co", rawPort: 10042 }
6. gossh-wasm → Subterm: TunnelInfo { tunnelUrl, rawPort, active: true }
7. Subterm: wyświetla URL w UI z przyciskiem "Copy URL"

Kiedy ktoś otwiera https://abc123.tunnel.subterm.co:
8. HTTP request → Caddy → wsproxy
9. wsproxy: serializuje request, wysyła przez WebSocket do przeglądarki
10. gossh-wasm: otwiera SSH direct-tcpip channel do localhost:3000 na remote
11. gossh-wasm: przekazuje request → SSH → remote service
12. Remote service odpowiada → SSH → gossh-wasm → WebSocket → wsproxy → klient HTTP
```

### 3.3 Flow: SFTP upload dużego pliku

```
1. User przeciąga plik (500MB) na file manager w Subterm Web
2. Subterm: File API daje File object z stream()
3. Subterm: GoSSH.sftpUpload(sftpId, "/home/user/file.zip", fileData, onProgress)
4. gossh-wasm: czyta Uint8Array kawałkami (1MB), pisze przez SFTP
5. gossh-wasm: woła onProgress(bytesWritten, totalSize) po każdym kawałku
6. Subterm: aktualizuje progress bar
7. Po zakończeniu: Promise resolve
```

---

## Część 4: Ryzyka i pytania otwarte

### 4.1 Znane ryzyka

| Ryzyko | Mitygacja |
|--------|-----------|
| Go WASM runtime jest duży (8-12 MB) | Brotli compression (2-3 MB), aggressive caching, lazy load |
| Go WASM single-threaded (no goroutine parallelism w przeglądarce) | Go scheduler działa kooperatywnie — działa OK dla I/O-bound operacji jak SSH |
| Service Worker dla streaming SFTP wymaga HTTPS | Production zawsze na HTTPS; dev z self-signed cert |
| Port forwarding subdomain wymaga wildcard DNS + TLS | Caddy z DNS challenge (Cloudflare) lub Let's Encrypt |
| Pliki >2 GB mogą OOM w WASM (32-bit address space) | Streaming approach (Service Worker), nigdy nie buforuj całego pliku |
| WebSocket timeout przez NAT/proxy po 60s idle | Ping/pong co 30s w proxy |
| Browser zamknięty = utrata kluczy agenta + aktywnych tuneli | Oczekiwane zachowanie — user wie że refresh = disconnect |

### 4.2 Otwarte pytania do rozstrzygnięcia podczas implementacji

1. **Multiplexing:** Czy jeden WebSocket per sesja SSH, czy multiplexing wielu sesji przez jeden WS? (Rekomendacja: jeden WS per sesja — prostsze, izolacja błędów)
2. **Tunnel protocol:** Dokładny format binarny dla multiplexowania HTTP requests + raw TCP przez jeden tunnel WebSocket. Trzeba zaprojektować framing.
3. **Service Worker lifecycle:** Jak obsłużyć update SW bez przerywania aktywnych transferów?
4. **Go WASM GC pressure:** Przy dużym throughput (SFTP), `js.CopyBytesToGo/JS` tworzy dużo alokacji. Potrzebne profilowanie.
5. **IPv6 targets:** Czy proxy powinien wspierać IPv6 targets? (Tak, ale blacklist musi to uwzględniać)
6. **Reconnect:** Czy gossh-wasm powinien mieć auto-reconnect, czy to odpowiedzialność aplikacji? (Rekomendacja: aplikacja — lib nie wie o credentials storage)

---

## Część 5: Wnioski z audytu c2FmZQ/sshterm

Przeprowadzono pełny audyt bezpieczeństwa i jakości kodu sshterm (~4300 linii Go, 12 kluczowych plików). Poniżej wnioski istotne dla gossh-wasm i wsproxy.

### 5.1 Wzorce do zaadaptowania

| Wzorzec | Plik źródłowy | Priorytet | Uwagi |
|---------|--------------|-----------|-------|
| WebSocket → `net.Conn` adapter | `websocket.go` | **MUST** | Elegancki pattern: `chan js.Value` jako bufor + greedy read + chunked write (4096B). Dodać `sync.Mutex` na pole `err` (race condition w oryginale). |
| SSH lifecycle + keepalive | `ssh.go` | **MUST** | `context.AfterFunc` dla cleanup, keepalive 30s + 30s timeout. Wydzielić z UI (sshterm miesza transport z terminal I/O). |
| `maskControl()` — sanityzacja | `ssh.go` | **MUST** | Filtruje control characters z SSH banner/prompt. Chroni przed terminal injection. Proste ale kluczowe. |
| Agent interface (keyRing) | `agent.go` | **SHOULD** | Solidna implementacja `agent.Agent` z `sync.Mutex` + `subtle.ConstantTimeCompare`. Wydzielić z global state (`var globalAgent`). |
| Service Worker streaming | `streams.go` | **SHOULD** | `ReadableStream` z pull-based model, progress via `atomic.Int64`, cancel via channel. Dodać fallback (Blob URL) gdy SW niedostępny. |
| `NewPromise()` wrapper | `jsutil.go` | **SHOULD** | Goroutine w Promise executor — standardowy wzorzec Go WASM. |
| Greedy read | `websocket.go:143` | **NICE** | Optymalizacja: jeśli bufor pusty ale channel ma więcej danych, czytaj dalej zamiast wracać z częściowym wynikiem. |
| `BroadcastChannel` cross-tab sync | `app.go` | **NICE** | Jeśli gossh-wasm będzie wspierać shared agent między tabami w przyszłości. |

### 5.2 Znalezione problemy bezpieczeństwa w sshterm (do uniknięcia)

| Severity | Problem | Lokalizacja | Jak unikamy w gossh-wasm |
|----------|---------|-------------|--------------------------|
| **MEDIUM** | Race condition: `ws.err` ustawiane bez mutex z JS callback i czytane w `Read()`/`Write()` | `websocket.go:72` | `sync.Mutex` na wszelkim shared state w WebSocket adapter |
| **MEDIUM** | `Await()` bez timeout — jeśli JS Promise nigdy nie resolve, goroutine wisi na zawsze | `jsutil.go:94-116` | Dodać `context.Context` z deadline do `Await()` |
| **LOW** | `TLSProxySID()` czyta cookie bez walidacji formatu | `jsutil.go:218` | Nie kopiujemy (coupling z tlsproxy) |
| **LOW** | SSH keepalive bez exponential backoff | `ssh.go` | Dodać backoff przy niestabilnym łączu |
| **INFO** | Brak TOFU warning counter — user może bezmyślnie akceptować zmienione host keys | `ssh.go` | Odpowiedzialność aplikacji (Subterm), nie lib |
| **INFO** | Identity provider cert flow bez certificate pinning | `keys.go` | Nie kopiujemy (specyficzne dla tlsproxy) |

### 5.3 Problemy jakościowe sshterm (lekcje dla nas)

| Problem | Szczegóły | Nasza odpowiedź |
|---------|-----------|-----------------|
| **Zero testów** | `find -name "*_test.go" → 0` | gossh-wasm MUSI mieć testy od dnia 1. Min: WebSocket adapter, SSH handshake mock, agent ops, SFTP ops. CI z Docker SSH server. |
| **Global mutable state** | `var globalAgent = newKeyRing()` | Agent jako pole struktury, nie package-level var. Dependency injection. |
| **Magic numbers** | `4096` (buffer), `20480` (file limit) — bez nazwanych constów | Named constants w `const` bloku z dokumentacją |
| **SFTP monolith** | 802 linii w jednym pliku (REPL + parsing + upload + download + drag-drop) | Osobne pliki: `sftp.go` (operations), `sftp_transfer.go` (upload/download + streaming) |
| **Brak graceful degradation** | Service Worker niedostępny = download niemożliwy | Chunked Blob fallback gdy SW niedostępny |

### 5.4 Kryptografia sshterm — ocena

Kryptograficzna strona sshterm jest **prawidłowa**:

- `subtle.ConstantTimeCompare` użyte konsekwentnie (host key, agent lock, cert matching) — odporne na timing attacks
- Backup: PBKDF2-SHA256 + NaCl secretbox (XSalsa20-Poly1305) — sprawdzone algorytmy
- RSA default 3072-bit — zgodne z NIST SP 800-57
- `crypto/rand` wszędzie (brak math/rand dla bezpieczeństwa)
- Brak hardcodowanych sekretów
- Private keys nigdy nie logowane

Jedyny zarzut: PBKDF2 50000 iteracji (OWASP rekomenduje 600k dla SHA-256), ale w WASM to kompromis wydajnościowy.

**Wniosek dla gossh-wasm:** Nie implementujemy własnej kryptografii — cała kryptografia SSH jest w `golang.org/x/crypto/ssh`. Nasza rola to prawidłowe użycie tej biblioteki + timing-safe porównania tam gdzie potrzebne.

### 5.5 Czego NIE kopiować

| Element | Powód |
|---------|-------|
| IndexedDB wrapper (`indexeddb.go`) | Subterm ma Convex / local-storage |
| SFTP REPL (`sftp.go` interactive CLI) | Subterm ma GUI file manager |
| Endpoint management (`ep.go`) | Subterm ma host management w UI |
| Backup/restore (`db.go`) | Subterm ma Convex cloud sync |
| Identity provider cert flow (`keys.go` dynSigner) | Specyficzne dla tlsproxy |
| `TLSProxySID()` cookie coupling | Specyficzne dla tlsproxy |
| `BroadcastChannel` DB sync | Subterm sync inaczej (Convex realtime) |

### 5.6 Ogólna ocena sshterm

| Kategoria | Ocena | Komentarz |
|-----------|-------|-----------|
| Bezpieczeństwo krypto | **8/10** | Prawidłowe użycie `subtle`, dobre algorytmy |
| Input validation | **7/10** | Rozsądne limity, `maskControl()`, drobne edge cases |
| Jakość kodu | **6/10** | Czytelny, ale zero testów i magic numbers |
| Architektura | **7/10** | Dobra separacja warstw, monolityczny SFTP |
| Przydatność jako referencja | **8/10** | Doskonała baza wzorców |

**Konkluzja:** sshterm jest bezpieczny i wartościowy jako referencja. Główne lekcje: (1) testy od dnia 1, (2) mutex na shared state w WebSocket, (3) timeout w Await(), (4) separacja lib od UI, (5) named constants, (6) fallback dla Service Worker.

---

## Część 6: Kolejność implementacji

```
1. gossh-wasm: transport.go (WebSocket net.Conn)           ← fundament wszystkiego
2. gossh-wasm: ssh.go (connect, write, resize, disconnect)  ← minimum viable
3. wsproxy: relay.go + auth.go + main.go                    ← potrzebne do testowania ssh.go
4. Test: połączenie SSH end-to-end przez przeglądarkę       ← milestone #1
5. gossh-wasm: sftp.go                                      ← po potwierdzeniu że SSH działa
6. gossh-wasm: agent.go                                     ← po SFTP
7. gossh-wasm: portforward.go                               ← najbardziej złożone
8. wsproxy: tunnel.go                                       ← potrzebne do portforward
9. Test: pełny feature set end-to-end                       ← milestone #2
10. Optymalizacja: streaming SFTP, binary size               ← polish
```

Kroki 1-4 to **MVP** — wystarczy aby udowodnić że architektura działa.
Kroki 5-9 to **pełny feature set** wymagany przez Subterm Web.
Krok 10 to **optymalizacja** przed production launch.
