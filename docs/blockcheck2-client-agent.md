# blockcheck2 client/agent

This is a Python port of `blockcheck2.sh` split into two programs:

| Program | Runs on | Responsibility |
| --- | --- | --- |
| `blockcheck2_agent.py` | the Linux router | installs firewall redirection to an NFQUEUE and starts/stops `nfqws2` |
| `blockcheck2_client.py` | any machine whose traffic goes through that router | generates bypass strategies, asks the agent to apply each one, runs `curl` locally and reports results |

```
          client machine                         Linux router
   +--------------------------+          +--------------------------------+
   | blockcheck2_client.py    |  TCP     | blockcheck2_agent.py           |
   |  - resolves domains      | JSON     |  - nftables / iptables rules   |
   |  - generates strategies  |<-------->|  - nfqws2 start/stop           |
   |  - runs curl locally     |  lines   |  - blob file upload            |
   +--------------------------+          +--------------------------------+
                                                  |
                                            nfqws2 + NFQUEUE
```

The client never touches the firewall and never runs `nfqws2`. The agent never
runs `curl`. Both are required.

## Requirements

- Python 3.7+ on both machines.
- Router: Linux with `nftables` (preferred) or `iptables`, and the `nfqws2`
  binary from this repository (`nfq2/nfqws2`).
- Router: must be run as **root** (needed for firewall and NFQUEUE).
- Client: `curl` 7.49+ (for `--connect-to`). HTTP/3 checks additionally need a
  curl built with HTTP/3 support.
- The client machine must route its Internet traffic through the router, so the
  router sees the packets it is asked to redirect.

## Router: start the agent

```sh
sudo python3 blockcheck2_agent.py --listen ROUTER_IP --port 1993 --token 'change-me'
```

Pass the router's LAN address to `--listen`, or omit it to listen on all
interfaces. Use `--token` to
require a shared secret; without it any host that can reach the port can start
and stop `nfqws2`.

### Agent options

| Option | Default | Meaning |
| --- | --- | --- |
| `--listen ADDR` | all interfaces | address to bind |
| `--port N` | `1993` | TCP port |
| `--token SECRET` | none | shared secret required from clients |
| `--zapret-base DIR` | script directory | location of `lua/`, used for nfqws2 lua libs |
| `--nfqws2 PATH` | `DIR/nfq2/nfqws2` | nfqws2 executable |
| `--fwtype nftables\|iptables` | auto | override firewall backend |
| `--qnum N` | `200` | NFQUEUE number |
| `--uid N`, `--gid N` | `0` | uid/gid nfqws2 runs as |
| `--sweep` | always on | remove stale `blockcheck2-*` firewall objects at startup |

The agent removes its firewall rules and stops `nfqws2` when the client
disconnects, on `reset`, on `shutdown`, and on `SIGINT`/`SIGTERM`.

## Client: run the checks

```sh
python3 blockcheck2_client.py --agent ROUTER_IP:1993 --token 'change-me' \
    --domains rutracker.org --ipv 46
```

Multiple domains and URIs are supported:

```sh
python3 blockcheck2_client.py --agent ROUTER_IP:1993 \
    --domains "rutracker.org/forum/index.php ej.ru www.torproject.org" \
    --ipv 4 --tls12 --no-http --scanlevel standard --repeats 2
```

### Client options

| Option | Default | Meaning |
| --- | --- | --- |
| `--agent HOST:PORT` | `ROUTER_IP:1993` | agent address |
| `--token SECRET` | `$BLOCKCHECK2_TOKEN` | agent shared secret |
| `--domains LIST` | `rutracker.org` | space separated domains / URIs |
| `--ipv 4\|6\|46` | `4` | IP version(s); `46` tests both |
| `--http` / `--no-http` | http on | test plain HTTP |
| `--tls12` / `--no-tls12` | tls12 on | test HTTPS with TLS 1.2 |
| `--tls13` / `--no-tls13` | auto | test HTTPS with TLS 1.3 (only if curl supports it) |
| `--http3` / `--no-http3` | auto | test QUIC/HTTP3 (only if curl supports it) |
| `--repeats N` | `1` | attempts per strategy |
| `--parallel` | off | run the repeat attempts in parallel |
| `--scanlevel veryquick\|quick\|standard\|force` | `standard` | how aggressively strategy families are explored |
| `--skip-ipblock` | off | skip IP/port block diagnostics |
| `--skip-pktws` | off | do not test bypass strategies (diagnostics only) |
| `--simulate` | off | fake test results (no nfqws2, no curl checks) |
| `--sim-success-rate N` | `10` | success percentage used by `--simulate` |
| `--curl PATH` | `curl` | curl executable |
| `--max-time N` | `2` | curl timeout, seconds |
| `--max-time-quic N` | same as `--max-time` | QUIC timeout |
| `--user-agent STR` | `Mozilla` | User-Agent sent by curl |
| `--http-port`, `--https-port`, `--quic-port` | `80`, `443`, `443` | target ports |
| `--unblocked-dom DOM` | `iana.org` | control domain for IP-block diagnostics |
| `--pace MS` | `0` | minimum milliseconds per check |
| `--curl-verbose` | off | add `-v` to curl |

`SCANLEVEL` controls how much is skipped once a family is known to work:

- `veryquick` – like `quick`, and stop after the first success in a family.
- `quick` – skip further attempts after the first failure.
- `standard` – investigate what works (default).
- `force` – test everything, even after success.

## Environment variables

All CLI defaults can be set through the environment, including the strategy
knobs from the shell version:

```
BLOCKCHECK2_AGENT, BLOCKCHECK2_TOKEN, DOMAINS, IPVS, TEST, REPEATS, PARALLEL,
SCANLEVEL, SKIP_IPBLOCK, SKIP_PKTWS, SIMULATE, SIM_SUCCESS_RATE, CURL,
CURL_MAX_TIME, CURL_MAX_TIME_QUIC, USER_AGENT, HTTP_PORT, HTTPS_PORT,
QUIC_PORT, UNBLOCKED_DOM, PACE, CURL_VERBOSE

FOOLINGS46_TCP, FOOLINGS6_TCP, FOOLINGS6_UDP, FOOLINGS_UDP, FAKE_REPEATS,
MIN_TTL, MAX_TTL, MIN_AUTOTTL_DELTA, MAX_AUTOTTL_DELTA, MULTIDISORDER, TCP_MD5,
FAKE_HTTP, FAKE_HTTPS, FAKE_QUIC, FAKED_PATTERN_HTTP, FAKED_PATTERN_HTTPS,
HOSTFAKE, SEQOVL_PATTERN_HTTP, SEQOVL_PATTERN_HTTPS,
PKTWS_EXTRA_PRE, PKTWS_EXTRA_POST, NOTEST_*
```

`FAKE_*`, `FAKED_PATTERN_*` and `SEQOVL_PATTERN_*` point at files on the
**client**. The client uploads them to the agent automatically before use.

## How a run proceeds

1. Client connects to the agent (`ping`) and checks local curl capabilities.
2. For each domain and IP version it resolves the target addresses.
3. It checks connectivity without a bypass. If the target already works, the
   bypass scan is skipped unless `--scanlevel force`.
4. It asks the agent to install redirection for the resolved IPs, protocol and
   port (`prepare`).
5. For every generated strategy:
   - client sends `start` with the nfqws2 arguments;
   - client runs the local curl check (with `--connect-to`);
   - client sends `stop`.
6. When all families are done the client sends `unprepare`.
7. A summary of working strategies is printed. With multiple domains it also
   prints common strategies and coverage counts.

Note that a successful result means: *traffic from this client, routed through
this router, with this strategy, passes the check*. It is a starting point for
your zapret configuration, not a guaranteed recipe.

## Quick start

```sh
# on the router
sudo python3 blockcheck2_agent.py --listen ROUTER_IP --port 1993 --token secret

# on the client (must use the router as gateway)
python3 blockcheck2_client.py --agent ROUTER_IP:1993 --token secret \
    --domains rutracker.org --ipv 46 --scanlevel standard
```

## Troubleshooting

- **`cannot connect to agent`** – check `--listen`, firewall on the router, and
  that `--agent`/`--token` match.
- **Every strategy fails** – confirm the client's traffic actually goes through
  the router (`traceroute`, or run the client on the router itself). Also make
  sure no other zapret/nfqws instance is running on the router.
- **Agent logs nothing about nfqws2 failures** – nfqws2 output is discarded.
  Reproduce manually with the same arguments to see errors.
- **No TLS 1.3 / HTTP3 tests** – the local curl lacks support; the client
  disables those checks automatically.
- **nftables vs iptables** – the agent picks nftables on kernels 4.16+ when
  `nft` is present. Use `--fwtype` to override.

## Security notes

- The agent can run `nfqws2` with arbitrary arguments and modifies firewall
  state. Run it only on a trusted network and always set `--token`.
- The API is plain TCP without encryption. Do not expose the port to the
  Internet; restrict it to your LAN or a VPN.
