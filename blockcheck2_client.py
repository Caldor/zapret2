#!/usr/bin/env python3
"""blockcheck2 client - strategy generator and curl checker.

The client does NOT run nfqws2 and does NOT touch the firewall.  It asks the
Linux agent (blockcheck2_agent.py), which runs on the router, to start/stop
nfqws2 with a given strategy.  curl checks run locally, so this machine must
send its traffic through the router running the agent.

Typical use:

    python3 blockcheck2_client.py --agent ROUTER_IP:1993 --token secret \
        --domains rutracker.org --ipv 46

The strategy families from blockcheck2.d/standard were ported to Python and
are generated combinatorially, honouring SCANLEVEL and the NOTEST_* switches.
"""

import argparse
import base64
import hashlib
import json
import os
import random
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor

AGENT_VERSION = "2.0"

LOOP4 = ".".join(str(x) for x in (127, 0, 0, 1))
LOOP6 = ":" * 2 + "1"
# empty HOST1:PORT1 part of curl --connect-to HOST1:PORT1:HOST2:PORT2
CT_EMPTY = ":" * 2


# --------------------------------------------------------------------------
# agent connection
# --------------------------------------------------------------------------

class AgentError(RuntimeError):
    pass


class AgentConnection:
    """Persistent JSON-lines client for blockcheck2_agent."""

    def __init__(self, hostport, token=None, timeout=30):
        host, _, port = hostport.rpartition(":")
        if not host:
            host, port = hostport, "1993"
        self.host = host.strip("[]")
        self.port = int(port)
        self.token = token
        self.timeout = timeout
        self.sock = None
        self.rf = None
        self._blob_cache = {}

    def _connect(self):
        if self.sock is not None:
            return
        try:
            self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        except OSError as e:
            raise AgentError("cannot connect to agent %s:%d: %s" % (self.host, self.port, e))
        self.rf = self.sock.makefile("rwb")

    def close(self):
        try:
            if self.rf:
                self.rf.close()
            if self.sock:
                self.sock.close()
        except OSError:
            pass
        self.sock = self.rf = None

    def request(self, cmd, **kw):
        req = {"cmd": cmd}
        if self.token:
            req["token"] = self.token
        req.update(kw)
        self._connect()
        try:
            self.rf.write((json.dumps(req) + "\n").encode("utf-8"))
            self.rf.flush()
            line = self.rf.readline()
        except OSError as e:
            self.close()
            raise AgentError("agent communication failed: %s" % e)
        if not line:
            self.close()
            raise AgentError("agent closed the connection")
        try:
            rep = json.loads(line.decode("utf-8", "replace"))
        except ValueError as e:
            raise AgentError("bad reply from agent: %s" % e)
        if not rep.get("ok"):
            raise AgentError(rep.get("error", "agent error"))
        return rep

    def ping(self):
        return self.request("ping")

    def prepare(self, ipv, proto, port, ips):
        return self.request("prepare", ipv=ipv, proto=proto, port=port, ips=ips)

    def unprepare(self):
        try:
            return self.request("unprepare")
        except AgentError:
            return None

    def start(self, args):
        return self.request("start", args=list(args))

    def stop(self):
        try:
            return self.request("stop")
        except AgentError:
            return None

    def reset(self):
        try:
            return self.request("reset")
        except AgentError:
            return None

    def upload(self, path):
        st = os.stat(path)
        key = (os.path.abspath(path), st.st_size, int(st.st_mtime))
        if key in self._blob_cache:
            return self._blob_cache[key]
        with open(path, "rb") as f:
            data = f.read()
        rep = self.request("put_file", name=os.path.basename(path),
                           content_b64=base64.b64encode(data).decode("ascii"))
        self._blob_cache[key] = rep["path"]
        return rep["path"]


# --------------------------------------------------------------------------
# small utilities
# --------------------------------------------------------------------------

def split_uri(s):
    """rutracker.org/forum/index.php -> ('rutracker.org', 'forum/index.php')."""
    if "/" in s:
        host, rest = s.split("/", 1)
        return host, rest
    return s, ""


def bracket(ip):
    return "[%s]" % ip if ":" in ip else ip


def tolower(s):
    return s.lower()


def contains(s, sub):
    return sub in s


def curl_code_text(code):
    return {
        0: "ok", 1: "unsupported protocol", 2: "early initialization code failed",
        3: "the URL was not properly formatted", 4: "feature not supported by libcurl",
        5: "could not resolve proxy", 6: "could not resolve host", 7: "could not connect",
        8: "invalid server reply", 9: "remote access denied", 27: "out of memory",
        28: "operation timed out", 35: "SSL connect error",
    }.get(code, "")


# --------------------------------------------------------------------------
# checker
# --------------------------------------------------------------------------

FAMILIES = [
    "http_basic", "misc", "oob", "multi", "seqovl", "syndata", "fake",
    "faked", "hostfake", "fake_multi", "fake_faked", "fake_hostfake", "quic",
]


class Checker:
    def __init__(self, opts, agent):
        self.o = opts
        self.agent = agent
        self.curl = opts.curl
        self.ipv = 4
        self.ipvv = ""
        self.dom = ""
        self.host = ""
        self.testname = ""
        self.testfn = None
        self.kind = ""
        self.port = 0
        self.proto = "tcp"
        self.ips = []
        self.strategy = None
        self.need = {}
        self.report = []
        self.successes = {}     # (testname, ipv, desc) -> set(domain)
        self.domains_count = 1
        self.tlsmax12 = []
        self.tlsmax13 = []
        self.tls13_ok = False
        self.http3_ok = False
        self.hdr_seq = 0

        e = os.environ

        self.FOOLINGS46_TCP = (e.get("FOOLINGS46_TCP") or
                               "tcp_md5 badsum tcp_seq=-3000 tcp_seq=1000000 "
                               "tcp_ack=-66000:tcp_ts_up tcp_ts=-1000 "
                               "tcp_flags_unset=ACK tcp_flags_set=SYN").split()
        self.FOOLINGS6_TCP = (e.get("FOOLINGS6_TCP") or
                              "ip6_hopbyhop ip6_hopbyhop:ip6_hopbyhop2 ip6_destopt "
                              "ip6_routing ip6_ah").split()
        self.FOOLINGS_TCP = list(self.FOOLINGS46_TCP)
        if self.ipv == 6:
            self.FOOLINGS_TCP += self.FOOLINGS6_TCP
        self.FOOLINGS6_UDP = (e.get("FOOLINGS6_UDP") or "").split() or self.FOOLINGS6_TCP
        self.FOOLINGS_UDP = (e.get("FOOLINGS_UDP") or "badsum").split()
        if self.ipv == 6:
            self.FOOLINGS_UDP += self.FOOLINGS6_UDP

        self.FAKE_REPEATS = int(e.get("FAKE_REPEATS") or 1)
        self.MIN_TTL = int(e.get("MIN_TTL") or 1)
        self.MAX_TTL = int(e.get("MAX_TTL") or 12)
        self.MIN_AUTOTTL_DELTA = int(e.get("MIN_AUTOTTL_DELTA") or 1)
        self.MAX_AUTOTTL_DELTA = int(e.get("MAX_AUTOTTL_DELTA") or 5)
        self.MULTIDISORDER = e.get("MULTIDISORDER") or "multidisorder"
        self.TCP_MD5 = e.get("TCP_MD5") or "tcp_md5"

        self.FAKE_HTTP = e.get("FAKE_HTTP") or ""
        self.FAKE_HTTPS = e.get("FAKE_HTTPS") or ""
        self.FAKE_QUIC = e.get("FAKE_QUIC") or ""
        self.FAKED_PATTERN_HTTP = e.get("FAKED_PATTERN_HTTP") or ""
        self.FAKED_PATTERN_HTTPS = e.get("FAKED_PATTERN_HTTPS") or ""
        self.HOSTFAKE = e.get("HOSTFAKE") or ""
        self.SEQOVL_PATTERN_HTTP = e.get("SEQOVL_PATTERN_HTTP") or ""
        self.SEQOVL_PATTERN_HTTPS = e.get("SEQOVL_PATTERN_HTTPS") or ""

        self.PKTWS_EXTRA_PRE = e.get("PKTWS_EXTRA_PRE") or ""
        self.PKTWS_EXTRA_POST = e.get("PKTWS_EXTRA_POST") or ""

        self.fake_http = "fake_http" if self.FAKE_HTTP else "fake_default_http"
        self.fake_tls = "fake_tls" if self.FAKE_HTTPS else "fake_default_tls"
        self.fake_quic = "fake_quic" if self.FAKE_QUIC else "fake_default_quic"

    # -- external utilities -------------------------------------------------

    def detect_curl(self):
        cmd = [self.curl, "--version"]
        try:
            p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError as e:
            raise SystemExit("curl not available: %s" % e)
        ver = p.stdout.decode("utf-8", "replace")
        self.curl_version = ver.strip()

        # --connect-to since 7.49
        if not self._curl_ok(["--connect-to=" + CT_EMPTY + LOOP4 + ":65535",
                              "-o", os.devnull,
                              "--max-time", "1", "http://" + LOOP4 + ":65535"]):
            raise SystemExit("installed curl does not support --connect-to; need >= 7.49")

        has_tlsmax = any(x in ver for x in
                         ("OpenSSL", "LibreSSL", "BoringSSL", "GnuTLS", "quictls"))
        if has_tlsmax and self._curl_rc(["--tls-max", "1.2", "-s", "-o", os.devnull,
                                         "--max-time", "1",
                                         "http://" + LOOP4 + ":65535"]) != 2:
            self.tlsmax12 = ["--tls-max", "1.2"]
            self.tlsmax13 = ["--tls-max", "1.3"]

        # tls1.3: option present + library actually supports it
        rc = self._curl_rc(["--tlsv1.3", "-s", "-o", os.devnull, "--max-time", "1",
                            "http://" + LOOP4 + ":65535"])
        if rc != 2:
            rc = self._curl_rc(["--tlsv1.3", "--max-time", "1", "-s", "-I",
                                "-o", os.devnull, "https://iana.org"])
            self.tls13_ok = rc not in (4, 35)

        rc = self._curl_rc(["--connect-to=" + CT_EMPTY + LOOP4 + ":65535",
                            "-s", "-o", os.devnull,
                            "--max-time", "1", "--http3-only",
                            "http://" + LOOP4 + ":65535"])
        self.http3_ok = rc != 2

    def _curl_rc(self, args):
        try:
            return subprocess.run([self.curl] + args, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL).returncode
        except OSError:
            return 127

    def _curl_ok(self, args):
        return self._curl_rc(args) != 2

    # -- blob rewriting -----------------------------------------------------

    def rewrite_blobs(self, args):
        out = []
        for a in args:
            if "@" in a and not a.startswith("@") and "://" not in a:
                head, _, path = a.rpartition("@")
                if os.path.isfile(path):
                    try:
                        remote = self.agent.upload(path)
                        a = head + "@" + remote
                    except AgentError as e:
                        print("blob upload failed: %s" % e)
            out.append(a)
        return out

    # -- firewall prep ------------------------------------------------------

    def resolve_all(self, name):
        host = split_uri(name)[0]
        try:
            fam = socket.AF_INET if self.ipv == 4 else socket.AF_INET6
        except AttributeError:
            fam = socket.AF_INET
        try:
            infos = socket.getaddrinfo(host, None, fam, socket.SOCK_STREAM)
        except OSError:
            return []
        seen = []
        for info in infos:
            ip = info[4][0]
            if ip not in seen:
                seen.append(ip)
        return seen

    def random_ip(self):
        return random.choice(self.ips) if self.ips else None

    # -- curl probes --------------------------------------------------------

    def _curl_base(self, ip, port):
        ct = CT_EMPTY + bracket(ip)
        if port:
            ct += ":%d" % port
        return ["-sS", "-A", self.o.user_agent, "--max-time", str(self.o.max_time),
                "--connect-to=" + ct]

    def _run_curl(self, args):
        env = dict(os.environ)
        env.pop("ALL_PROXY", None)
        env.pop("all_proxy", None)
        t0 = time.time()
        try:
            p = subprocess.run([self.curl] + args, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, env=env)
        except OSError:
            return 127, ""
        out = p.stdout.decode("utf-8", "replace")
        if self.o.pace > 0:
            took = int((time.time() - t0) * 1000)
            if self.o.pace > took:
                time.sleep((self.o.pace - took) / 1000.0)
        return p.returncode, out

    def test_http(self, ip=None, detail=False):
        ip = ip or self.random_ip()
        if not ip:
            return 6, ""
        hdr = tempfile.mktemp(prefix="zapret2-hdr-", suffix=".txt")
        args = self._curl_base(ip, self.o.http_port)
        if self.o.curl_verbose:
            args.append("-v")
        args += ["-D", hdr, "http://" + self.dom]
        args += ["-o", os.devnull]
        rc, out = self._run_curl(args)
        if rc != 0:
            try:
                os.unlink(hdr)
            except OSError:
                pass
            return rc, out
        try:
            with open(hdr, "r", errors="replace") as f:
                lines = f.read().splitlines()
        finally:
            try:
                os.unlink(hdr)
            except OSError:
                pass
        code = 0
        first = lines[0] if lines else ""
        m = re.match(r"^HTTP/1\.[01] ([0-9]+)", first)
        if m:
            code = int(m.group(1))
        if detail:
            text = "\n".join(lines[:1] + [l for l in lines if l.lower().startswith("location:")])
            return 0, text
        if code in (301, 302, 307, 308):
            loc = ""
            for l in lines:
                if l.lower().startswith("location:"):
                    loc = l.split(":", 1)[1].strip()
                    break
            dom = self.host
            if loc and not (tolower(loc).startswith("http://") or
                            tolower(loc).startswith("https://")):
                pass
            elif loc and not re.search(r"^https?://.*" + re.escape(dom) + r"(/|$)",
                                       tolower(loc)):
                return 254, "suspicious redirection %d to : %s" % (code, loc)
        if code == 400:
            return 254, "http code 400. likely the server receives fakes."
        return 0, out

    def test_https_tls12(self, ip=None, detail=False):
        ip = ip or self.random_ip()
        if not ip:
            return 6, ""
        args = self._curl_base(ip, self.o.https_port)
        if self.o.curl_verbose:
            args.append("-v")
        args += ["-Ss", "-I", "--tlsv1.2"] + self.tlsmax12
        args += ["https://" + self.dom, "-o", os.devnull]
        return self._run_curl(args)

    def test_https_tls13(self, ip=None, detail=False):
        ip = ip or self.random_ip()
        if not ip:
            return 6, ""
        args = self._curl_base(ip, self.o.https_port)
        if self.o.curl_verbose:
            args.append("-v")
        args += ["-Ss", "-I", "--tlsv1.3"] + self.tlsmax13
        args += ["https://" + self.dom, "-o", os.devnull]
        return self._run_curl(args)

    def test_http3(self, ip=None, detail=False):
        ip = ip or self.random_ip()
        if not ip:
            return 6, ""
        args = self._curl_base(ip, self.o.quic_port)
        args += ["--max-time", str(self.o.max_time_quic)]
        if self.o.curl_verbose:
            args.append("-v")
        args += ["-Ss", "-I", "--http3-only", "https://" + self.dom, "-o", os.devnull]
        return self._run_curl(args)

    def choose_testfn(self, kind):
        return {
            "http": self.test_http,
            "tls12": self.test_https_tls12,
            "tls13": self.test_https_tls13,
            "http3": self.test_http3,
        }[kind]

    # -- repeat / result handling ------------------------------------------

    def run_repeats(self, testfn, testname, detail=False):
        repeats = self.o.repeats
        parallel = self.o.parallel

        def one(_i):
            return testfn(detail=detail)

        if parallel and repeats > 1:
            results = [None] * repeats
            with ThreadPoolExecutor(max_workers=repeats) as ex:
                futs = [ex.submit(one, i) for i in range(repeats)]
                for i, f in enumerate(futs):
                    results[i] = f.result()
            code = 0
            for n, (rc, out) in enumerate(results, 1):
                if repeats > 1:
                    print("[attempt %d] " % n, end="")
                if rc == 0:
                    if repeats > 1:
                        print("AVAILABLE")
                else:
                    code = rc
                    if out.strip():
                        print(out.rstrip())
            if code == 0:
                print("!!!!! AVAILABLE !!!!!")
                return True, 0
            print("UNAVAILABLE code=%d" % code)
            return False, code

        code = 0
        for n in range(1, repeats + 1):
            if repeats > 1:
                print("[attempt %d] " % n, end="")
            rc, out = testfn(detail=detail)
            if rc == 0:
                if repeats > 1:
                    print("AVAILABLE")
                print("!!!!! AVAILABLE !!!!!")
                return True, 0
            code = rc
            if out.strip():
                print(out.rstrip())
            if self.o.scanlevel in ("quick", "veryquick"):
                break
        if code == 254:
            print("UNAVAILABLE")
        elif code == 0:
            print("!!!!! AVAILABLE !!!!!")
        else:
            print("UNAVAILABLE code=%d" % code)
        return False, code

    def describe(self, args):
        return " ".join(args)

    def t(self, args):
        args = [str(a) for a in args]
        pre = self.PKTWS_EXTRA_PRE.split() if self.PKTWS_EXTRA_PRE else []
        post = self.PKTWS_EXTRA_POST.split() if self.PKTWS_EXTRA_POST else []
        full = pre + args + post
        full = self.rewrite_blobs(full)
        desc = self.describe(full)
        print("- %s ipv%d %s : nfqws2 %s" % (self.testname, self.ipv, self.dom, desc))

        if self.o.simulate:
            ok = random.randrange(0, 100) < self.o.sim_success_rate
            print("SUCCESS" if ok else "FAILED")
        else:
            try:
                self.agent.start(full)
            except AgentError as e:
                print("agent start failed: %s" % e)
                return False
            try:
                ok, _ = self.run_repeats(self.testfn, self.testname)
            finally:
                self.agent.stop()

        if ok:
            self.strategy = full
            self.report.append("%s %s ipv%d : nfqws2 %s" %
                               (self.dom, self.testname, self.ipv, desc))
            key = (self.testname, self.ipv, desc)
            self.successes.setdefault(key, set()).add(self.dom)
            return True
        return False

    # ------------------------------------------------------------------
    # strategy families (ported from blockcheck2.d/standard)
    # ------------------------------------------------------------------

    # 10-http-basic
    def fam_http_basic_http(self):
        if os.environ.get("NOTEST_BASIC_HTTP") == "1":
            print("SKIPPED")
            return
        for s in ("http_hostcase", "http_hostcase:spell=hoSt", "http_domcase",
                  "http_methodeol", "http_unixeol"):
            self.t(["--payload=http_req", "--lua-desync=" + s])

    # 15-misc
    def fam_misc_http(self):
        if os.environ.get("NOTEST_MISC_HTTP") == "1":
            print("SKIPPED")
            return
        payload = "--payload=http_req"
        for repeats in (1, 20, 100, 260):
            ok = False
            if self.t([payload, "--lua-desync=tcpseg:pos=0,method+2:ip_id=rnd:repeats=%d" % repeats]):
                ok = True
            if self.t([payload, "--lua-desync=tcpseg:pos=0,midsld:ip_id=rnd:repeats=%d" % repeats]):
                ok = True
            if ok and self.o.scanlevel != "force":
                break

    def fam_misc_tls12(self):
        if os.environ.get("NOTEST_MISC_HTTPS") == "1":
            print("SKIPPED")
            return
        payload = "--payload=tls_client_hello"
        for repeats in (1, 20, 100, 260):
            ok = False
            if self.t([payload, "--lua-desync=tcpseg:pos=0,1:ip_id=rnd:repeats=%d" % repeats]):
                ok = True
            if self.t([payload, "--lua-desync=tcpseg:pos=0,midsld:ip_id=rnd:repeats=%d" % repeats]):
                ok = True
            if ok and self.o.scanlevel != "force":
                break

    def fam_misc_tls13(self):
        self.fam_misc_tls12()

    # 17-oob
    def _oob(self):
        for urp in ("b", "0", "2", "midsld"):
            self.t(["--in-range=-s1", "--lua-desync=oob:urp=" + urp])

    def fam_oob_http(self):
        if os.environ.get("NOTEST_OOB_HTTP") == "1":
            print("SKIPPED")
            return
        self._oob()

    def fam_oob_tls12(self):
        if os.environ.get("NOTEST_OOB_HTTPS") == "1":
            print("SKIPPED")
            return
        self._oob()

    def fam_oob_tls13(self):
        self.fam_oob_tls12()

    # 20-multi
    def _simple_split_tests(self, splits, pre):
        ok_any = False
        for splitf in ("multisplit", "multidisorder"):
            func = self.MULTIDISORDER if splitf == "multidisorder" else splitf
            self.need[splitf] = False
            ok = False
            for pos in splits:
                if self.t(list(pre) + ["--payload=" + self.payload,
                                       "--lua-desync=%s:pos=%s" % (func, pos)]):
                    ok = True
            if not (ok and self.o.scanlevel != "force"):
                self.need[splitf] = True
            if ok:
                ok_any = True
        return ok_any

    HTTP_SPLITS = "method+2 midsld method+2,midsld".split()
    TLS_SPLITS = ("2 1 sniext+1 sniext+4 host+1 midsld 1,midsld 1,midsld,1220 "
                  "1,sniext+1,host+1,midsld-2,midsld,midsld+2,endhost-1").split()

    def fam_multi_http(self):
        if os.environ.get("NOTEST_MULTI_HTTP") == "1":
            print("SKIPPED")
            return
        self._simple_split_tests(self.HTTP_SPLITS, [])

    def fam_multi_tls12(self):
        if os.environ.get("NOTEST_MULTI_HTTPS") == "1":
            print("SKIPPED")
            return
        if self._simple_split_tests(self.TLS_SPLITS, []) and self.o.scanlevel != "force":
            return
        save = dict(self.need)
        self._simple_split_tests(self.TLS_SPLITS,
                                 ["--lua-desync=wssize:wsize=1:scale=6"])
        self.need = save

    def fam_multi_tls13(self):
        if os.environ.get("NOTEST_MULTI_HTTPS") == "1":
            print("SKIPPED")
            return
        self._simple_split_tests(self.TLS_SPLITS, [])

    # 23-seqovl
    def _seqovl_http(self):
        payload = "--payload=http_req"
        pat = "seqovl_pat" if self.SEQOVL_PATTERN_HTTP else ""
        blob = (["--blob=seqovl_pat:@" + self.SEQOVL_PATTERN_HTTP]
                if self.SEQOVL_PATTERN_HTTP else [])
        extra = ("--lua-desync=tcpseg:pos=0,-1:seqovl=#%s:seqovl_pattern=%s" % (pat, pat)
                 if pat else None)

        self.t([payload, "--lua-desync=tcpseg:pos=0,-1:seqovl=1", "--lua-desync=drop"])
        if extra:
            self.t(blob + [payload, extra, "--lua-desync=drop"])

        ok = False
        for split in ("method+2", "method+2,midsld"):
            if self.t([payload, "--lua-desync=multisplit:pos=%s:seqovl=1" % split]):
                ok = True
            if extra and self.t(blob + [payload,
                    "--lua-desync=multisplit:pos=%s:seqovl=#%s:seqovl_pattern=%s"
                    % (split, pat, pat)]):
                ok = True
            if ok and self.o.scanlevel != "force":
                break
        for f, f2 in (("method+1", "method+2"), ("midsld-1", "midsld"),
                      ("method+1", "method+2,midsld")):
            self.t([payload, "--lua-desync=%s:pos=%s:seqovl=%s"
                    % (self.MULTIDISORDER, f2, f)])
            if extra:
                self.t(blob + [payload,
                        "--lua-desync=%s:pos=%s:seqovl=%s:seqovl_pattern=%s"
                        % (self.MULTIDISORDER, f2, f, pat)])

    def fam_seqovl_http(self):
        if os.environ.get("NOTEST_SEQOVL_HTTP") == "1":
            print("SKIPPED")
            return
        self._seqovl_http()

    def _seqovl_tls(self, pre):
        payload = "--payload=tls_client_hello"
        pat = "seqovl_pat" if self.SEQOVL_PATTERN_HTTPS else "fake_default_tls"
        blob = (["--blob=seqovl_pat:@" + self.SEQOVL_PATTERN_HTTPS]
                if self.SEQOVL_PATTERN_HTTPS else [])
        rnd_mod = ["--lua-init=%s=tls_mod(%s,'rnd')" % (pat, pat)]
        padencap_mod = ["--lua-desync=luaexec:code=desync.patmod="
                        "tls_mod(%s,'rnd,dupsid,padencap',desync.reasm_data)" % pat]

        ok = False
        if self.t(list(pre) + [payload, "--lua-desync=tcpseg:pos=0,-1:seqovl=1",
                               "--lua-desync=drop"]):
            ok = True
        if self.t(blob + rnd_mod + list(pre) + [payload,
                "--lua-desync=tcpseg:pos=0,-1:seqovl=#%s:seqovl_pattern=%s" % (pat, pat),
                "--lua-desync=drop"]):
            ok = True
        if self.t(blob + list(pre) + [payload] + padencap_mod + [
                "--lua-desync=tcpseg:pos=0,-1:seqovl=#patmod:seqovl_pattern=patmod",
                "--lua-desync=drop"]):
            ok = True
        ok_any = ok

        ok = False
        for split in ("10", "10,sniext+1", "10,sniext+4", "10,midsld"):
            if self.t(list(pre) + [payload,
                    "--lua-desync=multisplit:pos=%s:seqovl=1" % split]):
                ok = True
            if self.t(blob + rnd_mod + list(pre) + [payload,
                    "--lua-desync=multisplit:pos=%s:seqovl=#%s:seqovl_pattern=%s"
                    % (split, pat, pat)]):
                ok = True
            if self.t(blob + list(pre) + [payload] + padencap_mod + [
                    "--lua-desync=multisplit:pos=%s:seqovl=#patmod:seqovl_pattern=patmod"
                    % split]):
                ok = True
            if ok and self.o.scanlevel != "force":
                break
        for f, f2 in (("1", "2"), ("sniext", "sniext+1"),
                      ("sniext+3", "sniext+4"), ("midsld-1", "midsld"),
                      ("1", "2,midsld")):
            if self.t(list(pre) + [payload,
                    "--lua-desync=%s:pos=%s:seqovl=%s"
                    % (self.MULTIDISORDER, f2, f)]):
                ok = True
            if self.t(blob + rnd_mod + list(pre) + [payload,
                    "--lua-desync=%s:pos=%s:seqovl=%s:seqovl_pattern=%s"
                    % (self.MULTIDISORDER, f2, f, pat)]):
                ok = True
        if ok:
            ok_any = True
        return ok_any

    def fam_seqovl_tls12(self):
        if os.environ.get("NOTEST_SEQOVL_HTTPS") == "1":
            print("SKIPPED")
            return
        if self._seqovl_tls([]) and self.o.scanlevel != "force":
            return
        self._seqovl_tls(["--lua-desync=wssize:wsize=1:scale=6"])

    def fam_seqovl_tls13(self):
        if os.environ.get("NOTEST_SEQOVL_HTTPS") == "1":
            print("SKIPPED")
            return
        self._seqovl_tls([])

    # 24-syndata
    def fam_syndata_http(self):
        if os.environ.get("NOTEST_SYNDATA_HTTP") == "1":
            print("SKIPPED")
            return
        payload = "--payload=http_req"
        for split in ("", "multisplit", self.MULTIDISORDER):
            tail = [payload, "--lua-desync=" + split] if split else []
            self.t(["--lua-desync=syndata"] + tail)
            self.t(["--lua-desync=syndata:blob=fake_default_http"] + tail)

    def _syndata_tls(self, pre):
        payload = "--payload=tls_client_hello"
        ok = False
        for split in ("", "multisplit", self.MULTIDISORDER):
            tail = [payload, "--lua-desync=" + split] if split else []
            for desync in (
                "--lua-desync=syndata",
                "--lua-desync=syndata:blob=0x1603",
                "--lua-desync=syndata:blob=fake_default_tls:tls_mod=rnd,dupsid,rndsni",
                "--lua-desync=syndata:blob=fake_default_tls:tls_mod=rnd,dupsid,sni=google.com",
            ):
                if self.t(list(pre) + [desync] + tail):
                    ok = True
        return ok

    def fam_syndata_tls12(self):
        if os.environ.get("NOTEST_SYNDATA_HTTPS") == "1":
            print("SKIPPED")
            return
        if self._syndata_tls([]) and self.o.scanlevel != "force":
            return
        self._syndata_tls(["--lua-desync=wssize:wsize=1:scale=6"])

    def fam_syndata_tls13(self):
        if os.environ.get("NOTEST_SYNDATA_HTTPS") == "1":
            print("SKIPPED")
            return
        self._syndata_tls([])

    # helpers shared by the fake families
    def _ttls(self):
        return list(range(self.MIN_TTL, self.MAX_TTL + 1)) if self.MAX_TTL else []

    def _attls(self):
        if not self.MAX_AUTOTTL_DELTA:
            return []
        return list(range(self.MIN_AUTOTTL_DELTA, self.MAX_AUTOTTL_DELTA + 1))

    def _fake_blob(self, kind):
        if kind == "http":
            return (["--blob=%s:@" % self.fake_http + self.FAKE_HTTP]
                    if self.FAKE_HTTP else [])
        if kind == "tls":
            return (["--blob=%s:@" % self.fake_tls + self.FAKE_HTTPS]
                    if self.FAKE_HTTPS else [])
        return (["--blob=%s:@" % self.fake_quic + self.FAKE_QUIC]
                if self.FAKE_QUIC else [])

    # 25-fake
    def fam_fake_http(self):
        if os.environ.get("NOTEST_FAKE_HTTP") == "1":
            print("SKIPPED")
            return
        payload = "--payload=http_req"
        fake = self.fake_http
        blob = self._fake_blob("http")
        attls = self._attls()
        self.need["fake"] = False
        ok_any = False
        ok = False
        for ttl in self._ttls():
            for ff in (fake, "0x00000000"):
                for f in ([], ["--payload=empty", "--out-range=s1<d1",
                               "--lua-desync=pktmod:ip%s_ttl=1" % self.ipvv]):
                    if self.t(blob + [payload,
                            "--lua-desync=fake:blob=%s:ip%s_ttl=%d:repeats=%d"
                            % (ff, self.ipvv, ttl, self.FAKE_REPEATS)] + f):
                        ok = True
                        if self.o.scanlevel != "force":
                            break
            if ok:
                break
        for fooling in self.FOOLINGS_TCP:
            for ff in (fake, "0x00000000"):
                if self.t(blob + [payload,
                        "--lua-desync=fake:blob=%s:%s:repeats=%d"
                        % (ff, fooling, self.FAKE_REPEATS)]):
                    ok = True
                if contains(fooling, "tcp_md5") and self.t(blob + [payload,
                        "--lua-desync=fake:blob=%s:%s:repeats=%d"
                        % (ff, fooling, self.FAKE_REPEATS),
                        "--payload=empty", "--out-range=<s1",
                        "--lua-desync=send:" + self.TCP_MD5]):
                    ok = True
            if self.o.scanlevel == "veryquick" and ok:
                break
        for ttl in attls:
            for ff in (fake, "0x00000000"):
                for f in ([], ["--payload=empty", "--out-range=s1<d1",
                               "--lua-desync=pktmod:ip%s_ttl=1" % self.ipvv]):
                    if self.t(blob + [payload,
                            "--lua-desync=fake:blob=%s:ip%s_autottl=-%d,3-20:repeats=%d"
                            % (ff, self.ipvv, ttl, self.FAKE_REPEATS)] + f):
                        ok = True
                        if self.o.scanlevel != "force":
                            break
            if self.o.scanlevel == "veryquick" and ok:
                break
        if not ok and self.o.scanlevel != "force":
            self.need["fake"] = True
        if ok:
            ok_any = True
        return ok_any

    def _fake_https_vary_(self, fooling, pre, post):
        payload = "--payload=tls_client_hello"
        fake = self.fake_tls
        blob = self._fake_blob("tls")
        pre = list(pre)
        post = list(post)
        ok_any = False
        base = blob + pre

        if self.t(base + [payload,
                "--lua-desync=fake:blob=%s:%s:repeats=%d"
                % (fake, fooling, self.FAKE_REPEATS)] + post):
            ok_any = True
        if ok_any and self.o.scanlevel == "veryquick":
            return True
        if self.t(base + [payload,
                "--lua-desync=fake:blob=0x00000000:%s:repeats=%d"
                % (fooling, self.FAKE_REPEATS)] + post):
            ok_any = True
        if ok_any and self.o.scanlevel == "veryquick":
            return True
        if self.t(base + [payload,
                "--lua-desync=fake:blob=0x00000000:%s:repeats=%d"
                % (fooling, self.FAKE_REPEATS),
                "--lua-desync=fake:blob=%s:%s:tls_mod=rnd,dupsid:repeats=%d"
                % (fake, fooling, self.FAKE_REPEATS)] + post):
            ok_any = True
        if ok_any and self.o.scanlevel == "veryquick":
            return True
        if self.t(base + [payload,
                "--lua-desync=multisplit:blob=%s:%s:pos=2:nodrop:repeats=%d"
                % (fake, fooling, self.FAKE_REPEATS)] + post):
            ok_any = True
        if ok_any and self.o.scanlevel == "veryquick":
            return True
        if self.t(base + [payload,
                "--lua-desync=fake:blob=%s:%s:tls_mod=rnd,dupsid,padencap:repeats=%d"
                % (fake, fooling, self.FAKE_REPEATS)] + post):
            ok_any = True
        return ok_any

    def _fake_https_vary(self, fooling, pre, post):
        ok_any = False
        if self._fake_https_vary_(fooling, pre, post):
            ok_any = True
        if contains(fooling, "tcp_md5"):
            md5post = list(post) + ["--payload=empty", "--out-range=<s1",
                                    "--lua-desync=send:" + self.TCP_MD5]
            if self._fake_https_vary_(fooling, pre, md5post):
                ok_any = True
        return ok_any

    def _fake_https_tls(self, pre):
        pre = list(pre)
        attls = self._attls()
        self.need["fake"] = False
        ok_any = False
        ok = False
        for ttl in self._ttls():
            for f in ([], ["--payload=empty", "--out-range=s1<d1",
                           "--lua-desync=pktmod:ip%s_ttl=1" % self.ipvv]):
                if self._fake_https_vary("ip%s_ttl=%d" % (self.ipvv, ttl), pre, f):
                    ok = True
                    if self.o.scanlevel != "force":
                        break
            if ok or self.o.scanlevel == "veryquick":
                break
        for fooling in self.FOOLINGS_TCP:
            if self._fake_https_vary(fooling, pre, []):
                ok = True
            if self.o.scanlevel == "veryquick" and ok:
                break
        for ttl in attls:
            for f in ([], ["--payload=empty", "--out-range=s1<d1",
                           "--lua-desync=pktmod:ip%s_ttl=1" % self.ipvv]):
                if self._fake_https_vary("ip%s_autottl=-%d,3-20" % (self.ipvv, ttl),
                                         pre, f):
                    ok = True
                    if self.o.scanlevel != "force":
                        break
            if self.o.scanlevel == "veryquick" and ok:
                break
        if not ok and self.o.scanlevel != "force":
            self.need["fake"] = True
        if ok:
            ok_any = True
        return ok_any

    def fam_fake_tls12(self):
        if os.environ.get("NOTEST_FAKE_HTTPS") == "1":
            print("SKIPPED")
            return
        if self._fake_https_tls([]) and self.o.scanlevel != "force":
            return
        save = self.need.get("fake")
        self._fake_https_tls(["--lua-desync=wssize:wsize=1:scale=6"])
        self.need["fake"] = save

    def fam_fake_tls13(self):
        if os.environ.get("NOTEST_FAKE_HTTPS") == "1":
            print("SKIPPED")
            return
        self._fake_https_tls([])

    # 30-faked
    def _check_faked(self, payload, splits, pattern, pre, kind):
        if pattern:
            blob = ["--blob=faked_pat:@" + pattern]
            patref = "pattern=faked_pat:"
        else:
            blob = []
            patref = ""
        attls = self._attls()
        splitfs = []
        if self.need.get("multisplit", None) != 0 or self.o.scanlevel == "force":
            splitfs.append("fakedsplit")
        if self.need.get("multidisorder", None) != 0 or self.o.scanlevel == "force":
            splitfs.append("fakeddisorder")
        ok_any = False
        for splitf in splitfs:
            ok = False
            for ttl in self._ttls():
                for split in splits:
                    for f in ([], ["--payload=empty", "--out-range=s1<d1",
                                   "--lua-desync=pktmod:ip%s_ttl=1" % self.ipvv]):
                        if self.t(blob + list(pre) + [payload,
                                "--lua-desync=%s:%spos=%s:ip%s_ttl=%d:repeats=%d"
                                % (splitf, patref, split, self.ipvv, ttl,
                                   self.FAKE_REPEATS)] + f):
                            ok = True
                            if self.o.scanlevel != "force":
                                break
                    if self.o.scanlevel == "veryquick" and ok:
                        break
                if ok:
                    break
            for fooling in self.FOOLINGS_TCP:
                for split in splits:
                    if self.t(blob + list(pre) + [payload,
                            "--lua-desync=%s:%spos=%s:%s"
                            % (splitf, patref, split, fooling)]):
                        ok = True
                    if contains(fooling, "tcp_md5") and self.t(blob + list(pre) + [payload,
                            "--lua-desync=%s:%spos=%s:%s:repeats=%d"
                            % (splitf, patref, split, fooling, self.FAKE_REPEATS),
                            "--payload=empty", "--out-range=<s1",
                            "--lua-desync=send:" + self.TCP_MD5]):
                        ok = True
                    if self.o.scanlevel == "veryquick" and ok:
                        break
                if self.o.scanlevel == "veryquick" and ok:
                    break
            for ttl in attls:
                for split in splits:
                    for f in ([], ["--payload=empty", "--out-range=s1<d1",
                                   "--lua-desync=pktmod:ip%s_ttl=1" % self.ipvv]):
                        if self.t(blob + list(pre) + [payload,
                                "--lua-desync=%s:%spos=%s:ip%s_autottl=-%d,3-20:repeats=%d"
                                % (splitf, patref, split, self.ipvv, ttl,
                                   self.FAKE_REPEATS)] + f):
                            ok = True
                            if self.o.scanlevel != "force":
                                break
                    if self.o.scanlevel == "veryquick" and ok:
                        break
                if self.o.scanlevel == "veryquick" and ok:
                    break
            if not ok and self.o.scanlevel != "force":
                self.need[splitf] = True
            if ok:
                ok_any = True
            if self.o.scanlevel == "veryquick" and ok_any:
                break
        return ok_any

    def fam_faked_http(self):
        if os.environ.get("NOTEST_FAKED_HTTP") == "1":
            print("SKIPPED")
            return
        self._check_faked("--payload=http_req", self.HTTP_SPLITS,
                          self.FAKED_PATTERN_HTTP, [], "http")

    def fam_faked_tls12(self):
        if os.environ.get("NOTEST_FAKED_HTTPS") == "1":
            print("SKIPPED")
            return
        if self._check_faked("--payload=tls_client_hello", self.TLS_SPLITS,
                             self.FAKED_PATTERN_HTTPS, [], "tls") \
                and self.o.scanlevel != "force":
            return
        save = (self.need.get("fakedsplit"), self.need.get("fakeddisorder"))
        self._check_faked("--payload=tls_client_hello", self.TLS_SPLITS,
                          self.FAKED_PATTERN_HTTPS,
                          ["--lua-desync=wssize:wsize=1:scale=6"], "tls")
        self.need["fakedsplit"], self.need["fakeddisorder"] = save

    def fam_faked_tls13(self):
        if os.environ.get("NOTEST_FAKED_HTTPS") == "1":
            print("SKIPPED")
            return
        self._check_faked("--payload=tls_client_hello", self.TLS_SPLITS,
                          self.FAKED_PATTERN_HTTPS, [], "tls")

    # 35-hostfake
    def _hostfake_vary_(self, fooling, pre, post):
        payload = "--payload=" + self.payload
        hostopt = ("host=%s:" % self.HOSTFAKE) if self.HOSTFAKE else ""
        variants = [
            "",
            "nofake1:",
            "nofake2:",
            "midhost=midsld:",
            "nofake1:midhost=midsld:",
            "nofake2:midhost=midsld:",
        ]
        ok_any = False
        for disorder in ("", "disorder_after:"):
            for v in variants:
                if self.t(list(pre) + [payload,
                        "--lua-desync=hostfakesplit:%s%s%s%s:repeats=%d"
                        % (hostopt, disorder, v, fooling, self.FAKE_REPEATS)] + list(post)):
                    ok_any = True
                    if self.o.scanlevel == "veryquick":
                        return True
        return ok_any

    def _hostfake_vary(self, fooling, pre, post):
        ok = self._hostfake_vary_(fooling, pre, post)
        if contains(fooling, "tcp_md5"):
            md5post = list(post) + ["--payload=empty", "--out-range=<s1",
                                    "--lua-desync=send:" + self.TCP_MD5]
            if self._hostfake_vary_(fooling, pre, md5post):
                ok = True
        return ok

    def _check_hostfake(self, pre):
        if self.need.get("hostfakesplit", None) == 0:
            return False
        pre = list(pre)
        self.need["hostfakesplit"] = False
        ok = False
        for ttl in self._ttls():
            for f in ([], ["--payload=empty", "--out-range=s1<d1",
                           "--lua-desync=pktmod:ip%s_ttl=1" % self.ipvv]):
                if self._hostfake_vary("ip%s_ttl=%d" % (self.ipvv, ttl), pre, f):
                    ok = True
                    if self.o.scanlevel != "force":
                        break
            if ok:
                break
        for fooling in self.FOOLINGS_TCP:
            if self._hostfake_vary(fooling, pre, []):
                ok = True
            if self.o.scanlevel == "veryquick" and ok:
                break
        for ttl in self._attls():
            for f in ([], ["--payload=empty", "--out-range=s1<d1",
                           "--lua-desync=pktmod:ip%s_ttl=1" % self.ipvv]):
                if self._hostfake_vary("ip%s_autottl=-%d,3-20" % (self.ipvv, ttl), pre, f):
                    ok = True
                    if self.o.scanlevel != "force":
                        break
            if self.o.scanlevel == "veryquick" and ok:
                break
        if not ok and self.o.scanlevel != "force":
            self.need["hostfakesplit"] = True
        return ok

    def fam_hostfake_http(self):
        if os.environ.get("NOTEST_HOSTFAKE_HTTP") == "1":
            print("SKIPPED")
            return
        self.payload = "http_req"
        self._check_hostfake([])

    def fam_hostfake_tls12(self):
        if os.environ.get("NOTEST_HOSTFAKE_HTTPS") == "1":
            print("SKIPPED")
            return
        self.payload = "tls_client_hello"
        if self._check_hostfake([]) and self.o.scanlevel != "force":
            return
        save = self.need.get("hostfakesplit")
        self._check_hostfake(["--lua-desync=wssize:wsize=1:scale=6"])
        self.need["hostfakesplit"] = save

    def fam_hostfake_tls13(self):
        if os.environ.get("NOTEST_HOSTFAKE_HTTPS") == "1":
            print("SKIPPED")
            return
        self.payload = "tls_client_hello"
        self._check_hostfake([])

    # 50-fake-multi
    def _fake_multi_splitfs(self):
        splitfs = []
        if self.need.get("multisplit", None) != 0 or self.o.scanlevel == "force":
            splitfs.append("multisplit")
        if self.need.get("multidisorder", None) != 0 or self.o.scanlevel == "force":
            splitfs.append(self.MULTIDISORDER)
        return splitfs

    def fam_fake_multi_http(self):
        if os.environ.get("NOTEST_FAKE_MULTI_HTTP") == "1":
            print("SKIPPED")
            return
        payload = "--payload=http_req"
        fake = self.fake_http
        blob = self._fake_blob("http")
        attls = self._attls()
        for splitf in self._fake_multi_splitfs():
            ok = False
            for ttl in self._ttls():
                for split in self.HTTP_SPLITS:
                    for ff in (fake, "0x00000000"):
                        for f in ([], ["--payload=empty", "--out-range=s1<d1",
                                       "--lua-desync=pktmod:ip%s_ttl=1" % self.ipvv]):
                            if self.t(blob + [payload,
                                    "--lua-desync=fake:blob=%s:ip%s_ttl=%d:repeats=%d"
                                    % (ff, self.ipvv, ttl, self.FAKE_REPEATS),
                                    "--lua-desync=%s:pos=%s" % (splitf, split)] + f):
                                ok = True
                                if self.o.scanlevel != "force":
                                    break
                if ok:
                    break
            for fooling in self.FOOLINGS_TCP:
                for split in self.HTTP_SPLITS:
                    for ff in (fake, "0x00000000"):
                        if self.t(blob + [payload,
                                "--lua-desync=fake:blob=%s:%s:repeats=%d"
                                % (ff, fooling, self.FAKE_REPEATS),
                                "--lua-desync=%s:pos=%s" % (splitf, split)]):
                            ok = True
                        if contains(fooling, "tcp_md5") and self.t(blob + [payload,
                                "--lua-desync=fake:blob=%s:%s:repeats=%d"
                                % (ff, fooling, self.FAKE_REPEATS),
                                "--lua-desync=%s:pos=%s" % (splitf, split),
                                "--payload=empty", "--out-range=<s1",
                                "--lua-desync=send:" + self.TCP_MD5]):
                            ok = True
            for ttl in attls:
                for split in self.HTTP_SPLITS:
                    for ff in (fake, "0x00000000"):
                        for f in ([], ["--payload=empty", "--out-range=s1<d1",
                                       "--lua-desync=pktmod:ip%s_ttl=1" % self.ipvv]):
                            if self.t(blob + [payload,
                                    "--lua-desync=fake:blob=%s:ip%s_autottl=-%d,3-20:repeats=%d"
                                    % (ff, self.ipvv, ttl, self.FAKE_REPEATS),
                                    "--lua-desync=%s:pos=%s" % (splitf, split)] + f):
                                ok = True
                                if self.o.scanlevel != "force":
                                    break

    def _fake_multi_vary_(self, splitf, split, fooling, pre, post):
        payload = "--payload=tls_client_hello"
        fake = self.fake_tls
        blob = self._fake_blob("tls")
        pre = list(pre)
        post = list(post)
        ok_any = False
        base = blob + pre

        if self.t(base + [payload,
                "--lua-desync=fake:blob=%s:%s:repeats=%d" % (fake, fooling, self.FAKE_REPEATS),
                "--lua-desync=%s:pos=%s" % (splitf, split)] + post):
            ok_any = True
        if ok_any and self.o.scanlevel == "veryquick":
            return True
        if self.t(base + [payload,
                "--lua-desync=fake:blob=0x00000000:%s:repeats=%d" % (fooling, self.FAKE_REPEATS),
                "--lua-desync=%s:pos=%s" % (splitf, split)] + post):
            ok_any = True
        if ok_any and self.o.scanlevel == "veryquick":
            return True
        if self.t(base + [payload,
                "--lua-desync=fake:blob=0x00000000:%s:repeats=%d" % (fooling, self.FAKE_REPEATS),
                "--lua-desync=fake:blob=%s:%s:tls_mod=rnd,dupsid:repeats=%d"
                % (fake, fooling, self.FAKE_REPEATS),
                "--lua-desync=%s:pos=%s" % (splitf, split)] + post):
            ok_any = True
        if ok_any and self.o.scanlevel == "veryquick":
            return True
        if self.t(base + [payload,
                "--lua-desync=multisplit:blob=%s:%s:pos=2:nodrop:repeats=%d"
                % (fake, fooling, self.FAKE_REPEATS),
                "--lua-desync=%s:pos=%s" % (splitf, split)] + post):
            ok_any = True
        if ok_any and self.o.scanlevel == "veryquick":
            return True
        if self.t(base + [payload,
                "--lua-desync=fake:blob=%s:%s:tls_mod=rnd,dupsid,padencap:repeats=%d"
                % (fake, fooling, self.FAKE_REPEATS),
                "--lua-desync=%s:pos=%s" % (splitf, split)] + post):
            ok_any = True
        return ok_any

    def _fake_multi_vary(self, splitf, split, fooling, pre, post):
        ok = self._fake_multi_vary_(splitf, split, fooling, pre, post)
        if contains(fooling, "tcp_md5"):
            md5post = list(post) + ["--payload=empty", "--out-range=<s1",
                                    "--lua-desync=send:" + self.TCP_MD5]
            if self._fake_multi_vary_(splitf, split, fooling, pre, md5post):
                ok = True
        return ok

    def _fake_multi_tls(self, pre):
        pre = list(pre)
        attls = self._attls()
        ok_any = False
        for splitf in self._fake_multi_splitfs():
            ok = False
            for ttl in self._ttls():
                for split in self.TLS_SPLITS:
                    for f in ([], ["--payload=empty", "--out-range=s1<d1",
                                   "--lua-desync=pktmod:ip%s_ttl=1" % self.ipvv]):
                        if self._fake_multi_vary(splitf, split,
                                "ip%s_ttl=%d" % (self.ipvv, ttl), pre, f):
                            ok = True
                            if self.o.scanlevel != "force":
                                break
                    if self.o.scanlevel == "veryquick" and ok:
                        break
                if ok or self.o.scanlevel == "veryquick":
                    break
            for fooling in self.FOOLINGS_TCP:
                for split in self.TLS_SPLITS:
                    if self._fake_multi_vary(splitf, split, fooling, pre, []):
                        ok = True
                    if self.o.scanlevel == "veryquick" and ok:
                        break
                if self.o.scanlevel == "veryquick" and ok:
                    break
            for ttl in attls:
                for split in self.TLS_SPLITS:
                    for f in ([], ["--payload=empty", "--out-range=s1<d1",
                                   "--lua-desync=pktmod:ip%s_ttl=1" % self.ipvv]):
                        if self._fake_multi_vary(splitf, split,
                                "ip%s_autottl=-%d,3-20" % (self.ipvv, ttl), pre, f):
                            ok = True
                            if self.o.scanlevel != "force":
                                break
                    if self.o.scanlevel == "veryquick" and ok:
                        break
                if self.o.scanlevel == "veryquick" and ok:
                    break
            if ok:
                ok_any = True
            if self.o.scanlevel == "veryquick" and ok_any:
                break
        return ok_any

    def fam_fake_multi_tls12(self):
        if os.environ.get("NOTEST_FAKE_MULTI_HTTPS") == "1":
            print("SKIPPED")
            return
        if self._fake_multi_tls([]) and self.o.scanlevel != "force":
            return
        self._fake_multi_tls(["--lua-desync=wssize:wsize=1:scale=6"])

    def fam_fake_multi_tls13(self):
        if os.environ.get("NOTEST_FAKE_MULTI_HTTPS") == "1":
            print("SKIPPED")
            return
        self._fake_multi_tls([])

    # 55-fake-faked
    def _fake_faked_splitfs(self):
        splitfs = []
        if self.need.get("fakedsplit", None) != 0 or self.o.scanlevel == "force":
            splitfs.append("fakedsplit")
        if self.need.get("fakeddisorder", None) != 0 or self.o.scanlevel == "force":
            splitfs.append("fakeddisorder")
        return splitfs

    def _fake_faked_http(self):
        payload = "--payload=http_req"
        fake = self.fake_http
        fblob = self._fake_blob("http")
        pat = self.FAKED_PATTERN_HTTP
        pblob = ["--blob=faked_pat:@" + pat] if pat else []
        patref = "pattern=faked_pat:" if pat else ""
        attls = self._attls()
        for splitf in self._fake_faked_splitfs():
            ok = False
            for ttl in self._ttls():
                for split in self.HTTP_SPLITS:
                    for ff in (fake, "0x00000000"):
                        for f in ([], ["--payload=empty", "--out-range=s1<d1",
                                       "--lua-desync=pktmod:ip%s_ttl=1" % self.ipvv]):
                            if self.t(fblob + pblob + [payload,
                                    "--lua-desync=fake:blob=%s:ip%s_ttl=%d:repeats=%d"
                                    % (ff, self.ipvv, ttl, self.FAKE_REPEATS),
                                    "--lua-desync=%s:%spos=%s:ip%s_ttl=%d:repeats=%d"
                                    % (splitf, patref, split, self.ipvv, ttl,
                                       self.FAKE_REPEATS)] + f):
                                ok = True
                                if self.o.scanlevel != "force":
                                    break
                        if self.o.scanlevel == "veryquick" and ok:
                            break
                    if ok:
                        break
                if ok:
                    break
            for fooling in self.FOOLINGS_TCP:
                for split in self.HTTP_SPLITS:
                    for ff in (fake, "0x00000000"):
                        if self.t(fblob + pblob + [payload,
                                "--lua-desync=fake:blob=%s:%s:repeats=%d"
                                % (ff, fooling, self.FAKE_REPEATS),
                                "--lua-desync=%s:%spos=%s:%s:repeats=%d"
                                % (splitf, patref, split, fooling, self.FAKE_REPEATS)]):
                            ok = True
                        if contains(fooling, "tcp_md5") and self.t(fblob + pblob + [payload,
                                "--lua-desync=fake:blob=%s:%s:repeats=%d"
                                % (ff, fooling, self.FAKE_REPEATS),
                                "--lua-desync=%s:%spos=%s:%s:repeats=%d"
                                % (splitf, patref, split, fooling, self.FAKE_REPEATS),
                                "--payload=empty", "--out-range=<s1",
                                "--lua-desync=send:" + self.TCP_MD5]):
                            ok = True
                        if self.o.scanlevel == "veryquick" and ok:
                            break
                    if self.o.scanlevel == "veryquick" and ok:
                        break
                if self.o.scanlevel == "veryquick" and ok:
                    break
            for ttl in attls:
                for split in self.HTTP_SPLITS:
                    for ff in (fake, "0x00000000"):
                        for f in ([], ["--payload=empty", "--out-range=s1<d1",
                                       "--lua-desync=pktmod:ip%s_ttl=1" % self.ipvv]):
                            if self.t(fblob + pblob + [payload,
                                    "--lua-desync=fake:blob=%s:ip%s_autottl=-%d,3-20:repeats=%d"
                                    % (ff, self.ipvv, ttl, self.FAKE_REPEATS),
                                    "--lua-desync=%s:%spos=%s:ip%s_autottl=-%d,3-20:repeats=%d"
                                    % (splitf, patref, split, self.ipvv, ttl,
                                       self.FAKE_REPEATS)] + f):
                                ok = True
                                if self.o.scanlevel != "force":
                                    break
                        if self.o.scanlevel == "veryquick" and ok:
                            break
                    if self.o.scanlevel == "veryquick" and ok:
                        break
                if self.o.scanlevel == "veryquick" and ok:
                    break
            if self.o.scanlevel == "veryquick" and ok:
                break

    def fam_fake_faked_http(self):
        if os.environ.get("NOTEST_FAKE_FAKED_HTTP") == "1":
            print("SKIPPED")
            return
        self._fake_faked_http()

    def _fake_faked_tls(self, pre):
        pre = list(pre)
        attls = self._attls()
        fake = self.fake_tls
        fblob = self._fake_blob("tls")
        pat = self.FAKED_PATTERN_HTTPS
        pblob = ["--blob=faked_pat:@" + pat] if pat else []
        patref = "pattern=faked_pat:" if pat else ""
        ok_any = False
        for splitf in self._fake_faked_splitfs():
            ok = False
            for ttl in self._ttls():
                for split in self.TLS_SPLITS:
                    for f in ([], ["--payload=empty", "--out-range=s1<d1",
                                   "--lua-desync=pktmod:ip%s_ttl=1" % self.ipvv]):
                        if self.t(fblob + pblob + pre + ["--payload=tls_client_hello",
                                "--lua-desync=fake:blob=%s:ip%s_ttl=%d:repeats=%d"
                                % (fake, self.ipvv, ttl, self.FAKE_REPEATS),
                                "--lua-desync=%s:%spos=%s:ip%s_ttl=%d:repeats=%d"
                                % (splitf, patref, split, self.ipvv, ttl,
                                   self.FAKE_REPEATS)] + f):
                            ok = True
                            if self.o.scanlevel != "force":
                                break
                    if self.o.scanlevel == "veryquick" and ok:
                        break
                if ok:
                    break
            for fooling in self.FOOLINGS_TCP:
                for split in self.TLS_SPLITS:
                    if self.t(fblob + pblob + pre + ["--payload=tls_client_hello",
                            "--lua-desync=fake:blob=%s:%s:repeats=%d"
                            % (fake, fooling, self.FAKE_REPEATS),
                            "--lua-desync=%s:%spos=%s:%s:repeats=%d"
                            % (splitf, patref, split, fooling, self.FAKE_REPEATS)]):
                        ok = True
                    if contains(fooling, "tcp_md5") and self.t(
                            fblob + pblob + pre + ["--payload=tls_client_hello",
                            "--lua-desync=fake:blob=%s:%s:repeats=%d"
                            % (fake, fooling, self.FAKE_REPEATS),
                            "--lua-desync=%s:%spos=%s:%s:repeats=%d"
                            % (splitf, patref, split, fooling, self.FAKE_REPEATS),
                            "--payload=empty", "--out-range=<s1",
                            "--lua-desync=send:" + self.TCP_MD5]):
                        ok = True
                    if self.o.scanlevel == "veryquick" and ok:
                        break
                if self.o.scanlevel == "veryquick" and ok:
                    break
            for ttl in attls:
                for split in self.TLS_SPLITS:
                    for f in ([], ["--payload=empty", "--out-range=s1<d1",
                                   "--lua-desync=pktmod:ip%s_ttl=1" % self.ipvv]):
                        if self.t(fblob + pblob + pre + ["--payload=tls_client_hello",
                                "--lua-desync=fake:blob=%s:ip%s_autottl=-%d,3-20:repeats=%d"
                                % (fake, self.ipvv, ttl, self.FAKE_REPEATS),
                                "--lua-desync=%s:%spos=%s:ip%s_autottl=-%d,3-20:repeats=%d"
                                % (splitf, patref, split, self.ipvv, ttl,
                                   self.FAKE_REPEATS)] + f):
                            ok = True
                            if self.o.scanlevel != "force":
                                break
                    if self.o.scanlevel == "veryquick" and ok:
                        break
                if self.o.scanlevel == "veryquick" and ok:
                    break
            if ok:
                ok_any = True
            if self.o.scanlevel == "veryquick" and ok_any:
                break
        return ok_any

    def fam_fake_faked_tls12(self):
        if os.environ.get("NOTEST_FAKE_FAKED_HTTPS") == "1":
            print("SKIPPED")
            return
        if self._fake_faked_tls([]) and self.o.scanlevel != "force":
            return
        self._fake_faked_tls(["--lua-desync=wssize:wsize=1:scale=6"])

    def fam_fake_faked_tls13(self):
        if os.environ.get("NOTEST_FAKE_FAKED_HTTPS") == "1":
            print("SKIPPED")
            return
        self._fake_faked_tls([])

    # 60-fake-hostfake
    def _fake_hostfake_vary_(self, fooling, pre, post):
        payload = "--payload=" + self.payload
        fake = self.fake_http if self.kind == "http" else self.fake_tls
        blob = self._fake_blob("http" if self.kind == "http" else "tls")
        hostopt = ("host=%s:" % self.HOSTFAKE) if self.HOSTFAKE else ""
        variants = [
            "", "nofake1:", "nofake2:",
            "midhost=midsld:", "nofake1:midhost=midsld:", "nofake2:midhost=midsld:",
        ]
        ok_any = False
        for disorder in ("", "disorder_after:"):
            for v in variants:
                if self.t(blob + list(pre) + [payload,
                        "--lua-desync=fake:blob=%s:%s:repeats=%d"
                        % (fake, fooling, self.FAKE_REPEATS),
                        "--lua-desync=hostfakesplit:%s%s%s%s:repeats=%d"
                        % (hostopt, disorder, v, fooling, self.FAKE_REPEATS)] + list(post)):
                    ok_any = True
                    if self.o.scanlevel == "veryquick":
                        return True
        return ok_any

    def _fake_hostfake_vary(self, fooling, pre, post):
        ok = self._fake_hostfake_vary_(fooling, pre, post)
        if contains(fooling, "tcp_md5"):
            md5post = list(post) + ["--payload=empty", "--out-range=<s1",
                                    "--lua-desync=send:" + self.TCP_MD5]
            if self._fake_hostfake_vary_(fooling, pre, md5post):
                ok = True
        return ok

    def _check_fake_hostfake(self, pre):
        if self.need.get("hostfakesplit", None) == 0:
            return False
        pre = list(pre)
        ok = False
        for ttl in self._ttls():
            for f in ([], ["--payload=empty", "--out-range=s1<d1",
                           "--lua-desync=pktmod:ip%s_ttl=1" % self.ipvv]):
                if self._fake_hostfake_vary("ip%s_ttl=%d" % (self.ipvv, ttl), pre, f):
                    ok = True
                    if self.o.scanlevel != "force":
                        break
            if ok:
                break
        for fooling in self.FOOLINGS_TCP:
            if self._fake_hostfake_vary(fooling, pre, []):
                ok = True
            if self.o.scanlevel == "veryquick" and ok:
                break
        for ttl in self._attls():
            for f in ([], ["--payload=empty", "--out-range=s1<d1",
                           "--lua-desync=pktmod:ip%s_ttl=1" % self.ipvv]):
                if self._fake_hostfake_vary("ip%s_autottl=-%d,3-20" % (self.ipvv, ttl),
                                            pre, f):
                    ok = True
                    if self.o.scanlevel != "force":
                        break
            if self.o.scanlevel == "veryquick" and ok:
                break
        return ok

    def fam_fake_hostfake_http(self):
        if os.environ.get("NOTEST_FAKE_HOSTFAKE_HTTP") == "1":
            print("SKIPPED")
            return
        self.payload = "http_req"
        self._check_fake_hostfake([])

    def fam_fake_hostfake_tls12(self):
        if os.environ.get("NOTEST_FAKE_HOSTFAKE_HTTPS") == "1":
            print("SKIPPED")
            return
        self.payload = "tls_client_hello"
        if self._check_fake_hostfake([]) and self.o.scanlevel != "force":
            return
        self._check_fake_hostfake(["--lua-desync=wssize:wsize=1:scale=6"])

    def fam_fake_hostfake_tls13(self):
        if os.environ.get("NOTEST_FAKE_HOSTFAKE_HTTPS") == "1":
            print("SKIPPED")
            return
        self.payload = "tls_client_hello"
        self._check_fake_hostfake([])

    # 90-quic
    def fam_quic_http3(self):
        if os.environ.get("NOTEST_QUIC") == "1":
            print("SKIPPED")
            return
        payload = "--payload=quic_initial"
        fake = self.fake_quic
        blob = self._fake_blob("quic")
        for repeats in (1, 2, 5, 10, 20):
            self.t(blob + [payload,
                    "--lua-desync=fake:blob=%s:repeats=%d" % (fake, repeats)])
            if self.o.scanlevel != "force":
                break
        if self.ipv == 6:
            for fool in ("ip6_hopbyhop", "ip6_destopt",
                         "ip6_hopbyhop:ip6_destopt"):
                self.t([payload, "--lua-desync=send:" + fool, "--lua-desync=drop"])
        for pos in (8, 16, 32, 64):
            self.t([payload, "--lua-desync=send:ipfrag:ipfrag_pos_udp=%d" % pos,
                    "--lua-desync=drop"])
            if self.o.scanlevel != "force":
                break
        for pos in (8, 16, 32, 64):
            self.t(blob + [payload,
                    "--lua-desync=fake:blob=%s:repeats=%d" % (fake, self.FAKE_REPEATS),
                    "--lua-desync=send:ipfrag:ipfrag_pos_udp=%d" % pos,
                    "--lua-desync=drop"])
            if self.o.scanlevel != "force":
                break

    # ------------------------------------------------------------------
    # protocols
    # ------------------------------------------------------------------

    def _report(self, dom, testname, text):
        self.report.append("%s %s ipv%d : %s" % (dom, testname, self.ipv, text))

    def check_prolog(self):
        if self.o.simulate:
            return True
        print("\n* %s ipv%d %s" % (self.testname, self.ipv, self.dom))
        print("- checking without DPI bypass")
        ok, code = self.run_repeats(self.testfn, self.testname)
        if ok:
            self._report(self.dom, self.testname, "working without bypass")
            if self.o.scanlevel != "force":
                return False
            return True
        if code not in (1, 2, 3, 4, 6, 27):
            self._report(self.dom, self.testname,
                         "test aborted, no reason to continue. curl code %d%s"
                         % (code, (": " + curl_code_text(code)) if curl_code_text(code) else ""))
            return False
        return True

    def check_dpi_ip_block(self):
        print("\n- IP block tests (requires manual interpretation)")
        print("> testing %s on its original ip" % self.o.unblocked_dom)
        rc, _ = self.testfn()
        if rc != 0:
            print("%s is not available. skipping this test." % self.o.unblocked_dom)
            return
        uips = self.resolve_all(self.o.unblocked_dom)
        if not uips:
            print("%s does not resolve. tests not possible." % self.o.unblocked_dom)
            return
        print("> testing %s on %s (%s)" % (self.dom, uips[0], self.o.unblocked_dom))
        _, out = self.testfn(ip=uips[0], detail=True)
        if out.strip():
            print(out.rstrip())
        for bip in self.resolve_all(self.dom):
            print("> testing %s on %s (%s)" % (self.o.unblocked_dom, bip, self.dom))
            _, out = self.testfn(ip=bip, detail=True)
            if out.strip():
                print(out.rstrip())

    def check_port_block(self, dom, port):
        print("\n* port block tests ipv%d %s:%d" % (self.ipv, dom, port))
        ips = self.resolve_all(dom)
        if not ips:
            print("ipv%d %s does not resolve" % (self.ipv, dom))
            return
        fam = socket.AF_INET if self.ipv == 4 else socket.AF_INET6
        for ip in ips:
            s = socket.socket(fam, socket.SOCK_STREAM)
            s.settimeout(2)
            try:
                rc = s.connect_ex((ip, port))
            except OSError:
                rc = 1
            finally:
                s.close()
            if rc == 0:
                print("%s connects" % bracket(ip))
            else:
                print("%s does not connect (socket error %d)" % (bracket(ip), rc))

    def run_families(self, kind):
        for name in FAMILIES:
            fn = getattr(self, "fam_%s_%s" % (name, kind), None)
            if fn is not None:
                fn()

    def check(self, dom, kind):
        self.dom = dom
        self.host = split_uri(dom)[0]
        self.kind = kind
        if kind == "http":
            self.testname = "curl_test_http"
            self.port, self.proto, self.payload = self.o.http_port, "tcp", "http_req"
        elif kind == "tls12":
            self.testname = "curl_test_https_tls12"
            self.port, self.proto, self.payload = self.o.https_port, "tcp", "tls_client_hello"
        elif kind == "tls13":
            self.testname = "curl_test_https_tls13"
            self.port, self.proto, self.payload = self.o.https_port, "tcp", "tls_client_hello"
        elif kind == "http3":
            self.testname = "curl_test_http3"
            self.port, self.proto, self.payload = self.o.quic_port, "udp", "quic_initial"
        self.testfn = self.choose_testfn(kind)
        self.strategy = None
        self.need = {}
        self.ips = self.resolve_all(dom)
        if not self.ips:
            print("\n* %s ipv%d %s does not resolve. skipping." %
                  (self.testname, self.ipv, dom))
            return
        if not self.check_prolog():
            return
        if not self.o.skip_ipblock:
            self.check_dpi_ip_block()
        if self.o.skip_pktws:
            return

        print("\npreparing nfqws2 redirection ipv%d %s:%d" % (self.ipv, self.proto, self.port))
        try:
            self.agent.prepare(self.ipv, self.proto, self.port, self.ips)
        except AgentError as e:
            print("cannot prepare redirection: %s" % e)
            return
        try:
            self.run_families(kind)
        finally:
            self.agent.unprepare()

        print()
        if self.strategy:
            print("!!!!! %s: working strategy found for ipv%d %s : nfqws2 %s !!!!!"
                  % (self.testname, self.ipv, dom, self.describe(self.strategy)))
        else:
            print("%s: nfqws2 strategy for ipv%d %s not found"
                  % (self.testname, self.ipv, dom))
            self._report(dom, self.testname, "nfqws2 not working")

    # ------------------------------------------------------------------
    # summary
    # ------------------------------------------------------------------

    def summary(self):
        print("\n* SUMMARY")
        for line in self.report:
            print(line)
        if self.domains_count > 1:
            print("\n* COMMON")
            for key, doms in self.successes.items():
                if len(doms) >= self.domains_count:
                    print("%s ipv%d : %s" % (key[0], key[1], key[2]))
            print("\n* COVERAGE")
            for key, doms in sorted(self.successes.items(),
                                    key=lambda kv: len(kv[1]), reverse=True):
                print("%d/%d : %s ipv%d : %s"
                      % (len(doms), self.domains_count, key[0], key[1], key[2]))
            if self.o.scanlevel != "force":
                print("\nblockcheck optimizes test sequence. To save time some strategies "
                      "can be skipped if their test is considered useless.")
                print("That's why COMMON intersection can miss strategies that would work "
                      "for all domains, and COVERAGE counts can undercount.")
                print("Use \"force\" scan level to test all strategies and generate "
                      "trustable results.")
                print("Current scan level was \"%s\"." % self.o.scanlevel)
        print("\nPlease note this SUMMARY does not guarantee a magic pill for you to "
              "copy/paste and be happy.")
        print("Understanding how strategies work is very desirable.")


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def parse_args(argv):
    ap = argparse.ArgumentParser(description="blockcheck2 client")
    ap.add_argument("--agent", default=os.environ.get("BLOCKCHECK2_AGENT", LOOP4 + ":1993"),
                    help="agent host:port (default localhost:1993)")
    ap.add_argument("--token", default=os.environ.get("BLOCKCHECK2_TOKEN"),
                    help="shared secret (default $BLOCKCHECK2_TOKEN)")
    ap.add_argument("--domains", default=os.environ.get("DOMAINS", "rutracker.org"),
                    help="space separated domains or URIs")
    ap.add_argument("--ipv", default=os.environ.get("IPVS", "4"),
                    help="4, 6 or 46 (default 4)")
    ap.add_argument("--test", dest="testset", default=os.environ.get("TEST", "standard"),
                    help="test set name (informational, default standard)")
    ap.add_argument("--http", dest="enable_http", action="store_true", default=True)
    ap.add_argument("--no-http", dest="enable_http", action="store_false")
    ap.add_argument("--tls12", dest="enable_tls12", action="store_true", default=True)
    ap.add_argument("--no-tls12", dest="enable_tls12", action="store_false")
    ap.add_argument("--tls13", dest="enable_tls13", action="store_true", default=None)
    ap.add_argument("--no-tls13", dest="enable_tls13", action="store_false")
    ap.add_argument("--http3", dest="enable_http3", action="store_true", default=None)
    ap.add_argument("--no-http3", dest="enable_http3", action="store_false")
    ap.add_argument("--repeats", type=int, default=int(os.environ.get("REPEATS", "1")))
    ap.add_argument("--parallel", action="store_true", default=os.environ.get("PARALLEL") == "1")
    ap.add_argument("--scanlevel", default=os.environ.get("SCANLEVEL", "standard"),
                    choices=["veryquick", "quick", "standard", "force"])
    ap.add_argument("--skip-ipblock", action="store_true",
                    default=os.environ.get("SKIP_IPBLOCK") == "1")
    ap.add_argument("--skip-pktws", action="store_true",
                    default=os.environ.get("SKIP_PKTWS") == "1")
    ap.add_argument("--simulate", action="store_true", default=os.environ.get("SIMULATE") == "1")
    ap.add_argument("--sim-success-rate", type=int,
                    default=int(os.environ.get("SIM_SUCCESS_RATE", "10")))
    ap.add_argument("--curl", default=os.environ.get("CURL", "curl"))
    ap.add_argument("--max-time", type=int, default=int(os.environ.get("CURL_MAX_TIME", "2")))
    ap.add_argument("--max-time-quic", type=int,
                    default=int(os.environ.get("CURL_MAX_TIME_QUIC",
                                               os.environ.get("CURL_MAX_TIME", "2"))))
    ap.add_argument("--user-agent", default=os.environ.get("USER_AGENT", "Mozilla"))
    ap.add_argument("--http-port", type=int, default=int(os.environ.get("HTTP_PORT", "80")))
    ap.add_argument("--https-port", type=int, default=int(os.environ.get("HTTPS_PORT", "443")))
    ap.add_argument("--quic-port", type=int, default=int(os.environ.get("QUIC_PORT", "443")))
    ap.add_argument("--unblocked-dom", default=os.environ.get("UNBLOCKED_DOM", "iana.org"))
    ap.add_argument("--pace", type=int, default=int(os.environ.get("PACE", "0")))
    ap.add_argument("--curl-verbose", action="store_true",
                    default=os.environ.get("CURL_VERBOSE") == "1")
    return ap.parse_args(argv)


def main(argv=None):
    o = parse_args(argv or sys.argv[1:])
    domains = o.domains.split()
    if not domains:
        print("no domains specified", file=sys.stderr)
        return 1
    if o.ipv == "46":
        ipvs = [4, 6]
    elif o.ipv in ("4", "6"):
        ipvs = [int(o.ipv)]
    else:
        print("invalid --ipv, use 4, 6 or 46", file=sys.stderr)
        return 1

    agent = AgentConnection(o.agent, o.token)
    try:
        info = agent.ping()
    except AgentError as e:
        print("cannot contact agent: %s" % e, file=sys.stderr)
        return 1
    print("* connected to agent %s (fwtype=%s, nfqws2=%s)"
          % (o.agent, info.get("fwtype"), info.get("nfqws2")))

    chk = Checker(o, agent)
    chk.domains_count = len(domains)

    print("* checking system / curl")
    chk.detect_curl()
    print("curl: %s" % chk.curl_version.splitlines()[0] if chk.curl_version else "curl: ?")
    chk.tls13_ok = chk.tls13_ok or False
    chk.http3_ok = chk.http3_ok or False

    if o.enable_tls13 is None:
        o.enable_tls13 = 1 if chk.tls13_ok else 0
    if o.enable_http3 is None:
        o.enable_http3 = 1 if chk.http3_ok else 0
    if o.enable_tls13 and not chk.tls13_ok:
        print("WARNING ! installed curl does not support TLS 1.3. tests disabled.")
        o.enable_tls13 = 0
    if o.enable_http3 and not chk.http3_ok:
        print("WARNING ! installed curl does not support http3 QUIC. tests disabled.")
        o.enable_http3 = 0

    print("* checking DNS")
    for d in domains:
        host = split_uri(d)[0]
        try:
            infos = socket.getaddrinfo(host, None)
            ok = bool(infos)
        except OSError:
            ok = False
        print("%s : %s" % (d, "OK" if ok else "FAILED to resolve"))

    try:
        for dom in domains:
            for ipv in ipvs:
                chk.ipv = ipv
                chk.ipvv = "6" if ipv == 6 else ""
                chk.FOOLINGS_TCP = list(chk.FOOLINGS46_TCP)
                if ipv == 6:
                    chk.FOOLINGS_TCP += chk.FOOLINGS6_TCP
                chk.FOOLINGS_UDP = list((os.environ.get("FOOLINGS_UDP") or "badsum").split())
                if ipv == 6:
                    chk.FOOLINGS_UDP += chk.FOOLINGS6_UDP
                chk.TCP_MD5 = os.environ.get("TCP_MD5") or "tcp_md5"

                if o.enable_http:
                    if not o.skip_ipblock:
                        chk.check_port_block(dom, o.http_port)
                    chk.check(dom, "http")
                if (o.enable_tls12 or o.enable_tls13) and not o.skip_ipblock:
                    chk.check_port_block(dom, o.https_port)
                if o.enable_tls12:
                    chk.check(dom, "tls12")
                if o.enable_tls13:
                    chk.check(dom, "tls13")
                if o.enable_http3:
                    chk.check(dom, "http3")
    finally:
        agent.reset()
        agent.close()

    chk.summary()
    return 0


if __name__ == "__main__":
    sys.exit(main())
