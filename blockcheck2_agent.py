#!/usr/bin/env python3
"""blockcheck2 agent - runs on the Linux router.

This is the "server" half of the blockcheck2 split.  It owns the two things
that must happen on the router itself:

  * firewall redirection (nftables or iptables) of traffic to an NFQUEUE
  * the lifetime of the nfqws2 process that implements a DPI-bypass strategy

The client (blockcheck2_client.py) connects over TCP, hands over a strategy,
runs curl checks from wherever it lives and asks the agent to start/stop
nfqws2 around each check.

Protocol: one JSON object per line, one JSON reply per line.

    -> {"cmd":"ping"}
    <- {"ok":true,"fwtype":"nftables","pid":null,...}

Commands
--------
ping                         report capabilities / state
prepare {ipv,proto,port,ips} install redirection rules for these targets
unprepare                    remove redirection rules
start {args:[...]}           start nfqws2 with the given strategy arguments
stop                         stop nfqws2 (if running)
reset                        stop + unprepare
status                       report running/prepared state
put_file {name,content_b64}  upload a blob/pattern file, reply with remote path
shutdown                     reset and stop the agent

Run as root.  Example:

    python3 blockcheck2_agent.py --listen ROUTER_IP --port 1993 --token secret
"""

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import signal
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time

DESYNC_MARK = 0x10000000
GUARD_TIMER = (
    "timer_set('exit_guard',function(name,data) "
    "io.stderr:write('exit_guard\\n'); os.exit(3000); end,20000,true)"
)

AGENT_VERSION = "2.0"


# --------------------------------------------------------------------------
# process helpers
# --------------------------------------------------------------------------

def run(argv, check=False):
    """Run argv without a shell.  Return (rc, stdout, stderr)."""
    try:
        p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError:
        return 127, "", "%s: not found" % argv[0]
    out = p.stdout.decode("utf-8", "replace")
    err = p.stderr.decode("utf-8", "replace")
    if check and p.returncode != 0:
        raise RuntimeError("%s failed (%d): %s" % (" ".join(argv), p.returncode, err.strip()))
    return p.returncode, out, err


def which(name):
    return shutil.which(name)


def pid_alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def detect_fwtype():
    env = os.environ.get("FWTYPE")
    if env in ("nftables", "iptables"):
        return env
    if which("nft") and _kernel_ge(4, 16):
        return "nftables"
    if which("iptables"):
        return "iptables"
    return "unsupported"


def _kernel_ge(major, minor):
    try:
        with open("/proc/version", "r") as f:
            v = f.read()
        m = re.search(r"Linux version (\d+)\.(\d+)", v)
        if not m:
            return False
        a, b = int(m.group(1)), int(m.group(2))
        return a > major or (a == major and b >= minor)
    except OSError:
        return False


# --------------------------------------------------------------------------
# firewall backends
# --------------------------------------------------------------------------

class FirewallError(RuntimeError):
    pass


class BaseFirewall:
    def __init__(self, qnum):
        self.qnum = qnum
        self.mark = DESYNC_MARK
        self.prepared = False

    def prepare(self, ipv, proto, port, ips):
        self.unprepare()
        self._prepare(ipv, proto, port, ips)
        self.prepared = True

    def unprepare(self):
        if self.prepared:
            self._unprepare()
            self.prepared = False

    def _prepare(self, ipv, proto, port, ips):
        raise NotImplementedError

    def _unprepare(self):
        raise NotImplementedError

    def sweep(self):
        pass


class NftFirewall(BaseFirewall):
    """nftables backend.  Table name embeds our pid to allow safe sweep."""

    def __init__(self, qnum):
        super().__init__(qnum)
        self.table = "blockcheck2-%d" % os.getpid()

    def _nft(self, *args, check=False):
        return run(["nft"] + list(args), check=check)

    def _prepare(self, ipv, proto, port, ips):
        if not ips:
            raise FirewallError("no target ips")
        nfproto = "ipv%d" % ipv
        addr = "ip" if ipv == 4 else "ip6"
        settype = "ipv4_addr" if ipv == 4 else "ipv6_addr"

        self._nft("add", "table", "inet", self.table, check=True)
        self._nft("add", "chain", "inet", self.table, "postnat",
                  "{", "type", "filter", "hook", "postrouting", "priority", "102;", "}")
        self._nft("add", "chain", "inet", self.table, "prenat",
                  "{", "type", "filter", "hook", "prerouting", "priority", "-102;", "}")
        self._nft("add", "chain", "inet", self.table, "predefrag",
                  "{", "type", "filter", "hook", "output", "priority", "-402;", "}")
        self._nft("add", "set", "inet", self.table, "targets",
                  "{", "type", settype + ";", "}")
        elems = []
        for i, ip in enumerate(ips):
            elems.append(ip + ("," if i < len(ips) - 1 else ""))
        self._nft("add", "element", "inet", self.table, "targets", "{", *elems, "}")

        mark = "0x%x" % self.mark
        # outgoing: mark connection and hand the packet to nfqws2
        self._nft(
            "add", "rule", "inet", self.table, "postnat",
            "meta", "nfproto", nfproto,
            proto, "dport", str(port),
            "mark", "and", mark, "==", "0",
            addr, "daddr", "@targets",
            "ct", "mark", "set", "ct", "mark", "or", mark,
            "queue", "num", str(self.qnum), "bypass",
        )
        # do not let conntrack mangle packets synthesized by nfqws2
        self._nft(
            "add", "rule", "inet", self.table, "predefrag",
            "meta", "nfproto", nfproto,
            "mark", "and", mark, "!=", "0",
            "notrack",
        )
        # incoming SYN,ACK for tcp: needed by autottl / tcp_mss strategies
        if proto == "tcp":
            self._nft(
                "add", "rule", "inet", self.table, "prenat",
                "meta", "nfproto", nfproto,
                "tcp", "sport", str(port),
                "tcp", "flags", "&", "(", "syn", "|", "ack", ")", "==",
                "(", "syn", "|", "ack", ")",
                addr, "saddr", "@targets",
                "queue", "num", str(self.qnum), "bypass",
            )
        # drop ICMP errors related to tampered connections
        if ipv == 4:
            self._nft("add", "rule", "inet", self.table, "prenat",
                      "icmp", "type", "time-exceeded",
                      "ct", "mark", "and", mark, "!=", "0", "drop")
            self._nft("add", "rule", "inet", self.table, "prenat",
                      "icmp", "type", "time-exceeded",
                      "ct", "state", "invalid", "drop")
        else:
            self._nft("add", "rule", "inet", self.table, "prenat",
                      "icmpv6", "type", "time-exceeded",
                      "ct", "mark", "and", mark, "!=", "0", "drop")
            self._nft("add", "rule", "inet", self.table, "prenat",
                      "icmpv6", "type", "time-exceeded",
                      "ct", "state", "invalid", "drop")

    def _unprepare(self):
        self._nft("delete", "table", "inet", self.table)

    def sweep(self):
        rc, out, _ = self._nft("list", "tables")
        if rc != 0:
            return
        for line in out.splitlines():
            m = re.match(r"^table inet (blockcheck2-(\d+))$", line.strip())
            if not m:
                continue
            pid = int(m.group(2))
            if not pid_alive(pid):
                self._nft("delete", "table", "inet", m.group(1))


class IptFirewall(BaseFirewall):
    """iptables backend.  Router friendly: uses POSTROUTING / PREROUTING."""

    def __init__(self, qnum):
        super().__init__(qnum)
        self.pid = os.getpid()
        self.out_chain = "blockcheck2_output_%d" % self.pid
        self.in_chain = "blockcheck2_input_%d" % self.pid
        self.aux = []

    def _ipt(self, ver, *args, check=False):
        exe = "iptables" if ver == 4 else "ip6tables"
        return run([exe] + list(args), check=check)

    def _add_aux(self, ver, table, *args):
        # idempotent insert: skip when an identical rule already exists
        rc, _, _ = self._ipt(ver, "-t", table, "-C", *args)
        if rc != 0:
            self._ipt(ver, "-t", table, "-I", *args)
        self.aux.append((ver, table, args))

    def _prepare(self, ipv, proto, port, ips):
        if not ips:
            raise FirewallError("no target ips")
        ver = ipv
        mark = "0x%x/0x%x" % (self.mark, self.mark)
        os_chain, in_chain = self.out_chain, self.in_chain

        self._ipt(ver, "-t", "mangle", "-N", os_chain)
        self._ipt(ver, "-t", "mangle", "-F", os_chain)
        self._ipt(ver, "-t", "mangle", "-I", "POSTROUTING", "-j", os_chain)

        def app(*a):
            self._ipt(ver, "-t", "mangle", "-A", os_chain, *a)

        app("-m", "mark", "--mark", mark, "-j", "RETURN")
        app("!", "-p", proto, "-j", "RETURN")
        app("-p", proto, "!", "--dport", str(port), "-j", "RETURN")
        for ip in ips:
            app("-d", ip, "-j", "CONNMARK", "--or-mark", "0x%x" % self.mark)
            app("-d", ip, "-j", "NFQUEUE", "--queue-num", str(self.qnum), "--queue-bypass")

        # avoid INVALID state drops, allow fragments, notrack nfqws output
        if proto == "tcp":
            self._add_aux(ver, "filter", "INPUT", "-p", "tcp", "--sport", str(port), "!", "--syn", "-j", "ACCEPT")
            self._add_aux(ver, "filter", "FORWARD", "-p", "tcp", "--sport", str(port), "!", "--syn", "-j", "ACCEPT")
        icmp = "icmp" if ipv == 4 else "icmpv6"
        icmpt = "icmp" if ipv == 4 else "icmp6"
        self._add_aux(ver, "filter", "INPUT", "-p", icmp, "-m", icmpt, "--%s-type" % icmpt,
                      "time-exceeded", "-m", "connmark", "--mark", mark, "-j", "DROP")
        self._add_aux(ver, "filter", "FORWARD", "-p", icmp, "-m", icmpt, "--%s-type" % icmpt,
                      "time-exceeded", "-m", "connmark", "--mark", mark, "-j", "DROP")
        self._add_aux(ver, "filter", "OUTPUT", "-p", proto, "--dport", str(port),
                      "-m", "conntrack", "--ctstate", "INVALID", "-j", "ACCEPT")
        self._add_aux(ver, "filter", "FORWARD", "-p", proto, "--dport", str(port),
                      "-m", "conntrack", "--ctstate", "INVALID", "-j", "ACCEPT")
        if ipv == 4:
            self._add_aux(ver, "filter", "OUTPUT", "-f", "-j", "ACCEPT")
            self._add_aux(ver, "filter", "FORWARD", "-f", "-j", "ACCEPT")
        else:
            # disable ipv6 defrag for ipfrag/ts strategies (4.16+ kernels)
            rc, _, _ = self._ipt(ver, "-t", "raw", "-C", "OUTPUT", "-p", proto, "-m", "frag",
                                 "-j", "CT", "--notrack")
            if rc != 0:
                self._ipt(ver, "-t", "raw", "-I", "OUTPUT", "-p", proto, "-m", "frag",
                          "-j", "CT", "--notrack")
                self.aux.append((ver, "raw", ("OUTPUT", "-p", proto, "-m", "frag",
                                              "-j", "CT", "--notrack")))
        self._add_aux(ver, "raw", "OUTPUT", "-m", "mark", "--mark", mark,
                      "-j", "CT", "--notrack")

        # incoming SYN,ACK for tcp
        if proto == "tcp":
            self._ipt(ver, "-t", "mangle", "-N", in_chain)
            self._ipt(ver, "-t", "mangle", "-F", in_chain)
            self._ipt(ver, "-t", "mangle", "-I", "PREROUTING", "-j", in_chain)

            def appin(*a):
                self._ipt(ver, "-t", "mangle", "-A", in_chain, *a)

            appin("!", "-p", "tcp", "-j", "RETURN")
            appin("-p", "tcp", "!", "--sport", str(port), "-j", "RETURN")
            appin("-p", "tcp", "!", "--tcp-flags", "SYN,ACK", "SYN,ACK", "-j", "RETURN")
            for ip in ips:
                appin("-s", ip, "-j", "NFQUEUE", "--queue-num", str(self.qnum), "--queue-bypass")

    def _unprepare(self):
        # delete jumps/chains on both families; harmless where absent
        for v in (4, 6):
            self._ipt(v, "-t", "mangle", "-D", "POSTROUTING", "-j", self.out_chain)
            self._ipt(v, "-t", "mangle", "-F", self.out_chain)
            self._ipt(v, "-t", "mangle", "-X", self.out_chain)
            self._ipt(v, "-t", "mangle", "-D", "PREROUTING", "-j", self.in_chain)
            self._ipt(v, "-t", "mangle", "-F", self.in_chain)
            self._ipt(v, "-t", "mangle", "-X", self.in_chain)
        for v, table, args in self.aux:
            self._ipt(v, "-t", table, "-D", *args)
        self.aux = []

    def sweep(self):
        # remove chains and jumps whose owning pid is gone
        prefixes = ("blockcheck2_output_", "blockcheck2_input_")
        for v in (4, 6):
            exe = "iptables" if v == 4 else "ip6tables"
            rc, out, _ = run([exe, "-t", "mangle", "-S"])
            if rc != 0:
                continue
            stale = set()
            for line in out.splitlines():
                parts = line.split()
                if parts and parts[0] == "-N":
                    name = parts[1]
                    for p in prefixes:
                        if name.startswith(p) and name[len(p):].isdigit() \
                                and not pid_alive(int(name[len(p):])):
                            stale.add(name)
            if not stale:
                continue
            # delete jump rules pointing at stale chains, then the chains
            for line in out.splitlines():
                parts = line.split()
                if not parts or parts[0] not in ("-A", "-I"):
                    continue
                for name in stale:
                    if name in parts:
                        run([exe, "-t", "mangle", "-D"] + parts[1:])
                        break
            for name in stale:
                run([exe, "-t", "mangle", "-F", name])
                run([exe, "-t", "mangle", "-X", name])


# --------------------------------------------------------------------------
# nfqws2 manager
# --------------------------------------------------------------------------

class NfqwsManager:
    def __init__(self, zapret_base, nfqws2, uid, gid, qnum):
        self.base = zapret_base
        self.nfqws2 = nfqws2
        self.uid = uid
        self.gid = gid
        self.qnum = qnum
        self.proc = None

    @property
    def running(self):
        return self.proc is not None and self.proc.poll() is None

    def start(self, args):
        if self.running:
            self.stop()
        if not os.access(self.nfqws2, os.X_OK):
            raise RuntimeError("nfqws2 is not executable: %s" % self.nfqws2)
        lib = os.path.join(self.base, "lua", "zapret-lib.lua")
        ad = os.path.join(self.base, "lua", "zapret-antidpi.lua")
        cmd = [
            self.nfqws2,
            "--uid=%d:%d" % (self.uid, self.gid),
            "--fwmark=0x%x" % DESYNC_MARK,
            "--qnum=%d" % self.qnum,
            "--lua-init=" + GUARD_TIMER,
            "--lua-init=@" + lib,
            "--lua-init=@" + ad,
        ] + list(args)
        self.proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(0.1)
        if self.proc.poll() is not None:
            rc = self.proc.returncode
            self.proc = None
            raise RuntimeError("nfqws2 exited immediately (code %d)" % rc)
        return self.proc.pid

    def stop(self):
        p, self.proc = self.proc, None
        if p is None:
            return
        if p.poll() is not None:
            return
        try:
            p.terminate()
            p.wait(timeout=2)
        except subprocess.TimeoutExpired:
            p.kill()
            try:
                p.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
        except OSError:
            pass


# --------------------------------------------------------------------------
# agent
# --------------------------------------------------------------------------

class Agent:
    def __init__(self, args):
        self.args = args
        base = args.zapret_base or os.path.dirname(os.path.abspath(__file__))
        self.zapret_base = os.path.abspath(base)
        nfqws2 = args.nfqws2 or os.path.join(self.zapret_base, "nfq2", "nfqws2")
        self.fwtype = args.fwtype or detect_fwtype()
        self.qnum = args.qnum
        self.mark = DESYNC_MARK
        self.lock = threading.RLock()
        self.blob_dir = tempfile.mkdtemp(prefix="blockcheck2-blobs-")
        self.firewall = self._make_firewall(self.fwtype)
        self.nfqws = NfqwsManager(self.zapret_base, nfqws2, args.uid, args.gid, self.qnum)
        self.prepared = None
        self.stopping = False
        self.server = None

    def _make_firewall(self, fwtype):
        if fwtype == "nftables":
            return NftFirewall(self.qnum)
        if fwtype == "iptables":
            return IptFirewall(self.qnum)
        raise RuntimeError("unsupported firewall type: %s" % fwtype)

    # -- command handling ---------------------------------------------------

    def handle(self, req):
        cmd = req.get("cmd")
        if self.args.token and req.get("token") != self.args.token:
            return {"ok": False, "error": "unauthorized"}
        with self.lock:
            try:
                fn = getattr(self, "cmd_" + str(cmd), None)
                if fn is None:
                    return {"ok": False, "error": "unknown command: %r" % cmd}
                return fn(req)
            except (RuntimeError, FirewallError) as e:
                return {"ok": False, "error": str(e)}
            except Exception as e:  # pragma: no cover - defensive
                return {"ok": False, "error": "%s: %s" % (type(e).__name__, e)}

    def cmd_ping(self, req):
        return {
            "ok": True,
            "agent_version": AGENT_VERSION,
            "fwtype": self.fwtype,
            "kernel": self._kernel(),
            "zapret_base": self.zapret_base,
            "nfqws2": self.nfqws.nfqws2,
            "qnum": self.qnum,
            "pid": os.getpid(),
            "running": self.nfqws.running,
            "prepared": self.prepared,
        }

    def cmd_status(self, req):
        return {
            "ok": True,
            "running": self.nfqws.running,
            "pid": self.nfqws.proc.pid if self.nfqws.running else None,
            "prepared": self.prepared,
        }

    def cmd_prepare(self, req):
        ipv = int(req["ipv"])
        proto = req["proto"]
        port = int(req["port"])
        ips = [str(x) for x in req.get("ips", [])]
        if ipv not in (4, 6):
            return {"ok": False, "error": "bad ipv"}
        if proto not in ("tcp", "udp"):
            return {"ok": False, "error": "bad proto"}
        if not (1 <= port <= 65535):
            return {"ok": False, "error": "bad port"}
        self.firewall.prepare(ipv, proto, port, ips)
        self.prepared = {"ipv": ipv, "proto": proto, "port": port, "ips": ips}
        return {"ok": True, "prepared": self.prepared}

    def cmd_unprepare(self, req):
        self.firewall.unprepare()
        self.prepared = None
        return {"ok": True}

    def cmd_start(self, req):
        args = [str(a) for a in req.get("args", [])]
        pid = self.nfqws.start(args)
        return {"ok": True, "pid": pid}

    def cmd_stop(self, req):
        self.nfqws.stop()
        return {"ok": True}

    def cmd_reset(self, req):
        self.nfqws.stop()
        self.firewall.unprepare()
        self.prepared = None
        return {"ok": True}

    def cmd_put_file(self, req):
        name = str(req.get("name") or "blob")
        data = base64.b64decode(req.get("content_b64", ""))
        h = hashlib.sha256(data).hexdigest()[:16]
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", os.path.basename(name))
        path = os.path.join(self.blob_dir, "%s-%s" % (h, safe))
        if not os.path.exists(path):
            with open(path, "wb") as f:
                f.write(data)
        return {"ok": True, "path": path, "size": len(data)}

    def cmd_shutdown(self, req):
        self.nfqws.stop()
        self.firewall.unprepare()
        self.prepared = None
        self.stopping = True
        threading.Thread(target=self._shutdown_server, daemon=True).start()
        return {"ok": True}

    def _shutdown_server(self):
        time.sleep(0.1)
        if self.server is not None:
            self.server.shutdown()

    def close(self):
        with self.lock:
            try:
                self.nfqws.stop()
            finally:
                self.firewall.unprepare()
                shutil.rmtree(self.blob_dir, ignore_errors=True)

    def _kernel(self):
        try:
            with open("/proc/version", "r") as f:
                return f.read().strip()
        except OSError:
            return ""


# --------------------------------------------------------------------------
# server
# --------------------------------------------------------------------------

class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        agent = self.server.agent
        while not agent.stopping:
            line = self.rfile.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            try:
                req = json.loads(line.decode("utf-8", "replace"))
                if not isinstance(req, dict):
                    raise ValueError("request must be an object")
            except Exception as e:
                self._reply({"ok": False, "error": "bad json: %s" % e})
                continue
            reply = agent.handle(req)
            self._reply(reply)
        # client went away: never leave a running nfqws2 / stale rules behind
        if not agent.stopping:
            with agent.lock:
                agent.nfqws.stop()
                agent.firewall.unprepare()
                agent.prepared = None

    def _reply(self, obj):
        try:
            self.wfile.write((json.dumps(obj) + "\n").encode("utf-8"))
            self.wfile.flush()
        except OSError:
            pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    ap = argparse.ArgumentParser(description="blockcheck2 Linux router agent")
    anyaddr = ".".join(["0"] * 4)
    ap.add_argument("--listen", default=anyaddr, help="address to bind (default: all interfaces)")
    ap.add_argument("--port", type=int, default=1993, help="TCP port (default 1993)")
    ap.add_argument("--token", default=os.environ.get("BLOCKCHECK2_TOKEN"),
                    help="shared secret required from clients")
    ap.add_argument("--zapret-base", default=os.environ.get("ZAPRET_BASE"),
                    help="zapret base dir (default: script dir)")
    ap.add_argument("--nfqws2", default=os.environ.get("NFQWS2"),
                    help="path to nfqws2")
    ap.add_argument("--fwtype", default=os.environ.get("FWTYPE"),
                    choices=["nftables", "iptables"], help="override firewall type")
    ap.add_argument("--qnum", type=int, default=int(os.environ.get("QNUM", "200")),
                    help="NFQUEUE number (default 200)")
    ap.add_argument("--uid", type=int, default=int(os.environ.get("WS_UID", "0")),
                    help="nfqws2 uid (default 0)")
    ap.add_argument("--gid", type=int, default=int(os.environ.get("WS_GID", "0")),
                    help="nfqws2 gid (default 0)")
    ap.add_argument("--sweep", action="store_true", default=True,
                    help="remove stale blockcheck2 firewall objects at startup")
    args = ap.parse_args()

    if os.geteuid() != 0:
        print("blockcheck2_agent: root is required", file=sys.stderr)
        return 2

    agent = Agent(args)
    if agent.fwtype == "unsupported":
        print("blockcheck2_agent: neither nftables nor iptables is available", file=sys.stderr)
        return 2

    if args.sweep:
        agent.firewall.sweep()

    server_cls = Server
    if ":" in args.listen:
        class Server6(Server):
            address_family = socket.AF_INET6
        server_cls = Server6
    server = server_cls((args.listen, args.port), Handler)
    server.agent = agent
    agent.server = server

    def _sig(signum, frame):
        agent.stopping = True
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)
    signal.signal(signal.SIGHUP, _sig)

    print("blockcheck2_agent %s listening on %s:%d (fwtype=%s, nfqws2=%s)"
          % (AGENT_VERSION, args.listen, args.port, agent.fwtype, agent.nfqws.nfqws2))
    try:
        server.serve_forever()
    finally:
        agent.close()
        server.server_close()
        print("blockcheck2_agent stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
