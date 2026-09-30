#!/usr/bin/python3
import base64
import hashlib
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time

AGE_SHA = "c5f1e2cb2e7380db9e4554410224d6ad5c91c1119bf78ddf9f8902f3736a7674"
IDENTITY = "AGE-PLUGIN-TEST-10Q32NLXM"
STREAM_CAP = 65536
PROTOCOL_CAP = 65536
TRACE_CAP = 8192
AGE_SIZE_CAP = 256 * 1024 * 1024
GLOBAL_SECONDS = 30
children = []
captures = []


class Fail(Exception):
    pass


def atomic_json(path, value):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        json.dump(value, f, sort_keys=True, separators=(",", ":"))
        f.write("\n")
    os.replace(tmp, path)


def load_trace(path):
    try:
        s = os.stat(path, follow_symlinks=False)
        if not stat.S_ISREG(s.st_mode) or s.st_size > TRACE_CAP:
            raise Fail("bad_trace")
        with open(path, "r", encoding="utf-8") as f:
            value = json.load(f)
        if not isinstance(value, dict):
            raise Fail("bad_trace")
        return value
    except FileNotFoundError:
        return None


def hash_age(path):
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_size <= 0 or s.st_size > AGE_SIZE_CAP:
            raise Fail("age_premise")
        h = hashlib.sha256()
        while True:
            block = os.read(fd, 131072)
            if not block:
                break
            h.update(block)
        return h.hexdigest()
    finally:
        os.close(fd)


def cleanup_group(p):
    ok = True
    for sig, pause in ((signal.SIGTERM, 0.20), (signal.SIGKILL, 0.05)):
        delivered = False
        try:
            os.killpg(p.pid, sig)
            delivered = True
        except ProcessLookupError:
            pass
        except Exception:
            ok = False
        if delivered:
            time.sleep(pause)
    try:
        p.wait(timeout=0.7)
    except subprocess.TimeoutExpired:
        ok = False
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except Exception:
            ok = False
        try:
            p.wait(timeout=0.7)
        except subprocess.TimeoutExpired:
            ok = False
    try:
        os.killpg(p.pid, 0)
    except ProcessLookupError:
        pass
    except Exception:
        ok = False
    else:
        ok = False
    return ok


def category(rc):
    if rc is None:
        return "not_exited"
    if rc == 0:
        return "zero"
    if rc == -signal.SIGINT:
        return "signal_int"
    if rc < 0:
        return "other_signal"
    return "nonzero"


def enum_value(value, allowed):
    return value if value in allowed else "other"


PLUGIN = r'''#!/usr/bin/python3
import base64
import json
import os
import signal
import sys

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
with open(os.path.join(root, "mode"), "r", encoding="ascii") as f:
    mode = f.read()
trace_path = os.path.join(root, mode + ".json")
total = 0
trace = {}


def save():
    tmp = trace_path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        json.dump(trace, f, sort_keys=True, separators=(",", ":"))
        f.write("\n")
    os.replace(tmp, trace_path)


def read_stanza():
    global total
    line = sys.stdin.buffer.readline(4097)
    total += len(line)
    if not line:
        return None
    if len(line) > 4096 or total > 65536 or not line.endswith(b"\n") or not line.startswith(b"-> "):
        raise ValueError()
    fields = line[:-1].split(b" ")
    if len(fields) < 2:
        raise ValueError()
    size = 0
    while True:
        line = sys.stdin.buffer.readline(4097)
        total += len(line)
        if not line or len(line) > 4096 or total > 65536 or not line.endswith(b"\n"):
            raise ValueError()
        raw = line[:-1]
        part = base64.b64decode(raw + b"=" * ((4 - len(raw) % 4) % 4), validate=True)
        if len(part) > 48:
            raise ValueError()
        size += len(part)
        if len(part) < 48:
            return fields[1].decode("ascii"), [x.decode("ascii") for x in fields[2:]], size


def write_stanza(kind, body=b""):
    sys.stdout.buffer.write(b"-> " + kind.encode("ascii") + b"\n")
    raw = base64.b64encode(body).rstrip(b"=")
    for i in range(0, len(raw), 64):
        sys.stdout.buffer.write(raw[i:i + 64] + b"\n")
    if not raw or len(raw) % 64 == 0:
        sys.stdout.buffer.write(b"\n")
    sys.stdout.buffer.flush()


def read_phase():
    identities = 0
    wraps = 0
    extensions = 0
    identity_ok = False
    wrap_ok = False
    done_ok = False
    expected = True
    for _ in range(20):
        stanza = read_stanza()
        if stanza is None:
            break
        kind, args, body_size = stanza
        if kind == "add-identity":
            identities += 1
            identity_ok = args == ["AGE-PLUGIN-TEST-10Q32NLXM"] and body_size == 0
        elif kind == "wrap-file-key":
            wraps += 1
            wrap_ok = args == [] and body_size > 0
        elif kind == "extension-labels":
            extensions += 1
            expected = expected and args == [] and body_size == 0
        elif kind == "done":
            done_ok = args == [] and body_size == 0
            break
        elif not kind.startswith("grease-"):
            expected = False
    trace.update(
        argv=sys.argv[1:] == ["--age-plugin=recipient-v1"],
        identity=identities == 1 and identity_ok,
        wrap=wraps == 1 and wrap_ok,
        extension=extensions == 1,
        done=done_ok,
        expected=expected,
    )
    trace["premises"] = all(
        trace.get(k) is True
        for k in ("argv", "identity", "wrap", "extension", "done", "expected")
    )
    save()


def close_event():
    def interrupted(_signum, _frame):
        trace["terminal"] = "sigint"
        save()
        os._exit(0)

    signal.signal(signal.SIGINT, interrupted)
    trace["terminal"] = "eof" if read_stanza() is None else "stanza"
    save()


try:
    read_phase()
except Exception:
    trace["premises"] = False
    save()
    raise SystemExit(3)

if not trace["premises"]:
    write_stanza("error", b"fixture premise failed")
    raise SystemExit(4)

if mode == "cancel":
    trace["ready"] = True
    save()
    close_event()
    raise SystemExit(0)

write_stanza("request-secret", b"Enter synthetic PIN:")
trace["request"] = True
reply = read_stanza()
trace["response"] = "eof" if reply is None else reply[0]
save()

write_stanza("error", b"synthetic plugin failure")
reply = read_stanza()
trace["ack"] = "eof" if reply is None else reply[0]
save()
close_event()
'''


def fixture_ok(trace):
    return isinstance(trace, dict) and trace.get("premises") is True and all(
        trace.get(k) is True
        for k in ("argv", "identity", "wrap", "extension", "done", "expected")
    )


def spawn(age, identity, env, output_dir):
    p = subprocess.Popen(
        [age, "-e", "-i", identity],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=output_dir,
        env=env,
        close_fds=True,
        start_new_session=True,
    )
    children.append(p)
    state = {
        "out": bytearray(),
        "err": bytearray(),
        "out_total": 0,
        "err_total": 0,
        "overflow": False,
        "lock": threading.Lock(),
    }

    def drain(stream, key):
        total_key = key + "_total"
        while True:
            block = stream.read(4096)
            if not block:
                break
            should_stop = False
            with state["lock"]:
                state[total_key] += len(block)
                room = STREAM_CAP - len(state[key])
                if room > 0:
                    state[key].extend(block[:room])
                if state[total_key] > STREAM_CAP and not state["overflow"]:
                    state["overflow"] = True
                    should_stop = True
            if should_stop:
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    threads = [
        threading.Thread(target=drain, args=(p.stdout, "out"), daemon=True),
        threading.Thread(target=drain, args=(p.stderr, "err"), daemon=True),
    ]
    captures.append(threads)
    for thread in threads:
        thread.start()
    try:
        p.stdin.write(b"public synthetic payload\n")
        p.stdin.close()
    except BrokenPipeError:
        pass
    return p, state, threads


def snapshot(state):
    with state["lock"]:
        return state["overflow"], bytes(state["out"]), bytes(state["err"])


def finish(p, state, threads, seconds):
    end = time.monotonic() + seconds
    timed_out = False
    rc = None
    while True:
        overflow, _, _ = snapshot(state)
        rc = p.poll()
        if overflow or rc is not None:
            break
        if time.monotonic() >= end:
            timed_out = True
            break
        time.sleep(0.02)
    overflow, stdout, stderr = snapshot(state)
    bounded = not timed_out and not overflow and rc is not None
    if not bounded:
        cleanup_group(p)
    for thread in threads:
        thread.join(1)
    if any(thread.is_alive() for thread in threads):
        raise Fail("capture")
    overflow, stdout, stderr = snapshot(state)
    if overflow:
        bounded = False
    return bounded, rc, stdout, stderr


def purge_output(output_dir):
    ok = True
    try:
        names = os.listdir(output_dir)
    except Exception:
        return False
    for name in names:
        path = os.path.join(output_dir, name)
        try:
            if os.path.islink(path) or not os.path.isdir(path):
                os.unlink(path)
            else:
                shutil.rmtree(path)
        except FileNotFoundError:
            pass
        except Exception:
            ok = False
    try:
        return ok and os.listdir(output_dir) == []
    except Exception:
        return False


def main():
    if len(sys.argv) != 3 or not all(os.path.isabs(x) for x in sys.argv[1:]):
        return 64
    age, output_dir = sys.argv[1:]
    if os.path.lexists(output_dir):
        return 65

    os.umask(0o077)
    os.mkdir(output_dir, 0o700)
    result = {
        "schema": "sacrysty-age-interface-probe-v2",
        "probe_status": "error",
        "failure_class": "internal",
    }

    def global_timeout(_signum, _frame):
        raise Fail("global_bound")

    signal.signal(signal.SIGALRM, global_timeout)
    signal.alarm(GLOBAL_SECONDS)

    try:
        if not os.access(age, os.X_OK):
            raise Fail("age_premise")
        if hash_age(age) != AGE_SHA:
            raise Fail("age_digest_before")

        bindir = os.path.join(output_dir, "bin")
        tmpdir = os.path.join(output_dir, "tmp")
        os.mkdir(bindir, 0o700)
        os.mkdir(tmpdir, 0o700)
        plugin = os.path.join(bindir, "age-plugin-test")
        with open(plugin, "w", encoding="utf-8", newline="\n") as f:
            f.write(PLUGIN)
        os.chmod(plugin, 0o700)

        identity = os.path.join(output_dir, "identity")
        mode = os.path.join(output_dir, "mode")
        with open(identity, "w", encoding="ascii", newline="\n") as f:
            f.write(IDENTITY + "\n")

        env = {
            "PATH": bindir,
            "TMPDIR": tmpdir,
            "LC_ALL": "C",
            "PYTHONDONTWRITEBYTECODE": "1",
        }

        with open(mode, "w", encoding="ascii") as f:
            f.write("pin")
        p, state, threads = spawn(age, identity, env, output_dir)
        bounded, pin_rc, stdout, stderr = finish(p, state, threads, 8)
        group_clean = cleanup_group(p)
        trace = load_trace(os.path.join(output_dir, "pin.json"))
        if not bounded:
            raise Fail("pin_bound")
        if not group_clean:
            raise Fail("pin_cleanup")
        if not fixture_ok(trace):
            raise Fail("pin_premise")

        result["premises"] = {
            "age_digest_before": True,
            "age_regular_executable": True,
            "controlled_path": True,
            "fresh_output": True,
            "fresh_session_piped_stdio": True,
            "public_synthetic_identity": True,
            "recipient_v1_pin_fixture": True,
            "value_free_environment": True,
        }
        result["pin"] = {
            "age_exit_before_cleanup": category(pin_rc),
            "request_sent": trace.get("request") is True,
            "client_response": enum_value(trace.get("response"), ("fail", "ok", "eof")),
            "error_ack": enum_value(trace.get("ack"), ("ok", "fail", "eof")),
            "plugin_terminal_before_cleanup": enum_value(
                trace.get("terminal"), ("eof", "sigint", "stanza")
            ),
            "stdout": "empty" if not stdout else "nonempty",
            "warning": b"could not read value for age-plugin-test:" in stderr,
            "no_terminal_reason": (
                b"standard input is not a terminal" in stderr
                and b"/dev/tty is not available" in stderr
            ),
            "plugin_error": b"test plugin: synthetic plugin failure" in stderr,
            "prompt_on_stdout": b"Enter synthetic PIN:" in stdout,
            "prompt_on_stderr": b"Enter synthetic PIN:" in stderr,
        }

        with open(mode, "w", encoding="ascii") as f:
            f.write("cancel")
        p, state, threads = spawn(age, identity, env, output_dir)
        ready_end = time.monotonic() + 4
        trace = None
        while time.monotonic() < ready_end:
            overflow, _, _ = snapshot(state)
            if overflow or p.poll() is not None:
                break
            trace = load_trace(os.path.join(output_dir, "cancel.json"))
            if fixture_ok(trace) and trace.get("ready") is True:
                break
            time.sleep(0.02)
        if not fixture_ok(trace) or trace.get("ready") is not True:
            raise Fail("cancel_premise")

        os.kill(p.pid, signal.SIGINT)
        exit_end = time.monotonic() + 3
        cancel_rc = None
        while time.monotonic() < exit_end:
            overflow, _, _ = snapshot(state)
            cancel_rc = p.poll()
            if overflow or cancel_rc is not None:
                break
            time.sleep(0.02)
        age_exited = cancel_rc is not None

        trace_end = time.monotonic() + 1
        while time.monotonic() < trace_end:
            trace = load_trace(os.path.join(output_dir, "cancel.json"))
            if trace and trace.get("terminal") in ("eof", "sigint", "stanza"):
                break
            time.sleep(0.02)
        event = enum_value(
            trace.get("terminal") if isinstance(trace, dict) else None,
            ("eof", "sigint", "stanza"),
        )

        group_clean = cleanup_group(p)
        for thread in threads:
            thread.join(1)
        overflow, stdout, stderr = snapshot(state)
        if overflow or any(thread.is_alive() for thread in threads):
            raise Fail("cancel_bound")
        if not group_clean:
            raise Fail("cancel_cleanup")

        result["premises"]["recipient_v1_cancel_fixture"] = True
        result["cancel"] = {
            "signal_target": "age_only",
            "age_exited_before_cleanup": age_exited,
            "age_exit_before_cleanup": category(cancel_rc),
            "plugin_event_before_cleanup": event,
            "plugin_exited_cooperatively_before_cleanup": event in ("eof", "sigint"),
            "stdout": "empty" if not stdout else "nonempty",
            "stderr": "empty" if not stderr else "nonempty",
        }

        if hash_age(age) != AGE_SHA:
            raise Fail("age_digest_after")
        result["premises"]["age_digest_after"] = True
        result["probe_status"] = "complete"
        result["failure_class"] = "none"
    except Fail as e:
        result["failure_class"] = str(e)
    except Exception:
        result["failure_class"] = "internal"
    finally:
        signal.alarm(0)
        processes_clean = True
        for child in children:
            if not cleanup_group(child):
                processes_clean = False
        captures_clean = True
        for threads in captures:
            for thread in threads:
                thread.join(1)
            if any(thread.is_alive() for thread in threads):
                captures_clean = False
        fixtures_removed = purge_output(output_dir)
        result["cleanup"] = {
            "owned_process_groups": processes_clean,
            "capture_threads": captures_clean,
            "fixtures_removed": fixtures_removed,
            "retained_only_observations": fixtures_removed,
        }
        if not (processes_clean and captures_clean and fixtures_removed):
            result["probe_status"] = "error"
            result["failure_class"] = "cleanup"
        atomic_json(os.path.join(output_dir, "observations.json"), result)

    return 0 if result["probe_status"] == "complete" else 1


raise SystemExit(main())
