#!/usr/bin/env python3
"""Rehearse browser custody against source or an isolated installed SAB wheel.

Issuer/witness SigningKeys exist only in this Python process. Node sees public
policy, signed grants, and receipts. There are no test routes in the HTTP app.
Requires Node 22, an explicit Playwright package with Chromium installed, and
Python runtime dependencies plus the development dependency jsonschema. Run an
installed wheel's interpreter with -I -B and --installed from outside checkout.
Only root receipts, public observations and screenshots are uploadable; browser
profiles, synthetic database and the local system key remain private runtime.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from typing import Any
from urllib.parse import quote

DEFAULT_SOURCE = Path(__file__).resolve().parents[1]
DEFAULT_RUNTIME = Path.home() / '.dharma' / 'sab' / 'browser-rehearsals'
MAX_JSONL_BYTES = 65536
MAX_COMMANDS = 128
MAX_OBSERVATION_BYTES = 8 * 1024 * 1024
PARTICIPANT_ASSETS = ('participant.css', 'participant.js', 'participant_crypto.js')
CHILD = '''
import json, pathlib, sys
import agora
package = pathlib.Path(agora.__file__).resolve().parent
source = pathlib.Path(sys.argv[3]).resolve()
if sys.argv[2] == 'installed':
    if not sys.flags.isolated or not sys.dont_write_bytecode or not package.is_relative_to(pathlib.Path(sys.prefix).resolve()) or package.is_relative_to(source):
        raise RuntimeError('installed child imported Agora outside its environment')
elif package != source / 'agora':
    raise RuntimeError('source child imported a different Agora package')
pathlib.Path('server-import.json').write_text(json.dumps({'package':str(package),'python_prefix':sys.prefix,'isolated':bool(sys.flags.isolated),'dont_write_bytecode':sys.dont_write_bytecode}) + '\\n')
import agora.app as application
import uvicorn
uvicorn.run(application.app, fd=int(sys.argv[1]), access_log=False, log_level='warning', timeout_keep_alive=1, timeout_graceful_shutdown=3)
'''


def encoded(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def write_json(path: Path, value: Any) -> None:
    path.write_bytes(encoded(value))


def strict_object(raw: bytes, limit: int = MAX_JSONL_BYTES) -> dict:
    if len(raw) > limit:
        raise ValueError('JSON document exceeds its bounded size')
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise ValueError('duplicate JSON member')
            out[key] = value
        return out
    def constant(_):
        raise ValueError('nonfinite JSON constant')
    def finite(number):
        value = float(number)
        if not math.isfinite(value):
            raise ValueError('nonfinite JSON number')
        return value
    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant, parse_float=finite)
    if not isinstance(value, dict):
        raise ValueError('bridge command must be an object')
    return value


class PolicyEnvironment:
    """Fixture-compatible setenv collector; never modify ambient environment."""
    def __init__(self):
        self.values: dict[str, str] = {}

    def setenv(self, name: str, value: str) -> None:
        self.values[name] = value


class Bridge:
    def __init__(self, args):
        self.args = args
        self.source = args.source_root.resolve(strict=True)
        self.script = args.node_script.resolve(strict=True)
        self.fixtures = args.fixtures_root.resolve(strict=True)
        for name in ('authority_fixtures.py', 'keycontrol_fixtures.py'):
            if not (self.fixtures / name).is_file():
                raise RuntimeError(f'missing explicit synthetic fixture: {name}')
        if not (self.source / 'pyproject.toml').is_file() or not (self.source / 'agora').is_dir():
            raise RuntimeError('--source-root must identify the source checkout')
        # Installed mode never adds the source or fixture directory to sys.path.
        # Load these two trusted fixture files explicitly, allowing their Agora
        # imports to resolve only to the selected installed environment.
        if args.installed:
            if not sys.flags.isolated or not sys.dont_write_bytecode:
                raise RuntimeError('--installed requires the installed interpreter with -I -B')
            if Path.cwd().resolve().is_relative_to(self.source):
                raise RuntimeError('--installed must run from outside the source checkout')
            if Path(args.python).absolute() != Path(sys.executable).absolute():
                raise RuntimeError('--installed must use the current installed Python interpreter')
        else:
            sys.path.insert(0, str(self.source))
        import agora
        self.package = Path(agora.__file__).resolve().parent
        if args.installed:
            if not self.package.is_relative_to(Path(sys.prefix).resolve()) or self.package.is_relative_to(self.source):
                raise RuntimeError('Agora was not imported from the installed environment')
        elif self.package != self.source / 'agora':
            raise RuntimeError('source rehearsal imported a different Agora package')
        if args.runtime_root:
            self.root = args.runtime_root.resolve()
            if self.root.is_relative_to(self.source) or self.root.is_relative_to(self.package):
                raise RuntimeError('runtime output must stay outside source and installed package')
            self.root.mkdir(parents=True, exist_ok=False)
        else:
            DEFAULT_RUNTIME.mkdir(parents=True, exist_ok=True)
            self.root = Path(tempfile.mkdtemp(prefix='run-', dir=DEFAULT_RUNTIME))
        self.root.chmod(0o700)
        self.server = None
        self.node = None
        self.client = None
        self.logs = []
        self.events: list[dict] = []
        self.phase = 'initializing'
        self.receipt = {
            'schema': 'sab.synthetic_browser_bridge_receipt.v1',
            'runtime_root': str(self.root), 'source_root': str(self.source),
            'node_script': str(self.script), 'python': args.python,
            'playwright_module': str(args.playwright_module),
            'playwright_version': args.playwright_version,
            'mode': 'installed' if args.installed else 'source',
            'launcher_agora_package': str(self.package),
            'runtime_dependencies_only': False,
            'verification_dependencies': ['jsonschema', 'Node 22', 'Playwright with Chromium'],
            'source_usage': 'explicit fixture files, public schemas and asset byte comparisons' if args.installed else 'source application and explicit synthetic fixtures',
            'issuer_private_key_custody': 'memory_only_in_launcher',
            'participant_signing': 'Node/browser only; no launcher-held participant key',
            'grant_transport': 'POST /api/v1/authority/leases with real fixture signatures',
            'test_http_backdoor': False, 'operations': self.events,
            'server_processes': [], 'complete': False,
        }
        self.socket = socket.socket()
        self.socket.bind(('127.0.0.1', 0))
        self.socket.listen(128)
        self.port = self.socket.getsockname()[1]
        self.origin = f'http://127.0.0.1:{self.port}'
        self.receipt['origin'] = self.origin

        # Import only fixture utilities and pure signing/model helpers here.
        # The ASGI app imports solely in the separate sanitized child process.
        for name in ('keycontrol_fixtures', 'authority_fixtures'):
            spec = importlib.util.spec_from_file_location(name, self.fixtures / f'{name}.py')
            if spec is None or spec.loader is None:
                raise RuntimeError('explicit fixture module unavailable')
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
        self.fixture_module = sys.modules['authority_fixtures']
        self.policy_env = PolicyEnvironment()
        self.authority = self.fixture_module.provision_authority_policy(self.root, self.policy_env, audience=self.origin)
        (self.root / 'empty-seed-claims.json').write_text('[]\n')
        self.env = {
            'PATH': os.defpath,
            'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONUNBUFFERED': '1',
            'SAB_PUBLIC_MODE': 'local', 'SAB_IDENTITY_ORIGIN': self.origin,
            'SAB_DB_PATH': str(self.root / 'synthetic.db'),
            'SAB_AUTHORITY_DB_PATH': str(self.root / 'synthetic.db'),
            'SAB_SPARK_DB_PATH': str(self.root / 'synthetic.db'),
            'SAB_SYSTEM_WITNESS_KEY': str(self.root / 'synthetic-system.key'),
            'SAB_JWT_SECRET': str(self.root / 'synthetic-jwt-unused'),
            'SAB_SEED_CLAIMS_PATH': str(self.root / 'empty-seed-claims.json'),
            'SAB_LANGUAGE_WOMB_LANE_DIR': str(self.root / 'absent-inputs'),
            **self.policy_env.values,
        }
        if not args.installed:
            self.env['PYTHONPATH'] = str(self.source)
        self.receipt['server_environment'] = self.env
        self.receipt['public_policy_sha256'] = self.authority.policy_hash
        self.receipt['public_issuer_id'] = self.authority.issuer_id
        self.receipt['public_witness_id'] = self.authority.witness_id
        self.receipt['fixture_sha256'] = {name: hashlib.sha256((self.fixtures / name).read_bytes()).hexdigest()
                                         for name in ('authority_fixtures.py', 'keycontrol_fixtures.py')}
        self.package_before = self.package_digest() if args.installed else None

    def package_digest(self):
        return {str(path.relative_to(self.package)): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in self.package.rglob('*') if path.is_file()}

    def save(self):
        write_json(self.root / 'bridge-receipt.json', self.receipt)

    @staticmethod
    def stop_owned(process) -> None:
        if process is None:
            return
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            if process.poll() is None:
                process.wait(timeout=5)
            return
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
        # A crashed Node leader may leave Chromium children in its owned group.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def start_server(self):
        log = (self.root / 'server.log').open('ab')
        self.logs.append(log)
        flags = ['-I', '-B'] if self.args.installed else ['-B']
        argv = [self.args.python, *flags, '-c', CHILD, str(self.socket.fileno()),
                'installed' if self.args.installed else 'source', str(self.source)]
        self.server = subprocess.Popen(argv, cwd=self.root, env=self.env, stdin=subprocess.DEVNULL,
                                       stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
                                       pass_fds=(self.socket.fileno(),))
        self.receipt['server_processes'].append({'pid': self.server.pid, 'argv': argv})
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if self.server.poll() is not None:
                raise RuntimeError('synthetic server exited; inspect server.log')
            try:
                with httpx.Client(trust_env=False, follow_redirects=False, timeout=0.5) as check:
                    response = check.get(self.origin + '/healthz')
                    if response.status_code == 200:
                        self.client = httpx.Client(base_url=self.origin, trust_env=False,
                                                   follow_redirects=False, timeout=10)
                        self.receipt['server_import'] = strict_object((self.root / 'server-import.json').read_bytes())
                        self.save()
                        return
            except httpx.HTTPError:
                pass
            time.sleep(0.05)
        raise RuntimeError('synthetic server readiness deadline exceeded')

    def restart(self):
        old_pid = self.server.pid
        if self.client:
            self.client.close()
            self.client = None
        self.stop_owned(self.server)
        self.start_server()
        return {'ok': True, 'operation': 'restart', 'origin': self.origin,
                'previous_pid': old_pid, 'server_pid': self.server.pid}

    def command(self, payload: dict) -> dict:
        if len(self.events) >= MAX_COMMANDS:
            raise ValueError('synthetic bridge command limit exceeded')
        operation = payload.get('operation')
        if operation == 'restart':
            if set(payload) != {'operation'}:
                raise ValueError('restart accepts exactly operation')
            response = self.restart()
        elif operation == 'grant':
            if set(payload) != {'operation', 'subject_id', 'seed_id', 'actions'}:
                raise ValueError('grant requires exactly operation,subject_id,seed_id,actions')
            subject, seed, actions = payload['subject_id'], payload['seed_id'], payload['actions']
            if (not isinstance(subject, str)
                    or re.fullmatch(r'agent_[A-Za-z0-9_.:-]{2,154}', subject) is None):
                raise ValueError('invalid synthetic grant subject')
            if (not isinstance(seed, str) or not seed or len(seed) > 200
                    or any(ord(char) < 33 for char in seed)):
                raise ValueError('invalid synthetic grant seed')
            if (not isinstance(actions, list) or not actions
                    or any(not isinstance(action, str) for action in actions)
                    or len(actions) != len(set(actions))
                    or not set(actions) <= set(self.fixture_module.ACTIONS)):
                raise ValueError('invalid synthetic grant actions')
            grant = self.authority.issue(self.client, subject, seed, actions)
            response = {'ok': True, 'operation': 'grant', 'subject_id': subject, 'seed_id': seed,
                        'grant': grant, 'reference': self.fixture_module.reference_for(grant)}
            write_json(self.root / f'grant-{len(self.events) + 1}.json', response)
        else:
            raise ValueError('unsupported bridge operation')
        self.events.append({'request': payload, 'ok': response['ok'],
                            'lease_id': response.get('grant', {}).get('lease_id')})
        self.save()
        return response

    def send(self, payload: dict):
        raw = encoded(payload)
        if len(raw) > MAX_JSONL_BYTES:
            raise ValueError('bridge reply exceeds its bounded size')
        remaining = memoryview(raw)
        deadline = time.monotonic() + 10
        with selectors.DefaultSelector() as selector:
            selector.register(self.node.stdin, selectors.EVENT_WRITE)
            while remaining:
                if time.monotonic() >= deadline:
                    raise RuntimeError('Node did not consume its bounded bridge reply')
                if selector.select(timeout=0.25):
                    try:
                        count = os.write(self.node.stdin.fileno(), remaining)
                        if count <= 0:
                            raise RuntimeError('Node bridge input closed')
                        remaining = remaining[count:]
                    except BlockingIOError:
                        pass

    def run_node(self):
        stderr = (self.root / 'node-stderr.log').open('wb')
        self.logs.append(stderr)
        node_env = {
            'PATH': os.pathsep.join((str(Path(self.args.node).parent), os.defpath)),
            'HOME': str(Path.home()),
            'SAB_REHEARSAL_ORIGIN': self.origin,
            'SAB_REHEARSAL_OUTPUT_DIR': str(self.root),
            'SAB_PLAYWRIGHT_MODULE': str(self.args.playwright_module.resolve()),
            'SAB_REHEARSAL_BRIDGE': 'jsonl-v1',
        }
        if self.args.browser_cache:
            node_env['PLAYWRIGHT_BROWSERS_PATH'] = str(self.args.browser_cache)
        self.node = subprocess.Popen([self.args.node, str(self.script), *self.args.node_arg],
                                     cwd=self.root, env=node_env, stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=stderr, start_new_session=True)
        os.set_blocking(self.node.stdin.fileno(), False)
        self.receipt['node_pid'] = self.node.pid
        self.send({'ok': True, 'operation': 'ready', 'origin': self.origin,
                   'output_dir': str(self.root), 'server_pid': self.server.pid,
                   'policy_hash': self.authority.policy_hash})
        deadline = time.monotonic() + self.args.node_timeout
        pending = bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(self.node.stdout, selectors.EVENT_READ)
            while True:
                if time.monotonic() >= deadline:
                    raise RuntimeError('Node rehearsal deadline exceeded')
                ready = selector.select(timeout=0.25)
                if ready:
                    chunk = os.read(self.node.stdout.fileno(), 65536)
                    if not chunk:
                        if pending.strip():
                            raise ValueError('unterminated bridge JSONL command')
                        break
                    pending.extend(chunk)
                    if len(pending) > MAX_JSONL_BYTES:
                        raise ValueError('bridge JSONL command exceeds 65536 bytes')
                    while b'\n' in pending:
                        line, _, rest = pending.partition(b'\n')
                        pending = bytearray(rest)
                        if not line.strip():
                            continue
                        request = strict_object(bytes(line))
                        try:
                            reply = self.command(request)
                        except Exception as exc:
                            operation = request.get('operation') if request.get('operation') in ('grant', 'restart') else 'unsupported'
                            self.events.append({'operation': operation, 'ok': False, 'error_code': 'bridge_command_failed'})
                            self.save()
                            self.send({'ok': False, 'operation': operation,
                                       'error': 'bridge_command_failed', 'detail': 'Synthetic bridge command failed; inspect its receipt.'})
                            raise
                        self.send(reply)
                if self.node.poll() is not None and not ready:
                    break
        code = self.node.wait(timeout=5)
        self.receipt['node_exit_code'] = code
        if code != 0:
            raise RuntimeError('Node rehearsal failed; inspect node-stderr.log')

    def validate_browser_records(self):
        path = self.root / 'browser-observations.json'
        if not path.is_file() or path.stat().st_size > MAX_OBSERVATION_BYTES:
            raise RuntimeError('missing or oversized browser observation')
        observation = strict_object(path.read_bytes(), MAX_OBSERVATION_BYTES)
        if (observation.get('schema') != 'sab.browser_rehearsal_observation.v2'
                or observation.get('request_body_custody') != 'memory_only'
                or observation.get('packet_digest_canonicalization') != 'json-sort-keys-compact-v1'
                or observation.get('sanitizer_regression_passed') is not True
                or observation.get('complete') is not True or observation.get('errors')):
            raise RuntimeError('browser did not report a complete clean flow')
        rows = observation.get('requests')
        if not isinstance(rows, list) or len(rows) > 4096:
            raise RuntimeError('browser request observations are missing or unbounded')
        validated = []
        for row in rows:
            fields = {'method', 'route', 'origin_relation', 'resource_type', 'elapsed_ms'}
            if (not isinstance(row, dict) or not fields <= set(row) or set(row) - fields - {'packet'}
                    or row['origin_relation'] not in ('same-origin', 'other-origin')
                    or type(row['elapsed_ms']) is not int or row['elapsed_ms'] < 0):
                raise RuntimeError('browser request observation contains unapproved fields')
            if 'packet' not in row:
                continue
            packet = row['packet']
            if not isinstance(packet, dict) or set(packet) != {'kind', 'identifier', 'canonical_sha256'}:
                raise RuntimeError('browser packet observation contains unapproved fields')
            kind, identifier = packet['kind'], packet['identifier']
            if (row['method'] != 'POST' or row['origin_relation'] != 'same-origin' or kind not in ('seed', 'challenge')
                    or row['route'] != ('/api/v1/seeds' if kind == 'seed' else '/api/v1/seeds/:seed_id/challenges')
                    or not isinstance(identifier, str) or re.fullmatch(r'sab_' + kind + r'_[A-Za-z0-9_.:-]{3,128}', identifier) is None
                    or not isinstance(packet['canonical_sha256'], str) or re.fullmatch(r'[0-9a-f]{64}', packet['canonical_sha256']) is None):
                raise RuntimeError('browser packet observation has invalid public identifiers')
            response = self.client.get(f'/api/v1/{"seeds" if kind == "seed" else "challenges"}/{quote(identifier, safe="")}')
            if response.status_code != 200:
                raise RuntimeError(f'browser {kind} was not durably accepted')
            stored = strict_object(response.content, 512 * 1024).get(f'{kind}_packet')
            accepted_digest = hashlib.sha256(encoded(stored).rstrip(b'\n')).hexdigest()
            if accepted_digest != packet['canonical_sha256']:
                raise RuntimeError(f'accepted {kind} differs from the actual browser command')
            schema_name = f'sab.{kind}_packet.v1.schema.json'
            schema_bytes = (self.source / 'nodes' / 'schemas' / schema_name).read_bytes()
            served = self.client.get('/schemas/' + schema_name)
            if served.status_code != 200 or served.content != schema_bytes:
                raise RuntimeError(f'public {kind} schema does not match source bytes')
            validator = jsonschema.Draft202012Validator(strict_object(schema_bytes), format_checker=jsonschema.FormatChecker())
            validator.check_schema(validator.schema)
            errors = list(validator.iter_errors(stored))
            if errors:
                raise RuntimeError(f'accepted browser {kind} failed the declared JSON schema')
            validated.append({'kind': kind, 'identifier': identifier, 'accepted_packet_matches_browser': True,
                              'match_basis': 'canonical_sha256_from_memory_only_request_capture',
                              'schema': schema_name, 'schema_sha256': hashlib.sha256(schema_bytes).hexdigest(),
                              'packet_sha256': accepted_digest,
                              'validation': 'jsonschema Draft202012Validator with format checking'})
        if {row['kind'] for row in validated} != {'seed', 'challenge'}:
            raise RuntimeError('browser flow must submit both an accepted seed and challenge')
        self.receipt['accepted_packet_schema_validation'] = validated
        assets = {}
        for name in PARTICIPANT_ASSETS:
            response = self.client.get('/static/' + name)
            canonical = (self.source / 'agora' / 'static' / name).read_bytes()
            if response.status_code != 200 or response.content != canonical:
                raise RuntimeError(f'participant asset does not match source: {name}')
            installed = (self.package / 'static' / name).read_bytes()
            if response.content != installed:
                raise RuntimeError(f'participant asset was not served from selected package: {name}')
            assets[name] = hashlib.sha256(response.content).hexdigest()
        self.receipt['served_participant_assets_sha256'] = assets

    def run(self):
        try:
            self.phase = 'server_startup'
            self.start_server()
            self.phase = 'issuer_and_witness_enrollment'
            self.authority.enroll(self.client)
            self.receipt['issuer_and_witness_enrolled_via_http'] = True
            self.save()
            self.phase = 'browser_flow'
            self.run_node()
            self.phase = 'accepted_packet_validation'
            self.validate_browser_records()
            if self.args.installed:
                self.phase = 'installed_package_integrity'
                if self.package_before != self.package_digest():
                    raise RuntimeError('installed browser rehearsal changed package bytes')
                self.receipt['installed_package_unchanged'] = True
            self.receipt['complete'] = True
        except BaseException:
            self.receipt['failure'] = {'code': 'browser_rehearsal_failed', 'phase': self.phase}
            raise
        finally:
            self.stop_owned(self.node)
            if self.client:
                self.client.close()
            self.stop_owned(self.server)
            self.socket.close()
            self.receipt['owned_node_stopped'] = self.node is None or self.node.poll() is not None
            self.receipt['owned_server_stopped'] = self.server is None or self.server.poll() is not None
            with socket.socket() as sock:
                sock.settimeout(1)
                self.receipt['server_port_closed'] = sock.connect_ex(('127.0.0.1', self.port)) != 0
            self.save()
            for log in self.logs:
                log.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, default=DEFAULT_SOURCE)
    parser.add_argument('--fixtures-root', type=Path, help='Defaults to <source-root>/tests; explicit fixture files only')
    parser.add_argument('--node-script', type=Path, help='Defaults to <source-root>/tests/browser/participant_flow.mjs')
    parser.add_argument('--playwright-module', type=Path, default=os.environ.get('SAB_PLAYWRIGHT_MODULE'),
                        help='Explicit installed Playwright package directory (or SAB_PLAYWRIGHT_MODULE)')
    parser.add_argument('--browser-cache', type=Path, default=os.environ.get('PLAYWRIGHT_BROWSERS_PATH'),
                        help='Explicit Chromium cache (or PLAYWRIGHT_BROWSERS_PATH); otherwise Playwright default')
    parser.add_argument('--installed', action='store_true', help='Prove installed-wheel imports; requires invocation with -I -B')
    parser.add_argument('--runtime-root', type=Path, help='Must not already exist')
    parser.add_argument('--python', default=sys.executable)
    parser.add_argument('--node', default=shutil.which('node'), help='Node 22 executable; defaults to shutil.which(node)')
    parser.add_argument('--node-timeout', type=int, default=240)
    parser.add_argument('--node-arg', action='append', default=[])
    args = parser.parse_args()
    args.source_root = args.source_root.expanduser().resolve()
    args.fixtures_root = args.fixtures_root or args.source_root / 'tests'
    args.node_script = args.node_script or args.source_root / 'tests' / 'browser' / 'participant_flow.mjs'
    if not args.node or not 1 <= args.node_timeout <= 900:
        parser.error('Node 22 is required and --node-timeout must be between 1 and 900 seconds')
    args.node = shutil.which(args.node)
    if args.node is None:
        parser.error('--node executable could not be resolved')
    probe = subprocess.run([args.node, '--version'], capture_output=True, text=True, timeout=10, check=True)
    if re.fullmatch(r'v22\.\d+\.\d+\s*', probe.stdout) is None:
        parser.error('this rehearsal requires Node 22')
    if args.playwright_module is None:
        parser.error('supply --playwright-module or SAB_PLAYWRIGHT_MODULE; install Playwright and Chromium explicitly')
    args.playwright_module = args.playwright_module.expanduser().resolve()
    try:
        package = strict_object((args.playwright_module / 'package.json').read_bytes())
        if package.get('name') != 'playwright' or not (args.playwright_module / 'index.js').is_file():
            raise ValueError('not the Playwright package')
        args.playwright_version = package['version']
    except (OSError, ValueError, KeyError):
        parser.error('--playwright-module must point to an installed Playwright package directory')
    if args.browser_cache:
        args.browser_cache = args.browser_cache.expanduser().resolve()
    browser_env = {**os.environ}
    if args.browser_cache:
        browser_env['PLAYWRIGHT_BROWSERS_PATH'] = str(args.browser_cache)
    browser_probe = subprocess.run([args.node, '-e',
        "const p=require(process.argv[1]); const f=require('node:fs'); if(!f.existsSync(p.chromium.executablePath())) process.exit(2);",
        str(args.playwright_module)], capture_output=True, timeout=15, env=browser_env)
    if browser_probe.returncode:
        parser.error('Playwright Chromium is unavailable; explicitly install Chromium with the selected Playwright package/cache')
    global httpx, jsonschema
    try:
        import httpx
        import jsonschema
        import nacl.signing
        import uvicorn
    except ImportError as exc:
        parser.error(f'missing Python dependency {exc.name}; install wheel/runtime requirements plus jsonschema for this development rehearsal')
    args.python = shutil.which(args.python)
    if args.python is None:
        parser.error('--python executable could not be resolved')
    bridge = Bridge(args)
    def terminated(_signal, _frame):
        raise SystemExit('rehearsal terminated; cleaning up owned processes')
    signal.signal(signal.SIGTERM, terminated)
    failed = False
    try:
        bridge.run()
    except BaseException:
        # Raw assertion values, response bodies and exception messages remain
        # out of both the public receipt and CI's launcher stdout/stderr.
        failed = True
    finally:
        print(json.dumps({'runtime_root': str(bridge.root),
                          'receipt': str(bridge.root / 'bridge-receipt.json'),
                          'complete': bridge.receipt['complete']}))
    if failed:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
