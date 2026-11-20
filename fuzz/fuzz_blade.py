"""PZ 6 / Issue #10: bounded property-based fuzzing of real Blade parsers.
Run from project root: python fuzz/fuzz_blade.py --seconds 60
No live server, production DB, signing key or update installation is used.
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
import tempfile
import time
import traceback
import types
from collections import Counter
from pathlib import Path
from zipfile import ZipFile, ZIP_STORED

ROOT = Path(__file__).resolve().parents[1]
CRASH_DIR = ROOT / 'fuzz' / 'crashes'
TARGETS = ('json', 'version', 'sbom', 'zip')


def load_updater():
    # The real updater module is used; substitute only local configuration.
    settings = types.ModuleType('settings')
    settings.SERVER_URL = 'http://127.0.0.1:5000'
    settings.APP_VERSION = '1.0.0'
    settings.REQUEST_TIMEOUT = 5
    sys.modules['settings'] = settings
    sys.path.insert(0, str(ROOT / 'client'))
    import updater
    return updater


class Harness:
    def __init__(self, directory):
        self.u = load_updater()
        self.package = directory / 'valid.zip'
        self.incoming = directory / 'fuzz.zip'
        self.deps = {'cryptography': '1.0.0', 'requests': '2.0.0', 'pyside6': '6.0.0'}
        with ZipFile(self.package, 'w', ZIP_STORED) as z:
            z.writestr('requirements.txt', ''.join(f'{n}=={v}\n' for n, v in self.deps.items()))
            z.writestr('README.txt', 'Synthetic input; never installed.')
        self.seeds = {
            'json': b'{"version":"1.1.0","signature":"test"}',
            'version': b'1.1.0',
            'sbom': json.dumps({'bomFormat':'CycloneDX', 'specVersion':'1.5',
                'metadata':{'component':{'name':'Blade','version':'1.1.0'}},
                'components':[{'type':'library','name':n,'version':v} for n,v in self.deps.items()]}).encode('utf-8'),
            'zip': self.package.read_bytes(),
        }

    def invoke(self, target, data):
        """Return accepted/rejected. Only the documented UpdateError is expected."""
        try:
            if target == 'json':
                result = self.u._safe_json(data, 'fuzz input')
                assert isinstance(result, dict), 'JSON parser accepted a non-object'
            elif target == 'version':
                result = self.u.version_tuple(data.decode('utf-8', errors='replace'))
                assert len(result) == 3 and all(type(n) is int and n >= 0 for n in result)
            elif target == 'sbom':
                result = self.u.validate_sbom(data, self.package, '1.1.0')
                assert result['key_dependencies'] == self.deps
            elif target == 'zip':
                self.incoming.write_bytes(data)
                result = self.u.validate_zip_package(self.incoming)
                assert type(result) is int and 1 <= result <= self.u.MAX_ARCHIVE_FILES
            else:
                raise AssertionError('unknown target')
            return True
        except self.u.UpdateError:
            return False

    def smoke(self):
        for name, data in self.seeds.items():
            assert self.invoke(name, data), f'Valid {name} seed rejected'
        for name in TARGETS:
            assert not self.invoke(name, b''), f'Invalid empty {name} seed accepted'


def save_failure(target, data, exc):
    CRASH_DIR.mkdir(parents=True, exist_ok=True)
    path = CRASH_DIR / f'crash-{target}.json'
    path.write_text(json.dumps({'target': target, 'input_base64': base64.b64encode(data).decode('ascii'),
        'exception': type(exc).__name__, 'message': str(exc), 'traceback': traceback.format_exc()},
        ensure_ascii=True, indent=2), encoding='utf-8')
    return path


def run(harness, seconds):
    from hypothesis import given, settings, strategies as st, Phase, HealthCheck
    counts, accepted, rejected, faults = Counter(), Counter(), Counter(), Counter()
    start = time.monotonic()
    next_progress = 10.0

    def inputs(seed):
        # Random bytes, valid seeds, and locally mutated copies. ZIPs are tiny;
        # nothing is extracted or executed by these targets.
        @st.composite
        def mutations(draw):
            buf = bytearray(seed)
            for _ in range(draw(st.integers(1, 6))):
                pos = draw(st.integers(0, len(buf)))
                operation = draw(st.sampled_from(('insert', 'delete', 'replace')))
                value = draw(st.binary(min_size=1, max_size=8))
                if operation == 'insert':
                    buf[pos:pos] = value
                elif operation == 'delete':
                    del buf[pos:pos+len(value)]
                else:
                    buf[pos:pos+len(value)] = value
            return bytes(buf)
        return st.one_of(st.just(seed), st.binary(max_size=1024), mutations())

    def test_batch(target):
        @settings(max_examples=100, deadline=None, database=None,
                  phases=(Phase.generate, Phase.shrink), report_multiple_bugs=False,
                  suppress_health_check=(HealthCheck.too_slow,))
        @given(data=inputs(harness.seeds[target]))
        def property_test(data):
            counts[target] += 1
            try:
                if harness.invoke(target, data):
                    accepted[target] += 1
                else:
                    rejected[target] += 1
            except Exception as exc:
                faults[target] += 1
                save_failure(target, data, exc)
                raise  # Hypothesis attempts shrinking; the last failure is replayable.
        property_test()

    print('Blade fuzzing / Hypothesis', flush=True)
    print(f'Minimum duration: {seconds:g} seconds; targets: {", ".join(TARGETS)}', flush=True)
    failed = set()
    try:
        while time.monotonic() - start < seconds or not all(counts[t] for t in TARGETS):
            for target in TARGETS:
                if target in failed:
                    continue
                try:
                    test_batch(target)
                except Exception:
                    if not faults[target]:
                        raise  # Infrastructure problem, not a target crash.
                    failed.add(target)
                    print(f'FAIL {target}: {CRASH_DIR / ("crash-" + target + ".json")}', flush=True)
                    traceback.print_exc()
                elapsed = time.monotonic() - start
                if elapsed >= next_progress:
                    print(f'PROGRESS {elapsed:.1f}s | inputs={sum(counts.values())} | failures={len(failed)}', flush=True)
                    next_progress = (int(elapsed / 10) + 1) * 10
            if len(failed) == len(TARGETS):
                print('All targets failed; stopping this run.', flush=True)
                break
    except KeyboardInterrupt:
        print('INCOMPLETE: interrupted by user', flush=True)
        return 130
    elapsed = time.monotonic() - start
    print('\n=== FUZZING SUMMARY ===')
    for t in TARGETS:
        print(f'{t:8s}: inputs={counts[t]} accepted={accepted[t]} rejected={rejected[t]} unexpected_exceptions={faults[t]}')
    print(f'Elapsed seconds: {elapsed:.2f}')
    print(f'Total inputs: {sum(counts.values())}')
    print(f'Unexpected exceptions (including shrink attempts): {sum(faults.values())}')
    print(f'Failing targets (not deduplicated defects): {len(failed)}')
    print('RESULT: ' + ('FAIL' if failed else 'PASS' if elapsed >= seconds else 'INCOMPLETE'))
    return int(bool(failed) or elapsed < seconds)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seconds', type=float, default=60)
    parser.add_argument('--smoke', action='store_true', help='Only check the eight fixed seeds')
    parser.add_argument('--replay', type=Path, help='Replay a saved crash JSON')
    args = parser.parse_args()
    if not 0 < args.seconds <= 3600:
        parser.error('--seconds must be in (0, 3600]')
    with tempfile.TemporaryDirectory(prefix='blade-fuzz-') as tmp:
        harness = Harness(Path(tmp))
        harness.smoke()
        print('SMOKE: 8 fixed inputs passed', flush=True)
        if args.smoke:
            return 0
        if args.replay:
            case = json.loads(args.replay.read_text(encoding='utf-8'))
            target = case['target']
            if target not in TARGETS:
                parser.error('Unknown replay target')
            try:
                accepted = harness.invoke(target, base64.b64decode(case['input_base64'], validate=True))
            except Exception:
                traceback.print_exc()
                print('REPLAY: unexpected exception reproduced')
                return 1
            print('REPLAY: controlled ' + ('acceptance' if accepted else 'rejection'))
            return 0
        return run(harness, args.seconds)


if __name__ == '__main__':
    raise SystemExit(main())
