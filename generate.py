#!/usr/bin/env python3

import argparse
import datetime
import json
import re
import sys
import urllib.request
from pathlib import Path
from xml.sax.saxutils import escape

SOURCE_URL = "https://raw.githubusercontent.com/magicsword-io/LOLDrivers/main/loldrivers.io/content/api/drivers.json"
POLICY_ID = "{2fcdc60b-02ca-4907-a413-a927fef4a149}"
PLATFORM_ID = "{2E07F7E4-194C-4D20-B7C9-6F44A6C5A234}"
NAMESPACE = "urn:schemas-microsoft-com:sipolicy"
RULE_ID_PREFIX = "ID_DENY_LOL_"
RULE_ID_LENGTH = 24

BASE_OPTIONS = [
    "Enabled:Unsigned System Integrity Policy",
    "Enabled:Advanced Boot Options Menu",
    "Enabled:Update Policy No Reboot",
    "Disabled:Flight Signing",
]
AUDIT_OPTION = "Enabled:Audit Mode"

HEX_SHA1 = re.compile(r"^[0-9a-fA-F]{40}$")
HEX_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")


def load_source(source):
    if source.startswith("http://") or source.startswith("https://"):
        with urllib.request.urlopen(source, timeout=120) as response:
            return json.loads(response.read().decode("utf-8"))
    return json.loads(Path(source).read_text(encoding="utf-8"))


def clean_name(sample):
    for key in ("Filename", "OriginalFilename", "InternalName"):
        value = (sample.get(key) or "").strip()
        if value:
            name = re.sub(r"[^A-Za-z0-9._ -]", "", value)[:60].strip()
            if name:
                return name
    return "unknown.sys"


def collect(data):
    rules = {}
    skipped = []
    for entry in data:
        entry_id = entry.get("Id", "")
        for sample in entry.get("KnownVulnerableSamples", []) or []:
            authentihash = sample.get("Authentihash") or {}
            name = clean_name(sample)
            found = False
            for algorithm in ("SHA256", "SHA1"):
                value = (authentihash.get(algorithm) or "").strip()
                if algorithm == "SHA256" and not HEX_SHA256.match(value):
                    continue
                if algorithm == "SHA1" and not HEX_SHA1.match(value):
                    continue
                rules.setdefault(value.upper(), (name, algorithm))
                found = True
            if not found:
                skipped.append((entry_id, name, sample.get("SHA256") or sample.get("SHA1") or ""))
    ordered = sorted(rules.items(), key=lambda item: (len(item[0]), item[0]))
    return ordered, skipped


def rule_ids(ordered):
    short = {}
    for value, _ in ordered:
        short.setdefault(value[:RULE_ID_LENGTH], []).append(value)
    mapping = {}
    for stem, values in short.items():
        if len(values) == 1:
            mapping[values[0]] = RULE_ID_PREFIX + stem
        else:
            for value in values:
                mapping[value] = RULE_ID_PREFIX + value
    return mapping


def build_policy(ordered, version, audit):
    options = list(BASE_OPTIONS)
    if audit:
        options.append(AUDIT_OPTION)

    lines = []
    lines.append('<?xml version="1.0" encoding="utf-8"?>')
    lines.append('<SiPolicy xmlns="%s" PolicyType="Base Policy">' % NAMESPACE)
    lines.append("  <VersionEx>%s</VersionEx>" % version)
    lines.append("  <PlatformID>%s</PlatformID>" % PLATFORM_ID)
    lines.append("  <Rules>")
    for option in options:
        lines.append("    <Rule>")
        lines.append("      <Option>%s</Option>" % option)
        lines.append("    </Rule>")
    lines.append("  </Rules>")
    lines.append("  <EKUs />")
    lines.append("  <FileRules>")

    mapping = rule_ids(ordered)
    ids = []
    for value, (name, algorithm) in ordered:
        rule_id = mapping[value]
        ids.append(rule_id)
        friendly = escape("%s Hash %s" % (name, algorithm))
        lines.append('    <Deny ID="%s" FriendlyName="%s" Hash="%s" />' % (rule_id, friendly, value))
    lines.append('    <Allow ID="ID_ALLOW_ALL_KMCI" FriendlyName="Allow All" FileName="*" />')
    lines.append('    <Allow ID="ID_ALLOW_ALL_UMCI" FriendlyName="Allow All" FileName="*" />')
    lines.append("  </FileRules>")
    lines.append("  <Signers />")
    lines.append("  <SigningScenarios>")
    lines.append(
        '    <SigningScenario Value="131" ID="ID_SIGNINGSCENARIO_KMCI" FriendlyName="Kernel Mode Signing Scenario">'
    )
    lines.append("      <ProductSigners>")
    lines.append("        <FileRulesRef>")
    for rule_id in ids:
        lines.append('          <FileRuleRef RuleID="%s" />' % rule_id)
    lines.append('          <FileRuleRef RuleID="ID_ALLOW_ALL_KMCI" />')
    lines.append("        </FileRulesRef>")
    lines.append("      </ProductSigners>")
    lines.append("    </SigningScenario>")
    lines.append(
        '    <SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_UMCI" FriendlyName="User Mode Signing Scenario">'
    )
    lines.append("      <ProductSigners>")
    lines.append("        <FileRulesRef>")
    lines.append('          <FileRuleRef RuleID="ID_ALLOW_ALL_UMCI" />')
    lines.append("        </FileRulesRef>")
    lines.append("      </ProductSigners>")
    lines.append("    </SigningScenario>")
    lines.append("  </SigningScenarios>")
    lines.append("  <UpdatePolicySigners />")
    lines.append("  <CiSigners />")
    lines.append("  <HvciOptions>0</HvciOptions>")
    lines.append("  <BasePolicyID>%s</BasePolicyID>" % POLICY_ID)
    lines.append("  <PolicyID>%s</PolicyID>" % POLICY_ID)
    lines.append("</SiPolicy>")
    return "\n".join(lines) + "\n"


def build_skipped(skipped):
    lines = ["# Skipped samples", ""]
    lines.append("These samples carry no usable Authenticode hash in the upstream data set")
    lines.append("and are therefore not covered by the policy.")
    lines.append("")
    lines.append("| LOLDrivers ID | Filename | File hash |")
    lines.append("|---|---|---|")
    for entry_id, name, file_hash in sorted(skipped):
        lines.append("| %s | %s | %s |" % (entry_id, name, file_hash))
    lines.append("")
    lines.append("Total: %d" % len(skipped))
    lines.append("")
    return "\n".join(lines)


def default_version():
    today = datetime.datetime.now(datetime.timezone.utc).date()
    return "1.%d.%d.%d" % (today.year, today.month, today.day)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", default=SOURCE_URL)
    parser.add_argument("--out-dir", default="policies")
    parser.add_argument("--version", default=None)
    args = parser.parse_args()

    version = args.version or default_version()
    data = load_source(args.source)
    ordered, skipped = collect(data)

    if not ordered:
        print("No hashes found - aborting", file=sys.stderr)
        return 1

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "LOLDrivers-Audit.xml").write_text(build_policy(ordered, version, True), encoding="utf-8")
    (out_dir / "LOLDrivers-Enforced.xml").write_text(build_policy(ordered, version, False), encoding="utf-8")
    (out_dir / "skipped.md").write_text(build_skipped(skipped), encoding="utf-8")

    print("Version:     %s" % version)
    print("Deny rules:  %d" % len(ordered))
    print("Skipped:     %d" % len(skipped))
    return 0


if __name__ == "__main__":
    sys.exit(main())
