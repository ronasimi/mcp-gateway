#!/bin/sh
set -eu

# Runs only while building the image. No package installs on first tool use.
arch=$(dpkg --print-architecture)
case "$arch" in
  amd64)
    osquery_sha=1431a9a6394657eba3cdd3476a462a6fe9721fc3664a70f23efcf7e37816787a
    radare_sha=91e64c672e65521758c0deb0f70d98ac90f0a78eb654d8bd0d894dd5735130e3
    ;;
  *) echo 'The complete security image currently requires amd64 (Rapid7 packaged Metasploit).' >&2; exit 1 ;;
esac
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cd "$tmp"
curl -fLsS --retry 3 "https://github.com/osquery/osquery/releases/download/5.23.1/osquery_5.23.1-1.linux_${arch}.deb" -o osquery.deb
printf '%s  %s\n' "$osquery_sha" osquery.deb | sha256sum -c -
curl -fLsS --retry 3 "https://github.com/radareorg/radare2/releases/download/6.1.8/radare2_6.1.8_${arch}.deb" -o radare2.deb
printf '%s  %s\n' "$radare_sha" radare2.deb | sha256sum -c -
apt-get update
apt-get install -y --no-install-recommends ./osquery.deb ./radare2.deb

curl -fLsS --retry 3 "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_${arch}.zip" -o subfinder.zip
curl -fLsS --retry 3 "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_checksums.txt" -o checksums.txt
expected=$(awk -v f="subfinder_${SUBFINDER_VERSION}_linux_${arch}.zip" '$2==f {print $1}' checksums.txt)
test -n "$expected"
printf '%s  %s\n' "$expected" subfinder.zip | sha256sum -c -
unzip -q subfinder.zip subfinder
install -m 0755 subfinder /usr/local/bin/subfinder

# The Exploit-DB data set is a build-time snapshot; its exact commit is recorded.
git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb
git -C /opt/exploitdb rev-parse HEAD > /opt/exploitdb/SNAPSHOT_COMMIT
rm -rf /opt/exploitdb/.git
ln -s /opt/exploitdb/searchsploit /usr/local/bin/searchsploit
cp /opt/exploitdb/.searchsploit_rc /etc/searchsploit_rc

# Key is vendored from Rapid7's official omnibus installer. APT verifies packages.
gpg --batch --dearmor -o /usr/share/keyrings/metasploit-framework.gpg /opt/mcp/metasploit-release.asc
printf '%s\n' 'deb [arch=amd64 signed-by=/usr/share/keyrings/metasploit-framework.gpg] https://downloads.metasploit.com/data/releases/metasploit-framework/apt lucid main' > /etc/apt/sources.list.d/metasploit-framework.list
apt-get update
apt-get install -y --no-install-recommends "metasploit-framework=${METASPLOIT_VERSION}"
npm install -g --omit=dev "firecrawl-cli@${FIRECRAWL_CLI_VERSION}"
npm cache clean --force
rm -rf /var/lib/apt/lists/*
for binary in nmap firecrawl ffuf subfinder searchsploit sqlmap msfconsole nc socat jq tshark suricata osqueryi yara r2; do
  command -v "$binary"
done
