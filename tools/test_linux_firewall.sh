#!/bin/sh
# Run compiled Go tests only in disposable network/mount namespaces.
set -eu
[ "$(id -u)" = 0 ] || { echo "root required" >&2; exit 1; }
nm_test=$(realpath "$1")
nm_dnsmasq=${2:-}
[ -x "$nm_test" ]
unshare -n env NM_FW_NETNS_TEST=1 "$nm_test" -test.v -test.run='^(TestNFTKernelAtomicity|TestStrictServiceTraffic)$' -test.timeout=120s
if [ -n "$nm_dnsmasq" ]; then
    nm_dnsmasq=$(realpath "$nm_dnsmasq")
    unshare -n env NM_FW_NETNS_TEST=1 NM_DHCP_SERVER="$nm_dnsmasq" "$nm_test" -test.v -test.run='^TestActualDHCPRenewal$' -test.timeout=70s
fi
nm_tmp=$(mktemp -d /tmp/nm-ufw-test.XXXXXX)
trap 'rm -rf "$nm_tmp"' EXIT HUP INT TERM
cp -a /etc/ufw "$nm_tmp/ufw"
cp /etc/default/ufw "$nm_tmp/default-ufw"
unshare -m -n sh -eu -c '
    mount --make-rprivate /
    mount --bind "$1/ufw" /etc/ufw
    mount --bind "$1/default-ufw" /etc/default/ufw
    exec env NM_FW_UFW_TEST=1 "$2" -test.v -test.run="^TestUFWReload$" -test.timeout=90s
' sh "$nm_tmp" "$nm_test"
