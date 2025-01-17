# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704774");
  script_version("2021-07-26T11:00:54+0000");
  script_cve_id("CVE-2020-12351", "CVE-2020-12352", "CVE-2020-25211", "CVE-2020-25643", "CVE-2020-25645");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:C");
  script_tag(name:"last_modification", value:"2021-07-26 11:00:54 +0000 (Mon, 26 Jul 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-03 13:15:00 +0000 (Tue, 03 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-10-20 03:00:10 +0000 (Tue, 20 Oct 2020)");
  script_name("Debian: Security Advisory for linux (DSA-4774-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4774.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4774-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux'
  package(s) announced via the DSA-4774-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that
may lead to the execution of arbitrary code, privilege escalation,
denial of service or information leaks.

CVE-2020-12351
Andy Nguyen discovered a flaw in the Bluetooth implementation in the
way L2CAP packets with A2MP CID are handled. A remote attacker in
short distance knowing the victim's Bluetooth device address can
send a malicious l2cap packet and cause a denial of service or
possibly arbitrary code execution with kernel privileges.

CVE-2020-12352
Andy Nguyen discovered a flaw in the Bluetooth implementation. Stack
memory is not properly initialised when handling certain AMP
packets. A remote attacker in short distance knowing the victim's
Bluetooth device address can retrieve kernel stack information.

CVE-2020-25211
A flaw was discovered in netfilter subsystem. A local attacker
able to inject conntrack Netlink configuration can cause a denial
of service.

CVE-2020-25643
ChenNan Of Chaitin Security Research Lab discovered a flaw in the
hdlc_ppp module. Improper input validation in the ppp_cp_parse_cr()
function may lead to memory corruption and information disclosure.

CVE-2020-25645
A flaw was discovered in the interface driver for GENEVE
encapsulated traffic when combined with IPsec. If IPsec is
configured to encrypt traffic for the specific UDP port used by the
GENEVE tunnel, tunneled data isn't correctly routed over the
encrypted link and sent unencrypted instead.");

  script_tag(name:"affected", value:"'linux' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (buster), these problems have been fixed in
version 4.19.152-1. The vulnerabilities are fixed by rebasing to the new
stable upstream version 4.19.152 which includes additional bugfixes.

We recommend that you upgrade your linux packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"hyperv-daemons", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libbpf-dev", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libbpf4.19", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcpupower-dev", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcpupower1", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"liblockdep-dev", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"liblockdep4.19", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-8-arm", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-8-s390", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-8-x86", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-config-4.19", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-cpupower", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-doc-4.19", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-12-4kc-malta", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-12-5kc-malta", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-12-686", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-12-686-pae", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-12-all", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-12-all-amd64", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-12-all-arm64", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-12-all-armel", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-12-all-armhf", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-12-all-i386", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-12-all-mips", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-12-all-mips64el", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-12-all-mipsel", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-12-all-ppc64el", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-12-all-s390x", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-12-amd64", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-12-arm64", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-12-armmp", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-12-armmp-lpae", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-12-cloud-amd64", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-12-common", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-12-common-rt", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-12-loongson-3", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-12-marvell", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-12-octeon", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-12-powerpc64le", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-12-rpi", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-12-rt-686-pae", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-12-rt-amd64", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-12-rt-arm64", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-12-rt-armmp", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-12-s390x", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-4kc-malta", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-5kc-malta", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-686", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-686-pae", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-all", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-all-amd64", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-all-arm64", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-all-armel", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-all-armhf", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-all-i386", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-all-mips", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-all-mips64el", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-all-mipsel", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-all-ppc64el", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-all-s390x", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-amd64", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-arm64", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-armmp", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-armmp-lpae", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-cloud-amd64", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-common", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-common-rt", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-loongson-3", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-marvell", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-octeon", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-powerpc64le", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-rpi", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-rt-686-pae", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-rt-amd64", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-rt-arm64", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-rt-armmp", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-s390x", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-4kc-malta", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-5kc-malta", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-686", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-686-pae", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-all", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-all-amd64", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-all-arm64", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-all-armel", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-all-armhf", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-all-i386", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-all-mips", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-all-mips64el", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-all-mipsel", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-all-ppc64el", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-all-s390x", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-amd64", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-arm64", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-armmp", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-armmp-lpae", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-cloud-amd64", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-common", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-common-rt", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-loongson-3", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-marvell", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-octeon", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-powerpc64le", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-rpi", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-rt-686-pae", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-rt-amd64", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-rt-arm64", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-rt-armmp", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-8-s390x", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-9-4kc-malta", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-9-5kc-malta", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-9-686", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-9-686-pae", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-9-all", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-9-all-amd64", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-9-all-arm64", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-9-all-armel", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-9-all-armhf", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-9-all-i386", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-9-all-mips", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-9-all-mips64el", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-9-all-mipsel", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-9-all-ppc64el", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-9-all-s390x", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-9-amd64", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-9-arm64", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-9-armmp", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-9-armmp-lpae", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-9-cloud-amd64", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-9-common", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-9-common-rt", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-9-loongson-3", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-9-marvell", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-9-octeon", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-9-powerpc64le", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-9-rpi", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-9-rt-686-pae", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-9-rt-amd64", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-9-rt-arm64", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-9-rt-armmp", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-9-s390x", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-12-4kc-malta", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-12-4kc-malta-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-12-5kc-malta", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-12-5kc-malta-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-12-686-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-12-686-pae-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-12-686-pae-unsigned", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-12-686-unsigned", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-12-amd64-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-12-amd64-unsigned", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-12-arm64-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-12-arm64-unsigned", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-12-armmp", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-12-armmp-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-12-armmp-lpae", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-12-armmp-lpae-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-12-cloud-amd64-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-12-cloud-amd64-unsigned", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-12-loongson-3", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-12-loongson-3-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-12-marvell", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-12-marvell-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-12-octeon", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-12-octeon-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-12-powerpc64le", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-12-powerpc64le-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-12-rpi", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-12-rpi-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-12-rt-686-pae-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-12-rt-686-pae-unsigned", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-12-rt-amd64-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-12-rt-amd64-unsigned", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-12-rt-arm64-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-12-rt-arm64-unsigned", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-12-rt-armmp", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-12-rt-armmp-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-12-s390x", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-12-s390x-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-4kc-malta", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-4kc-malta-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-5kc-malta", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-5kc-malta-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-686-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-686-pae-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-686-pae-unsigned", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-686-unsigned", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-amd64-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-amd64-unsigned", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-arm64-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-arm64-unsigned", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-armmp", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-armmp-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-armmp-lpae", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-armmp-lpae-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-cloud-amd64-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-cloud-amd64-unsigned", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-loongson-3", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-loongson-3-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-marvell", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-marvell-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-octeon", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-octeon-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-powerpc64le", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-powerpc64le-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-rpi", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-rpi-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-rt-686-pae-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-rt-686-pae-unsigned", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-rt-amd64-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-rt-amd64-unsigned", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-rt-arm64-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-rt-arm64-unsigned", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-rt-armmp", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-rt-armmp-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-s390x", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-s390x-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-4kc-malta", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-4kc-malta-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-5kc-malta", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-5kc-malta-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-686-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-686-pae-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-686-pae-unsigned", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-686-unsigned", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-amd64-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-amd64-unsigned", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-arm64-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-arm64-unsigned", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-armmp", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-armmp-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-armmp-lpae", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-armmp-lpae-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-cloud-amd64-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-cloud-amd64-unsigned", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-loongson-3", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-loongson-3-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-marvell", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-marvell-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-octeon", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-octeon-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-powerpc64le", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-powerpc64le-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-rpi", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-rpi-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-rt-686-pae-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-rt-686-pae-unsigned", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-rt-amd64-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-rt-amd64-unsigned", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-rt-arm64-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-rt-arm64-unsigned", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-rt-armmp", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-rt-armmp-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-s390x", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-8-s390x-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-9-4kc-malta", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-9-4kc-malta-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-9-5kc-malta", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-9-5kc-malta-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-9-686-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-9-686-pae-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-9-686-pae-unsigned", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-9-686-unsigned", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-9-amd64-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-9-amd64-unsigned", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-9-arm64-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-9-arm64-unsigned", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-9-armmp", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-9-armmp-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-9-armmp-lpae", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-9-armmp-lpae-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-9-cloud-amd64-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-9-cloud-amd64-unsigned", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-9-loongson-3", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-9-loongson-3-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-9-marvell", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-9-marvell-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-9-octeon", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-9-octeon-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-9-powerpc64le", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-9-powerpc64le-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-9-rpi", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-9-rpi-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-9-rt-686-pae-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-9-rt-686-pae-unsigned", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-9-rt-amd64-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-9-rt-amd64-unsigned", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-9-rt-arm64-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-9-rt-arm64-unsigned", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-9-rt-armmp", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-9-rt-armmp-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-9-s390x", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-9-s390x-dbg", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-amd64-signed-template", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-arm64-signed-template", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-i386-signed-template", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-kbuild-4.19", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-libc-dev", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-perf-4.19", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-source-4.19", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-support-4.19.0-12", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-support-4.19.0-6", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-support-4.19.0-8", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-support-4.19.0-9", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lockdep", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usbip", ver:"4.19.152-1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
