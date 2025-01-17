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
  script_oid("1.3.6.1.4.1.25623.1.0.892242");
  script_version("2021-07-23T11:01:09+0000");
  script_cve_id("CVE-2019-19319", "CVE-2019-19462", "CVE-2019-19768", "CVE-2019-20806", "CVE-2019-20811", "CVE-2019-2182", "CVE-2019-5108", "CVE-2020-0543", "CVE-2020-10711", "CVE-2020-10732", "CVE-2020-10751", "CVE-2020-10757", "CVE-2020-10942", "CVE-2020-11494", "CVE-2020-11565", "CVE-2020-11608", "CVE-2020-11609", "CVE-2020-11668", "CVE-2020-12114", "CVE-2020-12464", "CVE-2020-12652", "CVE-2020-12653", "CVE-2020-12654", "CVE-2020-12770", "CVE-2020-13143", "CVE-2020-2732", "CVE-2020-8428", "CVE-2020-8647", "CVE-2020-8648", "CVE-2020-8649", "CVE-2020-9383");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-07-23 11:01:09 +0000 (Fri, 23 Jul 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-22 22:15:00 +0000 (Mon, 22 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-11 03:00:11 +0000 (Thu, 11 Jun 2020)");
  script_name("Debian LTS: Security Advisory for linux-4.9 (DLA-2242-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/06/msg00012.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2242-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/952660");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-4.9'
  package(s) announced via the DLA-2242-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service or information
leaks.

CVE-2019-2182

Hanjun Guo and Lei Li reported a race condition in the arm64
virtual memory management code, which could lead to an information
disclosure, denial of service (crash), or possibly privilege
escalation.

CVE-2019-5108

Mitchell Frank of Cisco discovered that when the IEEE 802.11
(WiFi) stack was used in AP mode with roaming, it would trigger
roaming for a newly associated station before the station was
authenticated. An attacker within range of the AP could use this
to cause a denial of service, either by filling up a switching
table or by redirecting traffic away from other stations.

CVE-2019-19319

Jungyeon discovered that a crafted filesystem can cause the ext4
implementation to deallocate or reallocate journal blocks. A user
permitted to mount filesystems could use this to cause a denial of
service (crash), or possibly for privilege escalation.

CVE-2019-19462

The syzbot tool found a missing error check in the 'relay'
library used to implement various files under debugfs. A local
user permitted to access debugfs could use this to cause a denial
of service (crash) or possibly for privilege escalation.

CVE-2019-19768

Tristan Madani reported a race condition in the blktrace debug
facility that could result in a use-after-free. A local user able
to trigger removal of block devices could possibly use this to
cause a denial of service (crash) or for privilege escalation.

CVE-2019-20806

A potential null pointer dereference was discovered in the tw5864
media driver. The security impact of this is unclear.

CVE-2019-20811

The Hulk Robot tool found a reference-counting bug in an error
path in the network subsystem. The security impact of this is
unclear.

CVE-2020-0543

Researchers at VU Amsterdam discovered that on some Intel CPUs
supporting the RDRAND and RDSEED instructions, part of a random
value generated by these instructions may be used in a later
speculative execution on any core of the same physical CPU.
Depending on how these instructions are used by applications, a
local user or VM guest could use this to obtain sensitive
information such as cryptographic keys from other users or VMs.

This vulnerability can be mitigated by a microcode update, either
as part of system firmware (BIOS) or through the intel-microcode
package in Debian's non-free archive section. This kernel update
only provides reporting of the vulnerability and the option to
disable the mitigation if it is not needed.

CVE-2020-2732

Paulo Bonzini discovered that the KVM implemen ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'linux-4.9' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
4.9.210-1+deb9u1~deb8u1. This version also fixes some related bugs
that do not have their own CVE IDs, and a regression in the macvlan
driver introduced in the previous security update (bug #952660).

We recommend that you upgrade your linux-4.9 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-4.9-arm", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-doc-4.9", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.11-686", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.11-686-pae", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.11-all", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.11-all-amd64", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.11-all-armel", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.11-all-armhf", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.11-all-i386", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.11-amd64", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.11-armmp", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.11-armmp-lpae", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.11-common", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.11-common-rt", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.11-marvell", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.11-rt-686-pae", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.11-rt-amd64", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.12-686", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.12-686-pae", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.12-all", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.12-all-amd64", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.12-all-armel", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.12-all-armhf", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.12-all-i386", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.12-amd64", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.12-armmp", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.12-armmp-lpae", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.12-common", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.12-common-rt", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.12-marvell", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.12-rt-686-pae", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.12-rt-amd64", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.11-686", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.11-686-pae", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.11-686-pae-dbg", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.11-amd64", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.11-amd64-dbg", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.11-armmp", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.11-armmp-lpae", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.11-marvell", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.11-rt-686-pae", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.11-rt-686-pae-dbg", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.11-rt-amd64", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.11-rt-amd64-dbg", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.12-686", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.12-686-pae", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.12-686-pae-dbg", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.12-amd64", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.12-amd64-dbg", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.12-armmp", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.12-armmp-lpae", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.12-marvell", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.12-rt-686-pae", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.12-rt-686-pae-dbg", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.12-rt-amd64", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.12-rt-amd64-dbg", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-kbuild-4.9", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-manual-4.9", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-perf-4.9", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-source-4.9", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-support-4.9.0-0.bpo.11", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-support-4.9.0-0.bpo.12", ver:"4.9.210-1+deb9u1~deb8u1", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
