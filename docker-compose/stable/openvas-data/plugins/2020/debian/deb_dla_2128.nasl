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
  script_oid("1.3.6.1.4.1.25623.1.0.892128");
  script_version("2021-07-26T02:01:39+0000");
  script_cve_id("CVE-2020-2583", "CVE-2020-2590", "CVE-2020-2593", "CVE-2020-2601", "CVE-2020-2604", "CVE-2020-2654", "CVE-2020-2659");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-07-26 02:01:39 +0000 (Mon, 26 Jul 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)");
  script_tag(name:"creation_date", value:"2020-03-01 04:00:12 +0000 (Sun, 01 Mar 2020)");
  script_name("Debian LTS: Security Advisory for openjdk-7 (DLA-2128-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/02/msg00034.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2128-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-7'
  package(s) announced via the DLA-2128-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the OpenJDK Java runtime,
resulting in denial of service, incorrect implementation of Kerberos
GSSAPI and TGS requests or incorrect TLS handshakes.");

  script_tag(name:"affected", value:"'openjdk-7' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
7u251-2.6.21-1~deb8u1.

We recommend that you upgrade your openjdk-7 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"icedtea-7-jre-jamvm", ver:"7u251-2.6.21-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-dbg", ver:"7u251-2.6.21-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-demo", ver:"7u251-2.6.21-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-doc", ver:"7u251-2.6.21-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-jdk", ver:"7u251-2.6.21-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-jre", ver:"7u251-2.6.21-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-jre-headless", ver:"7u251-2.6.21-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-jre-lib", ver:"7u251-2.6.21-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-jre-zero", ver:"7u251-2.6.21-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-source", ver:"7u251-2.6.21-1~deb8u1", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
