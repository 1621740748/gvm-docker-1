# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.891802");
  script_version("2020-01-29T08:22:52+0000");
  script_cve_id("CVE-2019-10894", "CVE-2019-10895", "CVE-2019-10899", "CVE-2019-10901", "CVE-2019-10903");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2020-01-29 08:22:52 +0000 (Wed, 29 Jan 2020)");
  script_tag(name:"creation_date", value:"2019-05-26 02:00:33 +0000 (Sun, 26 May 2019)");
  script_name("Debian LTS: Security Advisory for wireshark (DLA-1802-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/05/msg00034.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-1802-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/926718");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark'
  package(s) announced via the DLA-1802-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been found in wireshark, a network traffic analyzer.

CVE-2019-10894

Assertion failure in dissect_gssapi_work (packet-gssapi.c) leading to
crash of the GSS-API dissector. Remote attackers might leverage this
vulnerability to trigger DoS via a packet containing crafted GSS-API
payload.

CVE-2019-10895

Insufficient data validation leading to large number of heap buffer
overflows read and write in the NetScaler trace handling module
(netscaler.c). Remote attackers might leverage these vulnerabilities to
trigger DoS, or any other unspecified impact via crafted packets.

CVE-2019-10899

Heap-based buffer under-read vulnerability in the Service Location
Protocol dissector. Remote attackers might leverage these
vulnerabilities to trigger DoS, or any other unspecified impact via
crafted SRVLOC packets.

CVE-2019-10901

NULL pointer dereference in the Local Download Sharing Service
protocol dissector. Remote attackers might leverage these flaws to
trigger DoS via crafted LDSS packets.

CVE-2019-10903

Missing boundary checks leading to heap out-of-bounds read
vulnerability in the Microsoft Spool Subsystem protocol dissector.
Remote attackers might leverage these vulnerabilities to trigger DoS,
or any other unspecified impact via crafted SPOOLSS packets.");

  script_tag(name:"affected", value:"'wireshark' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
1.12.1+g01b65bf-4+deb8u19.

We recommend that you upgrade your wireshark packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libwireshark-data", ver:"1.12.1+g01b65bf-4+deb8u19", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwireshark-dev", ver:"1.12.1+g01b65bf-4+deb8u19", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwireshark5", ver:"1.12.1+g01b65bf-4+deb8u19", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwiretap-dev", ver:"1.12.1+g01b65bf-4+deb8u19", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwiretap4", ver:"1.12.1+g01b65bf-4+deb8u19", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwsutil-dev", ver:"1.12.1+g01b65bf-4+deb8u19", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwsutil4", ver:"1.12.1+g01b65bf-4+deb8u19", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tshark", ver:"1.12.1+g01b65bf-4+deb8u19", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"wireshark", ver:"1.12.1+g01b65bf-4+deb8u19", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"wireshark-common", ver:"1.12.1+g01b65bf-4+deb8u19", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"wireshark-dbg", ver:"1.12.1+g01b65bf-4+deb8u19", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"wireshark-dev", ver:"1.12.1+g01b65bf-4+deb8u19", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"wireshark-doc", ver:"1.12.1+g01b65bf-4+deb8u19", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"wireshark-qt", ver:"1.12.1+g01b65bf-4+deb8u19", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
