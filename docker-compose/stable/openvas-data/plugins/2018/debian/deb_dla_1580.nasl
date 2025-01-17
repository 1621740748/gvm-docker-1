# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.891580");
  script_version("2021-08-02T02:00:56+0000");
  script_cve_id("CVE-2018-1049", "CVE-2018-15686", "CVE-2018-15688");
  script_name("Debian LTS: Security Advisory for systemd (DLA-1580-1)");
  script_tag(name:"last_modification", value:"2021-08-02 02:00:56 +0000 (Mon, 02 Aug 2021)");
  script_tag(name:"creation_date", value:"2018-11-20 00:00:00 +0100 (Tue, 20 Nov 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:35:00 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/11/msg00017.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_tag(name:"affected", value:"systemd on Debian Linux");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
215-17+deb8u8.

We recommend that you upgrade your systemd packages.");

  script_tag(name:"summary", value:"systemd was found to suffer from multiple security vulnerabilities
ranging from denial of service attacks to possible root privilege
escalation.

CVE-2018-1049

A race condition exists between .mount and .automount units such
that automount requests from kernel may not be serviced by systemd
resulting in kernel holding the mountpoint and any processes that
try to use said mount will hang. A race condition like this may
lead to denial of service, until mount points are unmounted.

CVE-2018-15686

A vulnerability in unit_deserialize of systemd allows an attacker
to supply arbitrary state across systemd re-execution via
NotifyAccess. This can be used to improperly influence systemd
execution and possibly lead to root privilege escalation.

CVE-2018-15688

A buffer overflow vulnerability in the dhcp6 client of systemd
allows a malicious dhcp6 server to overwrite heap memory in
systemd-networkd, which is not enabled by default in Debian.");

  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"gir1.2-gudev-1.0", ver:"215-17+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libgudev-1.0-0", ver:"215-17+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libgudev-1.0-dev", ver:"215-17+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpam-systemd", ver:"215-17+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsystemd-daemon-dev", ver:"215-17+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsystemd-daemon0", ver:"215-17+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsystemd-dev", ver:"215-17+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsystemd-id128-0", ver:"215-17+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsystemd-id128-dev", ver:"215-17+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsystemd-journal-dev", ver:"215-17+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsystemd-journal0", ver:"215-17+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsystemd-login-dev", ver:"215-17+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsystemd-login0", ver:"215-17+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsystemd0", ver:"215-17+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libudev-dev", ver:"215-17+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libudev1", ver:"215-17+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python3-systemd", ver:"215-17+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"systemd", ver:"215-17+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"systemd-dbg", ver:"215-17+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"systemd-sysv", ver:"215-17+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"udev", ver:"215-17+deb8u8", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
