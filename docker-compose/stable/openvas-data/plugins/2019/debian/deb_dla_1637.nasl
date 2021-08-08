# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.891637");
  script_version("2020-11-24T09:51:52+0000");
  script_cve_id("CVE-2019-3462");
  script_name("Debian LTS: Security Advisory for apt (DLA-1637-1)");
  script_tag(name:"last_modification", value:"2020-11-24 09:51:52 +0000 (Tue, 24 Nov 2020)");
  script_tag(name:"creation_date", value:"2019-01-22 00:00:00 +0100 (Tue, 22 Jan 2019)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/01/msg00014.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_tag(name:"affected", value:"apt on Debian Linux");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', this problem has been fixed in version
1.0.9.8.5.

We recommend that you upgrade your apt packages.

Please note the specific upgrade instructions within the referenced vendor advisory.");

  script_tag(name:"summary", value:"Max Justicz discovered a vulnerability in APT, the high level package manager.
The code handling HTTP redirects in the HTTP transport method doesn't properly
sanitize fields transmitted over the wire. This vulnerability could be used by
an attacker located as a man-in-the-middle between APT and a mirror to inject
malicious content in the HTTP connection. This content could then be recognized
as a valid package by APT and used later for code execution with root
privileges on the target machine.");

  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"apt", ver:"1.0.9.8.5", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"apt-doc", ver:"1.0.9.8.5", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"apt-transport-https", ver:"1.0.9.8.5", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"apt-utils", ver:"1.0.9.8.5", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libapt-inst1.5", ver:"1.0.9.8.5", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libapt-pkg-dev", ver:"1.0.9.8.5", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libapt-pkg-doc", ver:"1.0.9.8.5", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libapt-pkg4.12", ver:"1.0.9.8.5", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}