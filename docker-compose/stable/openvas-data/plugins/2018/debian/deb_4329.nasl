###############################################################################
# OpenVAS Vulnerability Test
#
# Auto-generated from advisory DSA 4329-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704329");
  script_version("2021-06-22T02:00:27+0000");
  script_cve_id("CVE-2018-18541");
  script_name("Debian Security Advisory DSA 4329-1 (teeworlds - security update)");
  script_tag(name:"last_modification", value:"2021-06-22 02:00:27 +0000 (Tue, 22 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-10-28 00:00:00 +0200 (Sun, 28 Oct 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-23 18:15:00 +0000 (Tue, 23 Jul 2019)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4329.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");
  script_tag(name:"affected", value:"teeworlds on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (stretch), this problem has been fixed in
version 0.6.5+dfsg-1~deb9u1.

We recommend that you upgrade your teeworlds packages.");

  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/teeworlds");
  script_tag(name:"summary", value:"It was discovered that incorrect connection setup in the server for
Teeworlds, an online multi-player platform 2D shooter, could result in
denial of service via forged connection packets (rendering all game
server slots occupied).");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"teeworlds", ver:"0.6.5+dfsg-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"teeworlds-data", ver:"0.6.5+dfsg-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"teeworlds-server", ver:"0.6.5+dfsg-1~deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}