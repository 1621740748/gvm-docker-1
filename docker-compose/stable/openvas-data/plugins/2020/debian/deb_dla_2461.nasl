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
  script_oid("1.3.6.1.4.1.25623.1.0.892461");
  script_version("2021-07-26T11:00:54+0000");
  script_cve_id("CVE-2016-10742", "CVE-2020-11800");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-07-26 11:00:54 +0000 (Mon, 26 Jul 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-21 20:15:00 +0000 (Sat, 21 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-22 04:00:14 +0000 (Sun, 22 Nov 2020)");
  script_name("Debian LTS: Security Advisory for zabbix (DLA-2461-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/11/msg00039.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2461-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'zabbix'
  package(s) announced via the DLA-2461-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were discovered in Zabbix, a network
monitoring solution. An attacker may remotely execute code on the
zabbix server, and redirect to external links through the zabbix web
frontend.

CVE-2016-10742

Zabbix allows open redirect via the request parameter.

CVE-2020-11800

Zabbix allows remote attackers to execute arbitrary code.

This update also includes several other bug fixes and
improvements. For more information please refer to the upstream
changelog file.");

  script_tag(name:"affected", value:"'zabbix' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
1:3.0.31+dfsg-0+deb9u1.

We recommend that you upgrade your zabbix packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"zabbix-agent", ver:"1:3.0.31+dfsg-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"zabbix-frontend-php", ver:"1:3.0.31+dfsg-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"zabbix-java-gateway", ver:"1:3.0.31+dfsg-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"zabbix-proxy-mysql", ver:"1:3.0.31+dfsg-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"zabbix-proxy-pgsql", ver:"1:3.0.31+dfsg-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"zabbix-proxy-sqlite3", ver:"1:3.0.31+dfsg-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"zabbix-server-mysql", ver:"1:3.0.31+dfsg-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"zabbix-server-pgsql", ver:"1:3.0.31+dfsg-0+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
