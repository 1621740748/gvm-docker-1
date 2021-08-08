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
  script_oid("1.3.6.1.4.1.25623.1.0.890996");
  script_version("2021-06-21T02:00:27+0000");
  script_cve_id("CVE-2017-5664");
  script_name("Debian LTS: Security Advisory for tomcat7 (DLA-996-1)");
  script_tag(name:"last_modification", value:"2021-06-21 02:00:27 +0000 (Mon, 21 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-01-29 00:00:00 +0100 (Mon, 29 Jan 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2017/06/msg00025.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_tag(name:"affected", value:"tomcat7 on Debian Linux");

  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
7.0.28-4+deb7u14.

We recommend that you upgrade your tomcat7 packages.");

  script_tag(name:"summary", value:"The error page mechanism of the Java Servlet Specification requires
that, when an error occurs and an error page is configured for the
error that occurred, the original request and response are forwarded
to the error page. This means that the request is presented to the
error page with the original HTTP method. If the error page is a
static file, expected behaviour is to serve content of the file as if
processing a GET request, regardless of the actual HTTP method. The
Default Servlet in Apache Tomcat did not do this. Depending on the
original request this could lead to unexpected and undesirable results
for static error pages including, if the DefaultServlet is configured
to permit writes, the replacement or removal of the custom error page.");

  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libservlet3.0-java", ver:"7.0.28-4+deb7u14", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libservlet3.0-java-doc", ver:"7.0.28-4+deb7u14", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libtomcat7-java", ver:"7.0.28-4+deb7u14", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat7", ver:"7.0.28-4+deb7u14", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat7-admin", ver:"7.0.28-4+deb7u14", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat7-common", ver:"7.0.28-4+deb7u14", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat7-docs", ver:"7.0.28-4+deb7u14", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat7-examples", ver:"7.0.28-4+deb7u14", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat7-user", ver:"7.0.28-4+deb7u14", rls:"DEB7"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
