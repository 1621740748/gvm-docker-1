###############################################################################
# OpenVAS Vulnerability Test
#
# Auto-generated from advisory DSA 4161-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.704161");
  script_version("2021-06-15T11:41:24+0000");
  script_cve_id("CVE-2018-7536", "CVE-2018-7537");
  script_name("Debian Security Advisory DSA 4161-1 (python-django - security update)");
  script_tag(name:"last_modification", value:"2021-06-15 11:41:24 +0000 (Tue, 15 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-04-01 00:00:00 +0200 (Sun, 01 Apr 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-28 21:21:00 +0000 (Thu, 28 Feb 2019)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4161.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB[89]");
  script_tag(name:"affected", value:"python-django on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (jessie), these problems have been fixed
in version 1.7.11-1+deb8u3.

For the stable distribution (stretch), these problems have been fixed in
version 1:1.10.7-2+deb9u1.

We recommend that you upgrade your python-django packages.");

  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/python-django");
  script_tag(name:"summary", value:"James Davis discovered two issues in Django, a high-level Python web
development framework, that can lead to a denial-of-service attack.
An attacker with control on the input of the django.utils.html.urlize()
function or django.utils.text.Truncator's chars() and words() methods
could craft a string that might stuck the execution of the application.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"python-django", ver:"1.7.11-1+deb8u3", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-django-common", ver:"1.7.11-1+deb8u3", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-django-doc", ver:"1.7.11-1+deb8u3", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python3-django", ver:"1.7.11-1+deb8u3", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-django", ver:"1:1.10.7-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-django-common", ver:"1:1.10.7-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-django-doc", ver:"1:1.10.7-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python3-django", ver:"1:1.10.7-2+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}