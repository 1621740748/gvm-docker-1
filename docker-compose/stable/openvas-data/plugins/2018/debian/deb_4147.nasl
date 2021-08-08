###############################################################################
# OpenVAS Vulnerability Test
#
# Auto-generated from advisory DSA 4147-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.704147");
  script_version("2021-06-16T13:21:12+0000");
  script_cve_id("CVE-2017-18187", "CVE-2018-0487", "CVE-2018-0488");
  script_name("Debian Security Advisory DSA 4147-1 (polarssl - security update)");
  script_tag(name:"last_modification", value:"2021-06-16 13:21:12 +0000 (Wed, 16 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-03-21 00:00:00 +0100 (Wed, 21 Mar 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-10 16:15:00 +0000 (Mon, 10 Feb 2020)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4147.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"polarssl on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (jessie), these problems have been fixed
in version 1.3.9-2.1+deb8u3.

We recommend that you upgrade your polarssl packages.");

  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/polarssl");
  script_tag(name:"summary", value:"Several vulnerabilities were discovered in PolarSSL, a lightweight
crypto and SSL/TLS library, that allowed a remote attacker to either
cause a denial-of-service by application crash, or execute arbitrary
code.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libpolarssl-dev", ver:"1.3.9-2.1+deb8u3", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpolarssl-runtime", ver:"1.3.9-2.1+deb8u3", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpolarssl7", ver:"1.3.9-2.1+deb8u3", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}