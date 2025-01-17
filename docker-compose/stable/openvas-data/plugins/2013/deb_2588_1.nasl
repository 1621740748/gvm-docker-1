# OpenVAS Vulnerability Test
# Auto-generated from advisory DSA 2588-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702588");
  script_version("2020-10-05T06:02:24+0000");
  script_cve_id("CVE-2012-5829", "CVE-2012-4201", "CVE-2012-5842", "CVE-2012-4216", "CVE-2012-4207");
  script_name("Debian Security Advisory DSA 2588-1 (icedove - several vulnerabilities)");
  script_tag(name:"last_modification", value:"2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)");
  script_tag(name:"creation_date", value:"2013-09-18 11:53:02 +0200 (Wed, 18 Sep 2013)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_xref(name:"URL", value:"http://www.debian.org/security/2012/dsa-2588.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");
  script_tag(name:"affected", value:"icedove on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (squeeze), these problems have been fixed in
version 3.0.11-1+squeeze15.

For the unstable distribution (sid), these problems have been fixed in
version 10.0.11-1.

We recommend that you upgrade your icedove packages.");
  script_tag(name:"summary", value:"Multiple vulnerabilities have been found in Icedove, Debian's version
of the Mozilla Thunderbird mail and news client.

CVE-2012-4201The evalInSandbox implementation uses an incorrect context during
the handling of JavaScript code that sets the location.href
property, which allows remote attackers to conduct cross-site
scripting (XSS) attacks or read arbitrary files by leveraging a
sandboxed add-on.

CVE-2012-4207The HZ-GB-2312 character-set implementation does not properly handle
a ~ (tilde) character in proximity to a chunk delimiter, which
allows remote attackers to conduct cross-site scripting (XSS)
attacks via a crafted document.

CVE-2012-4216Use-after-free vulnerability in the gfxFont::GetFontEntry function
allows remote attackers to execute arbitrary code or cause a denial
of service (heap memory corruption) via unspecified vectors.

CVE-2012-5829Heap-based buffer overflow in the nsWindow::OnExposeEvent function could
allow remote attackers to execute arbitrary code.

CVE-2012-5842Multiple unspecified vulnerabilities in the browser engine could
allow remote attackers to cause a denial of service (memory
corruption and application crash) or possibly execute arbitrary
code.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"icedove", ver:"3.0.11-1+squeeze15", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"icedove-dbg", ver:"3.0.11-1+squeeze15", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"icedove-dev", ver:"3.0.11-1+squeeze15", rls:"DEB6")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
