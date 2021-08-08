# OpenVAS Vulnerability Test
# $Id: deb_3627.nasl 14279 2019-03-18 14:48:34Z cfischer $
# Auto-generated from advisory DSA 3627-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.703627");
  script_version("$Revision: 14279 $");
  script_cve_id("CVE-2016-1927", "CVE-2016-2039", "CVE-2016-2040", "CVE-2016-2041",
                  "CVE-2016-2560", "CVE-2016-2561", "CVE-2016-5099", "CVE-2016-5701",
                  "CVE-2016-5705", "CVE-2016-5706", "CVE-2016-5731", "CVE-2016-5733",
                  "CVE-2016-5739");
  script_name("Debian Security Advisory DSA 3627-1 (phpmyadmin - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-08-02 10:58:14 +0530 (Tue, 02 Aug 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2016/dsa-3627.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"phpmyadmin on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (jessie),
these problems have been fixed in version 4:4.2.12-2+deb8u2.

For the unstable distribution (sid), these problems have been fixed in
version 4:4.6.3-1.

We recommend that you upgrade your phpmyadmin packages.");
  script_tag(name:"summary", value:"Several vulnerabilities have been fixed in
phpMyAdmin, the web-based MySQL administration interface.

CVE-2016-1927
The suggestPassword function relied on a non-secure random number
generator which makes it easier for remote attackers to guess
generated passwords via a brute-force approach.

CVE-2016-2039
CSRF token values were generated by a non-secure random number
generator, which allows remote attackers to bypass intended access
restrictions by predicting a value.

CVE-2016-2040
Multiple cross-site scripting (XSS) vulnerabilities allow remote
authenticated users to inject arbitrary web script or HTML.

CVE-2016-2041
phpMyAdmin does not use a constant-time algorithm for comparing
CSRF tokens, which makes it easier for remote attackers to bypass
intended access restrictions by measuring time differences.

CVE-2016-2560
Multiple cross-site scripting (XSS) vulnerabilities allow remote
attackers to inject arbitrary web script or HTML.

CVE-2016-2561
Multiple cross-site scripting (XSS) vulnerabilities allow remote
attackers to inject arbitrary web script or HTML.

CVE-2016-5099
Multiple cross-site scripting (XSS) vulnerabilities allow remote
attackers to inject arbitrary web script or HTML.

CVE-2016-5701
For installations running on plain HTTP, phpMyAdmin allows remote
attackers to conduct BBCode injection attacks against HTTP sessions
via a crafted URI.

CVE-2016-5705
Multiple cross-site scripting (XSS) vulnerabilities allow remote
attackers to inject arbitrary web script or HTML.

CVE-2016-5706
phpMyAdmin allows remote attackers to cause a denial of service
(resource consumption) via a large array in the scripts parameter.

CVE-2016-5731
A cross-site scripting (XSS) vulnerability allows remote
attackers to inject arbitrary web script or HTML.

CVE-2016-5733
Multiple cross-site scripting (XSS) vulnerabilities allow remote
attackers to inject arbitrary web script or HTML.

CVE-2016-5739
A specially crafted Transformation could leak information which
a remote attacker could use to perform cross site request forgeries.");
  script_tag(name:"vuldetect", value:"This check tests the installed software
version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"phpmyadmin", ver:"4:4.2.12-2+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}