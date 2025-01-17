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
  script_oid("1.3.6.1.4.1.25623.1.0.891914");
  script_version("2020-01-29T08:22:52+0000");
  script_cve_id("CVE-2019-10181", "CVE-2019-10182", "CVE-2019-10185");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-29 08:22:52 +0000 (Wed, 29 Jan 2020)");
  script_tag(name:"creation_date", value:"2019-09-10 02:00:20 +0000 (Tue, 10 Sep 2019)");
  script_name("Debian LTS: Security Advisory for icedtea-web (DLA-1914-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/09/msg00008.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-1914-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/934319");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'icedtea-web'
  package(s) announced via the DLA-1914-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security vulnerabilities were found in icedtea-web, an
implementation of the Java Network Launching Protocol (JNLP).

CVE-2019-10181

It was found that in icedtea-web executable code could be injected
in a JAR file without compromising the signature verification. An
attacker could use this flaw to inject code in a trusted JAR. The
code would be executed inside the sandbox.

CVE-2019-10182

It was found that icedtea-web did not properly sanitize paths from
<jar/> elements in JNLP files. An attacker could trick a victim
into running a specially crafted application and use this flaw to
upload arbitrary files to arbitrary locations in the context of the
user.

CVE-2019-10185

It was found that icedtea-web was vulnerable to a zip-slip attack
during auto-extraction of a JAR file. An attacker could use this
flaw to write files to arbitrary locations. This could also be used
to replace the main running application and, possibly, break out of
the sandbox.");

  script_tag(name:"affected", value:"'icedtea-web' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
1.5.3-1+deb8u1.

We recommend that you upgrade your icedtea-web packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"icedtea-7-plugin", ver:"1.5.3-1+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedtea-netx", ver:"1.5.3-1+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedtea-netx-common", ver:"1.5.3-1+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedtea-plugin", ver:"1.5.3-1+deb8u1", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
