# OpenVAS Vulnerability Test
# Auto-generated from advisory DSA 3184-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.703184");
  script_version("2019-12-18T09:57:42+0000");
  script_cve_id("CVE-2014-3591", "CVE-2015-0837", "CVE-2015-1606");
  script_name("Debian Security Advisory DSA 3184-1 (gnupg - security update)");
  script_tag(name:"last_modification", value:"2019-12-18 09:57:42 +0000 (Wed, 18 Dec 2019)");
  script_tag(name:"creation_date", value:"2015-03-12 00:00:00 +0100 (Thu, 12 Mar 2015)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.debian.org/security/2015/dsa-3184.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"gnupg on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (wheezy),
these problems have been fixed in version 1.4.12-7+deb7u7.

For the upcoming stable distribution (jessie), these problems have been
fixed in version 1.4.18-7.

For the unstable distribution (sid), these problems have been fixed in
version 1.4.18-7.

We recommend that you upgrade your gnupg packages.");
  script_tag(name:"summary", value:"Multiple vulnerabilities were discovered
in GnuPG, the GNU Privacy Guard:

CVE-2014-3591
The Elgamal decryption routine was susceptible to a side-channel
attack discovered by researchers of Tel Aviv University. Ciphertext
blinding was enabled to counteract it. Note that this may have a
quite noticeable impact on Elgamal decryption performance.

CVE-2015-0837
The modular exponentiation routine mpi_powm() was susceptible to a
side-channel attack caused by data-dependent timing variations when
accessing its internal pre-computed table.

CVE-2015-1606
The keyring parsing code did not properly reject certain packet
types not belonging in a keyring, which caused an access to memory
already freed. This could allow remote attackers to cause a denial
of service (crash) via crafted keyring files.");
  script_tag(name:"vuldetect", value:"This check tests the installed software
version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"gnupg", ver:"1.4.12-7+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gnupg-curl", ver:"1.4.12-7+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gpgv", ver:"1.4.12-7+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gpgv-win32", ver:"1.4.12-7+deb7u7", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}