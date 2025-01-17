# OpenVAS Vulnerability Test
# Auto-generated from advisory DSA 3191-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.703191");
  script_version("2020-02-04T09:04:16+0000");
  script_cve_id("CVE-2015-0282", "CVE-2015-0294");
  script_name("Debian Security Advisory DSA 3191-1 (gnutls26 - security update)");
  script_tag(name:"last_modification", value:"2020-02-04 09:04:16 +0000 (Tue, 04 Feb 2020)");
  script_tag(name:"creation_date", value:"2015-03-15 00:00:00 +0100 (Sun, 15 Mar 2015)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.debian.org/security/2015/dsa-3191.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"gnutls26 on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (wheezy),
these problems have been fixed in version 2.12.20-8+deb7u3.

We recommend that you upgrade your gnutls26 packages.");
  script_tag(name:"summary", value:"Multiple vulnerabilities have been
discovered in GnuTLS, a library implementing the TLS and SSL protocols. The
Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2015-0282
GnuTLS does not verify the RSA PKCS #1 signature algorithm to match
the signature algorithm in the certificate, leading to a potential
downgrade to a disallowed algorithm without detecting it.

CVE-2015-0294
It was reported that GnuTLS does not check whether the two signature
algorithms match on certificate import.");
  script_tag(name:"vuldetect", value:"This check tests the installed
software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"gnutls-bin", ver:"2.12.20-8+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gnutls26-doc", ver:"2.12.20-8+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"guile-gnutls:amd64", ver:"2.12.20-8+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"guile-gnutls:i386", ver:"2.12.20-8+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgnutls-dev", ver:"2.12.20-8+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgnutls-openssl27:amd64", ver:"2.12.20-8+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgnutls-openssl27:i386", ver:"2.12.20-8+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgnutls26:amd64", ver:"2.12.20-8+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgnutls26:i386", ver:"2.12.20-8+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgnutls26-dbg", ver:"2.12.20-8+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgnutlsxx27:amd64", ver:"2.12.20-8+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgnutlsxx27:i386", ver:"2.12.20-8+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}