# Copyright (C) 2018 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.890977");
  script_version("2020-01-29T08:22:52+0000");
  script_cve_id("CVE-2014-2015", "CVE-2015-4680", "CVE-2017-9148");
  script_name("Debian LTS: Security Advisory for freeradius (DLA-977-1)");
  script_tag(name:"last_modification", value:"2020-01-29 08:22:52 +0000 (Wed, 29 Jan 2020)");
  script_tag(name:"creation_date", value:"2018-01-29 00:00:00 +0100 (Mon, 29 Jan 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2017/06/msg00005.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_tag(name:"affected", value:"freeradius on Debian Linux");

  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
2.1.12+dfsg-1.2+deb7u1.

We recommend that you upgrade your freeradius packages.");

  script_tag(name:"summary", value:"Several issues were discovered in FreeRADIUS, a high-performance and
highly configurable RADIUS server.

CVE-2014-2015

A stack-based buffer overflow was found in the normify function in
the rlm_pap module, which can be attacked by existing users to
cause denial of service or other issues.

CVE-2015-4680

It was discovered that freeradius failed to check revocation of
intermediate CA certificates, thus accepting client certificates
issued by revoked certificates from an intermediate CA.

Note that to enable checking of intermediate CA certificates, it
is necessary to enable the check_all_crl option of the EAP TLS
section in eap.conf. This is only necessary for servers using
certificates signed by an intermediate CA. Servers that use
self-signed CA certificate are unaffected.

CVE-2017-9148

The TLS session cache fails to reliably prevent resumption of an
unauthenticated session, which allows remote attackers (such as
malicious 802.1X supplicants) to bypass authentication via PEAP or
TTLS.");

  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"freeradius", ver:"2.1.12+dfsg-1.2+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"freeradius-common", ver:"2.1.12+dfsg-1.2+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"freeradius-dbg", ver:"2.1.12+dfsg-1.2+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"freeradius-dialupadmin", ver:"2.1.12+dfsg-1.2+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"freeradius-iodbc", ver:"2.1.12+dfsg-1.2+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"freeradius-krb5", ver:"2.1.12+dfsg-1.2+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"freeradius-ldap", ver:"2.1.12+dfsg-1.2+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"freeradius-mysql", ver:"2.1.12+dfsg-1.2+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"freeradius-postgresql", ver:"2.1.12+dfsg-1.2+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"freeradius-utils", ver:"2.1.12+dfsg-1.2+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libfreeradius-dev", ver:"2.1.12+dfsg-1.2+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libfreeradius2", ver:"2.1.12+dfsg-1.2+deb7u1", rls:"DEB7"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
