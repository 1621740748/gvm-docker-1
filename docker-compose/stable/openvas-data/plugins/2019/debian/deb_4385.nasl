# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.704385");
  script_version("2021-01-14T07:10:35+0000");
  script_cve_id("CVE-2019-3814");
  script_name("Debian Security Advisory DSA 4385-1 (dovecot - security update)");
  script_tag(name:"last_modification", value:"2021-01-14 07:10:35 +0000 (Thu, 14 Jan 2021)");
  script_tag(name:"creation_date", value:"2019-02-05 00:00:00 +0100 (Tue, 05 Feb 2019)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4385.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");
  script_tag(name:"affected", value:"dovecot on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (stretch), this problem has been fixed in
version 1:2.2.27-3+deb9u3.

We recommend that you upgrade your dovecot packages.");

  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/dovecot");
  script_tag(name:"summary", value:"halfdog discovered an authentication bypass vulnerability in the Dovecot
email server. Under some configurations Dovecot mistakenly trusts the
username provided via authentication instead of failing. If there is no
additional password verification, this allows the attacker to login as
anyone else in the system. Only installations using:

auth_ssl_require_client_cert = yes

auth_ssl_username_from_cert = yes

are affected by this flaw.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"dovecot-core", ver:"1:2.2.27-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dovecot-dbg", ver:"1:2.2.27-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dovecot-dev", ver:"1:2.2.27-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dovecot-gssapi", ver:"1:2.2.27-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dovecot-imapd", ver:"1:2.2.27-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dovecot-ldap", ver:"1:2.2.27-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dovecot-lmtpd", ver:"1:2.2.27-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dovecot-lucene", ver:"1:2.2.27-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dovecot-managesieved", ver:"1:2.2.27-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dovecot-mysql", ver:"1:2.2.27-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dovecot-pgsql", ver:"1:2.2.27-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dovecot-pop3d", ver:"1:2.2.27-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dovecot-sieve", ver:"1:2.2.27-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dovecot-solr", ver:"1:2.2.27-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dovecot-sqlite", ver:"1:2.2.27-3+deb9u3", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}
