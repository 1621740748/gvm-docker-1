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
  script_oid("1.3.6.1.4.1.25623.1.0.704475");
  script_version("2019-07-03T02:00:06+0000");
  script_cve_id("CVE-2019-1543");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-07-03 02:00:06 +0000 (Wed, 03 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-03 02:00:06 +0000 (Wed, 03 Jul 2019)");
  script_name("Debian Security Advisory DSA 4475-1 (openssl - security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4475.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4475-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl'
  package(s) announced via the DSA-4475-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Joran Dirk Greef discovered that overly long nonces used with
ChaCha20-Poly1305 were incorrectly processed and could result in nonce
reuse. This doesn't affect OpenSSL-internal uses of ChaCha20-Poly1305
such as TLS.");

  script_tag(name:"affected", value:"'openssl' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (stretch), this problem has been fixed in
version 1.1.0k-1~deb9u1. This DSA also upgrades openssl1.0 (which
itself is not affected by CVE-2019-1543) to 1.0.2s-1~deb9u1

We recommend that you upgrade your openssl packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libssl-dev", ver:"1.1.0k-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libssl-doc", ver:"1.1.0k-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libssl1.1", ver:"1.1.0k-1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"openssl", ver:"1.1.0k-1~deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);