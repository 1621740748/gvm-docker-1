# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.704607");
  script_version("2021-07-27T02:00:54+0000");
  script_cve_id("CVE-2019-16239");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-07-27 02:00:54 +0000 (Tue, 27 Jul 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-07 23:15:00 +0000 (Wed, 07 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-01-21 04:00:04 +0000 (Tue, 21 Jan 2020)");
  script_name("Debian Security Advisory DSA 4607-1 (openconnect - security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(9|10)");

  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4607.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4607-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openconnect'
  package(s) announced via the DSA-4607-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Lukas Kupczyk reported a vulnerability in the handling of chunked HTTP
in openconnect, an open client for Cisco AnyConnect, Pulse and
GlobalProtect VPN. A malicious HTTP server (after having accepted its
identity certificate), can provide bogus chunk lengths for chunked HTTP
encoding and cause a heap-based buffer overflow.");

  script_tag(name:"affected", value:"'openconnect' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the oldstable distribution (stretch), this problem has been fixed
in version 7.08-1+deb9u1.

For the stable distribution (buster), this problem has been fixed in
version 8.02-1+deb10u1.

We recommend that you upgrade your openconnect packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libopenconnect-dev", ver:"7.08-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libopenconnect5", ver:"7.08-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libopenconnect5-dbg", ver:"7.08-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"openconnect", ver:"7.08-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"openconnect-dbg", ver:"7.08-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libopenconnect-dev", ver:"8.02-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libopenconnect5", ver:"8.02-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"openconnect", ver:"8.02-1+deb10u1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);