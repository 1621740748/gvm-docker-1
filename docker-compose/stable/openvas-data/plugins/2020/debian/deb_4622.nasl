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
  script_oid("1.3.6.1.4.1.25623.1.0.704622");
  script_version("2021-07-27T02:00:54+0000");
  script_cve_id("CVE-2020-1720");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-07-27 02:00:54 +0000 (Tue, 27 Jul 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-15 13:28:00 +0000 (Thu, 15 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-02-15 04:00:12 +0000 (Sat, 15 Feb 2020)");
  script_name("Debian: Security Advisory for postgresql-9.6 (DSA-4622-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4622.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4622-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql-9.6'
  package(s) announced via the DSA-4622-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tom Lane discovered that ALTER ... DEPENDS ON EXTENSION
sub commands
in the PostgreSQL database did not perform authorisation checks.");

  script_tag(name:"affected", value:"'postgresql-9.6' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the oldstable distribution (stretch), this problem has been fixed
in version 9.6.17-0+deb9u1.

We recommend that you upgrade your postgresql-9.6 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libecpg-compat3", ver:"9.6.17-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libecpg-dev", ver:"9.6.17-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libecpg6", ver:"9.6.17-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpgtypes3", ver:"9.6.17-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpq-dev", ver:"9.6.17-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpq5", ver:"9.6.17-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"postgresql-9.6", ver:"9.6.17-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"postgresql-9.6-dbg", ver:"9.6.17-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"postgresql-client-9.6", ver:"9.6.17-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"postgresql-contrib-9.6", ver:"9.6.17-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"postgresql-doc-9.6", ver:"9.6.17-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"postgresql-plperl-9.6", ver:"9.6.17-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"postgresql-plpython-9.6", ver:"9.6.17-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"postgresql-plpython3-9.6", ver:"9.6.17-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"postgresql-pltcl-9.6", ver:"9.6.17-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"postgresql-server-dev-9.6", ver:"9.6.17-0+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
