# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.704937");
  script_version("2021-07-10T03:00:14+0000");
  script_cve_id("CVE-2020-35452", "CVE-2021-26690", "CVE-2021-26691", "CVE-2021-30641", "CVE-2021-31618");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-07-10 03:00:14 +0000 (Sat, 10 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-10 03:00:14 +0000 (Sat, 10 Jul 2021)");
  script_name("Debian: Security Advisory for apache2 (DSA-4937-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-4937.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4937-1");
  script_xref(name:"Advisory-ID", value:"DSA-4937-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2'
  package(s) announced via the DSA-4937-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been found in the Apache HTTP server, which
could result in denial of service. In addition the implementation of
the MergeSlashes option could result in unexpected behaviour.");

  script_tag(name:"affected", value:"'apache2' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (buster), these problems have been fixed in
version 2.4.38-3+deb10u5.

We recommend that you upgrade your apache2 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"apache2", ver:"2.4.38-3+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"apache2-bin", ver:"2.4.38-3+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"apache2-data", ver:"2.4.38-3+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"apache2-dev", ver:"2.4.38-3+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"apache2-doc", ver:"2.4.38-3+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"apache2-ssl-dev", ver:"2.4.38-3+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"apache2-suexec-custom", ver:"2.4.38-3+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"apache2-suexec-pristine", ver:"2.4.38-3+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"apache2-utils", ver:"2.4.38-3+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-md", ver:"2.4.38-3+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-proxy-uwsgi", ver:"2.4.38-3+deb10u5", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
