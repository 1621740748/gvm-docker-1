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
  script_oid("1.3.6.1.4.1.25623.1.0.704805");
  script_version("2021-07-26T11:00:54+0000");
  script_cve_id("CVE-2020-17508", "CVE-2020-17509");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-07-26 11:00:54 +0000 (Mon, 26 Jul 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-14 20:20:00 +0000 (Thu, 14 Jan 2021)");
  script_tag(name:"creation_date", value:"2020-12-08 10:02:39 +0000 (Tue, 08 Dec 2020)");
  script_name("Debian: Security Advisory for trafficserver (DSA-4805-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4805.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4805-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'trafficserver'
  package(s) announced via the DSA-4805-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were discovered in Apache Traffic Server, a reverse
and forward proxy server:

CVE-2020-17508
The ESI plugin was vulnerable to memory disclosure.

CVE-2020-17509
The negative cache option was vulnerable to cache poisoning.");

  script_tag(name:"affected", value:"'trafficserver' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (buster), these problems have been fixed in
version 8.0.2+ds-1+deb10u4.

We recommend that you upgrade your trafficserver packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"trafficserver", ver:"8.0.2+ds-1+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"trafficserver-dev", ver:"8.0.2+ds-1+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"trafficserver-experimental-plugins", ver:"8.0.2+ds-1+deb10u4", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
