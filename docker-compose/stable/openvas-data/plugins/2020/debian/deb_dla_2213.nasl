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
  script_oid("1.3.6.1.4.1.25623.1.0.892213");
  script_version("2021-07-26T02:01:39+0000");
  script_cve_id("CVE-2020-12783");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-07-26 02:01:39 +0000 (Mon, 26 Jul 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-04 18:15:00 +0000 (Tue, 04 May 2021)");
  script_tag(name:"creation_date", value:"2020-05-19 03:00:18 +0000 (Tue, 19 May 2020)");
  script_name("Debian LTS: Security Advisory for exim4 (DLA-2213-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/05/msg00017.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2213-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'exim4'
  package(s) announced via the DLA-2213-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that exim4, a mail transport agent, suffers from a
authentication bypass vulnerability in the spa authentication driver.
The spa authentication driver is not enabled by default.");

  script_tag(name:"affected", value:"'exim4' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', this problem has been fixed in version
4.84.2-2+deb8u7.

We recommend that you upgrade your exim4 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"exim4", ver:"4.84.2-2+deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"exim4-base", ver:"4.84.2-2+deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"exim4-config", ver:"4.84.2-2+deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"exim4-daemon-heavy", ver:"4.84.2-2+deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"exim4-daemon-heavy-dbg", ver:"4.84.2-2+deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"exim4-daemon-light", ver:"4.84.2-2+deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"exim4-daemon-light-dbg", ver:"4.84.2-2+deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"exim4-dbg", ver:"4.84.2-2+deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"exim4-dev", ver:"4.84.2-2+deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"eximon4", ver:"4.84.2-2+deb8u7", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
