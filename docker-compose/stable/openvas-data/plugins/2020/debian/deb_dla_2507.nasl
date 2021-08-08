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
  script_oid("1.3.6.1.4.1.25623.1.0.892507");
  script_version("2021-07-22T11:01:40+0000");
  script_cve_id("CVE-2020-26258", "CVE-2020-26259");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-07-22 11:01:40 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-13 18:10:00 +0000 (Tue, 13 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-01-01 04:00:10 +0000 (Fri, 01 Jan 2021)");
  script_name("Debian LTS: Security Advisory for libxstream-java (DLA-2507-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/12/msg00042.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2507-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/977625");
  script_xref(name:"URL", value:"https://bugs.debian.org/977624");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxstream-java'
  package(s) announced via the DLA-2507-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security vulnerabilities were discovered in XStream, a Java library to
serialize objects to XML and back again.

CVE-2020-26258

XStream is vulnerable to a Server-Side Forgery Request which can be
activated when unmarshalling. The vulnerability may allow a remote attacker
to request data from internal resources that are not publicly available
only by manipulating the processed input stream.

CVE-2020-26259

Xstream is vulnerable to an Arbitrary File Deletion on the local host when
unmarshalling. The vulnerability may allow a remote attacker to delete
arbitrary known files on the host as long as the executing process has
sufficient rights only by manipulating the processed input stream.");

  script_tag(name:"affected", value:"'libxstream-java' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
1.4.11.1-1+deb9u1.

We recommend that you upgrade your libxstream-java packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libxstream-java", ver:"1.4.11.1-1+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
