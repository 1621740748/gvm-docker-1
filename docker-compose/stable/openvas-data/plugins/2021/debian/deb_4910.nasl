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
  script_oid("1.3.6.1.4.1.25623.1.0.704910");
  script_version("2021-05-06T07:37:16+0000");
  script_cve_id("CVE-2021-22204");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-05-06 07:37:16 +0000 (Thu, 06 May 2021)");
  script_tag(name:"creation_date", value:"2021-05-03 03:00:04 +0000 (Mon, 03 May 2021)");
  script_name("Debian: Security Advisory for libimage-exiftool-perl (DSA-4910-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-4910.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4910-1");
  script_xref(name:"Advisory-ID", value:"DSA-4910-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libimage-exiftool-perl'
  package(s) announced via the DSA-4910-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was discovered in libimage-exiftool-perl, a library and
program to read and write meta information in multimedia files, which
may result in execution of arbitrary code if a malformed DjVu file is
processed.");

  script_tag(name:"affected", value:"'libimage-exiftool-perl' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (buster), this problem has been fixed in
version 11.16-1+deb10u1.

We recommend that you upgrade your libimage-exiftool-perl packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libimage-exiftool-perl", ver:"11.16-1+deb10u1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
