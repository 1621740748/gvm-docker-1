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
  script_oid("1.3.6.1.4.1.25623.1.0.892304");
  script_version("2021-07-28T02:00:54+0000");
  script_cve_id("CVE-2015-9542");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-07-28 02:00:54 +0000 (Wed, 28 Jul 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-14 14:28:00 +0000 (Fri, 14 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-02 03:00:10 +0000 (Sun, 02 Aug 2020)");
  script_name("Debian LTS: Security Advisory for libpam-radius-auth (DLA-2304-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/08/msg00000.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2304-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/951396");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libpam-radius-auth'
  package(s) announced via the DLA-2304-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"`add_password` in pam_radius_auth.c in pam_radius 1.4.0 does not
correctly check the length of the input password, and is vulnerable
to a stack-based buffer overflow during memcpy(). An attacker could
send a crafted password to an application (loading the pam_radius
library) and crash it. Arbitrary code execution might be possible,
depending on the application, C library, compiler, and other factors.");

  script_tag(name:"affected", value:"'libpam-radius-auth' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, this problem has been fixed in version
1.3.16-5+deb9u1.

We recommend that you upgrade your libpam-radius-auth packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libpam-radius-auth", ver:"1.3.16-5+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
