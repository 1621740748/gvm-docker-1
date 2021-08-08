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
  script_oid("1.3.6.1.4.1.25623.1.0.892617");
  script_version("2021-04-05T03:00:08+0000");
  script_cve_id("CVE-2020-15227");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-04-05 03:00:08 +0000 (Mon, 05 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-05 03:00:08 +0000 (Mon, 05 Apr 2021)");
  script_name("Debian LTS: Security Advisory for php-nette (DLA-2617-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/04/msg00003.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2617-1");
  script_xref(name:"Advisory-ID", value:"DLA-2617-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php-nette'
  package(s) announced via the DLA-2617-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Cyku Hong from DEVCORE discovered that php-nette, a PHP MVC framework, is
vulnerable to a code injection attack by passing specially formed parameters to
URL that may possibly leading to remote code execution.");

  script_tag(name:"affected", value:"'php-nette' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, this problem has been fixed in version
2.4-20160731-1+deb9u1.

We recommend that you upgrade your php-nette packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"php-nette", ver:"2.4-20160731-1+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
