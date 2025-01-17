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
  script_oid("1.3.6.1.4.1.25623.1.0.892573");
  script_version("2021-02-21T04:00:15+0000");
  # TODO: No CVE assigned yet. Check https://security-tracker.debian.org/tracker/TEMP-0982519-32E0AF / https://github.com/facebook/zstd/issues/2491 if a CVE got assigned.
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-02-21 04:00:15 +0000 (Sun, 21 Feb 2021)");
  script_tag(name:"creation_date", value:"2021-02-21 04:00:15 +0000 (Sun, 21 Feb 2021)");
  script_name("Debian LTS: Security Advisory for libzstd (DLA-2573-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/02/msg00034.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2573-1");
  script_xref(name:"Advisory-ID", value:"DLA-2573-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/981404");
  script_xref(name:"URL", value:"https://bugs.debian.org/982519");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libzstd'
  package(s) announced via the DLA-2573-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that zstd, a compression utility, was vulnerable
to a race condition: it temporarily exposed, during a very short
timeframe, a world-readable version of its input even if the
original file had restrictive permissions.");

  script_tag(name:"affected", value:"'libzstd' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, this problem has been fixed in version
1.1.2-1+deb9u1.

We recommend that you upgrade your libzstd packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libzstd-dev", ver:"1.1.2-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libzstd1", ver:"1.1.2-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"zstd", ver:"1.1.2-1+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
