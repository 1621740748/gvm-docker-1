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
  script_oid("1.3.6.1.4.1.25623.1.0.892554");
  script_version("2021-02-19T11:20:59+0000");
  script_cve_id("CVE-2021-26910");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-02-19 11:20:59 +0000 (Fri, 19 Feb 2021)");
  script_tag(name:"creation_date", value:"2021-02-12 04:00:04 +0000 (Fri, 12 Feb 2021)");
  script_name("Debian LTS: Security Advisory for firejail (DLA-2554-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/02/msg00015.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2554-1");
  script_xref(name:"Advisory-ID", value:"DLA-2554-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firejail'
  package(s) announced via the DLA-2554-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Roman Fiedler discovered a vulnerability in the OverlayFS code in
firejail, a sandbox program to restrict the running environment of
untrusted applications, which could result in root privilege
escalation. This update disables OverlayFS support in firejail.");

  script_tag(name:"affected", value:"'firejail' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, this problem has been fixed in version
0.9.44.8-2+deb9u2.

We recommend that you upgrade your firejail packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"firejail", ver:"0.9.44.8-2+deb9u2", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
