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
  script_oid("1.3.6.1.4.1.25623.1.0.892581");
  script_version("2021-03-09T09:52:25+0000");
  script_cve_id("CVE-2021-27803");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-03-09 09:52:25 +0000 (Tue, 09 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-03-03 04:00:26 +0000 (Wed, 03 Mar 2021)");
  script_name("Debian LTS: Security Advisory for wpa (DLA-2581-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/03/msg00003.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2581-1");
  script_xref(name:"Advisory-ID", value:"DLA-2581-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wpa'
  package(s) announced via the DLA-2581-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was discovered in how p2p/p2p_pd.c in wpa_supplicant
before 2.10 processes P2P (Wi-Fi Direct) provision discovery requests.
It could result in denial of service or other impact (potentially
execution of arbitrary code), for an attacker within radio range.");

  script_tag(name:"affected", value:"'wpa' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, this problem has been fixed in version
2:2.4-1+deb9u9.

We recommend that you upgrade your wpa packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"hostapd", ver:"2:2.4-1+deb9u9", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"wpagui", ver:"2:2.4-1+deb9u9", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"wpasupplicant", ver:"2:2.4-1+deb9u9", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
