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
  script_oid("1.3.6.1.4.1.25623.1.0.892319");
  script_version("2021-07-27T02:00:54+0000");
  script_cve_id("CVE-2020-4044");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-07-27 02:00:54 +0000 (Tue, 27 Jul 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-14 21:15:00 +0000 (Fri, 14 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-17 13:22:01 +0000 (Mon, 17 Aug 2020)");
  script_name("Debian LTS: Security Advisory for xrdp (DLA-2319-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/08/msg00015.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2319-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/964573");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xrdp'
  package(s) announced via the DLA-2319-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"xrdp-sesman service in xrdp can be crashed by connecting over port 3350
and supplying a malicious payload. Once the xrdp-sesman process is dead,
an unprivileged attacker on the server could then proceed to start their
own imposter sesman service listening on port 3350. This will allow them
to capture any user credentials that are submitted to XRDP and approve or
reject arbitrary login credentials. For xorgxrdp sessions in particular,
this allows an unauthorized user to hijack an existing session. This is a
buffer overflow attack, so there may be a risk of arbitrary code
execution as well.");

  script_tag(name:"affected", value:"'xrdp' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, this problem has been fixed in version
0.9.1-9+deb9u4.

We recommend that you upgrade your xrdp packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"xorgxrdp", ver:"0.9.1-9+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xrdp", ver:"0.9.1-9+deb9u4", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
