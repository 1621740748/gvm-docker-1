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
  script_oid("1.3.6.1.4.1.25623.1.0.892630");
  script_version("2021-04-27T06:50:40+0000");
  script_cve_id("CVE-2021-29447", "CVE-2021-29450");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-04-27 06:50:40 +0000 (Tue, 27 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-22 03:01:17 +0000 (Thu, 22 Apr 2021)");
  script_name("Debian LTS: Security Advisory for wordpress (DLA-2630-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/04/msg00017.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2630-1");
  script_xref(name:"Advisory-ID", value:"DLA-2630-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/987065");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wordpress'
  package(s) announced via the DLA-2630-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2021-29447

Wordpress is an open source CMS. A user with the ability to
upload files (like an Author) can exploit an XML parsing issue
in the Media Library leading to XXE attacks. This requires
WordPress installation to be using PHP 8. Access to internal
files is possible in a successful XXE attack.

CVE-2021-29450

Wordpress is an open source CMS. One of the blocks in the
WordPress editor can be exploited in a way that exposes
password-protected posts and pages. This requires at least
contributor privileges.");

  script_tag(name:"affected", value:"'wordpress' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
4.7.20+dfsg-1+deb9u1.

We recommend that you upgrade your wordpress packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"wordpress", ver:"4.7.20+dfsg-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"wordpress-l10n", ver:"4.7.20+dfsg-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"wordpress-theme-twentyfifteen", ver:"4.7.20+dfsg-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"wordpress-theme-twentyseventeen", ver:"4.7.20+dfsg-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"wordpress-theme-twentysixteen", ver:"4.7.20+dfsg-1+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
