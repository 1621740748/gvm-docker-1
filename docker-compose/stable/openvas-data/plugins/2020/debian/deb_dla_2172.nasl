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
  script_oid("1.3.6.1.4.1.25623.1.0.892172");
  script_version("2021-07-28T02:00:54+0000");
  script_cve_id("CVE-2020-6819", "CVE-2020-6820", "CVE-2020-6821", "CVE-2020-6822", "CVE-2020-6825");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-07-28 02:00:54 +0000 (Wed, 28 Jul 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-01 16:07:00 +0000 (Fri, 01 May 2020)");
  script_tag(name:"creation_date", value:"2020-04-15 03:00:11 +0000 (Wed, 15 Apr 2020)");
  script_name("Debian LTS: Security Advisory for thunderbird (DLA-2172-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/04/msg00006.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2172-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird'
  package(s) announced via the DLA-2172-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues have been found in Thunderbird which could result
in denial of service or potentially the execution of arbitrary code.");

  script_tag(name:"affected", value:"'thunderbird' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
1:68.7.0-1~deb8u1.

We recommend that you upgrade your thunderbird packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"icedove", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-dbg", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-dev", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-all", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-ar", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-ast", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-be", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-bg", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-bn-bd", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-br", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-ca", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-cs", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-da", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-de", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-dsb", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-el", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-en-gb", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-es-ar", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-es-es", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-et", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-eu", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-fi", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-fr", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-fy-nl", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-ga-ie", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-gd", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-gl", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-he", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-hr", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-hsb", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-hu", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-hy-am", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-id", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-is", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-it", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-ja", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-kab", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-ko", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-lt", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-nb-no", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-nl", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-nn-no", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-pa-in", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-pl", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-pt-br", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-pt-pt", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-rm", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-ro", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-ru", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-si", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-sk", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-sl", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-sq", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-sr", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-sv-se", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-ta-lk", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-tr", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-uk", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-vi", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-zh-cn", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-zh-tw", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-extension", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-ar", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-ast", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-be", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-bg", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-bn-bd", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-br", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-ca", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-cs", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-cy", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-da", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-de", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-dsb", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-el", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-en-gb", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-es-ar", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-es-es", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-et", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-eu", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-fi", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-fr", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-fy-nl", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-ga-ie", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-gd", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-gl", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-he", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-hr", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-hsb", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-hu", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-hy-am", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-id", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-is", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-it", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-ja", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-kab", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-ko", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-lt", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-nb-no", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-nl", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-nn-no", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-pa-in", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-pl", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-pt-br", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-pt-pt", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-rm", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-ro", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-ru", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-si", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-sk", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-sl", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-sq", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-sr", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-sv-se", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-ta-lk", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-tr", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-uk", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-vi", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-zh-cn", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-zh-tw", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-ar", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-ast", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-be", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-bg", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-bn-bd", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-br", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-ca", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-cs", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-cy", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-da", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-de", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-dsb", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-el", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-en-gb", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-es-ar", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-es-es", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-et", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-eu", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-fi", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-fr", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-fy-nl", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-ga-ie", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-gd", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-gl", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-he", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-hr", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-hsb", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-hu", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-hy-am", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-id", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-is", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-it", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-ja", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-kab", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-kk", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-ko", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-lt", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-ms", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-nb-no", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-nl", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-nn-no", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-pa-in", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-pl", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-pt-br", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-pt-pt", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-rm", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-ro", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-ru", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-si", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-sk", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-sl", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-sq", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-sr", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-sv-se", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-ta-lk", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-tr", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-uk", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-vi", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-zh-cn", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-zh-tw", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-dbg", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-dev", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-all", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-ar", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-ast", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-be", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-bg", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-bn-bd", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-br", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-ca", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-cs", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-cy", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-da", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-de", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-dsb", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-el", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-en-gb", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-es-ar", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-es-es", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-et", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-eu", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-fi", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-fr", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-fy-nl", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-ga-ie", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-gd", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-gl", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-he", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-hr", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-hsb", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-hu", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-hy-am", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-id", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-is", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-it", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-ja", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-kab", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-kk", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-ko", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-lt", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-ms", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-nb-no", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-nl", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-nn-no", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-pa-in", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-pl", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-pt-br", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-pt-pt", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-rm", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-ro", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-ru", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-si", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-sk", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-sl", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-sq", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-sr", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-sv-se", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-ta-lk", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-tr", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-uk", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-vi", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-zh-cn", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-zh-tw", ver:"1:68.7.0-1~deb8u1", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
