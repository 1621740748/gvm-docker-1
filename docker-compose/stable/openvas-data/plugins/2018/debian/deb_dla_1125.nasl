# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.891125");
  script_version("2021-06-18T02:00:26+0000");
  script_cve_id("CVE-2017-14737");
  script_name("Debian LTS: Security Advisory for botan1.10 (DLA-1125-1)");
  script_tag(name:"last_modification", value:"2021-06-18 02:00:26 +0000 (Fri, 18 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-02-07 00:00:00 +0100 (Wed, 07 Feb 2018)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2017/10/msg00005.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_tag(name:"affected", value:"botan1.10 on Debian Linux");

  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
1.10.5-1+deb7u4.

We recommend that you upgrade your botan1.10 packages.");

  script_tag(name:"summary", value:"CVE-2017-14737
Fix of cache-based side channel attack, which could recover
information about RSA secret keys.");

  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"botan1.10-dbg", ver:"1.10.5-1+deb7u4", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libbotan-1.10-0", ver:"1.10.5-1+deb7u4", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libbotan1.10-dev", ver:"1.10.5-1+deb7u4", rls:"DEB7"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
