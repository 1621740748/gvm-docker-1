# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.891725");
  script_version("2020-01-29T08:22:52+0000");
  script_cve_id("CVE-2016-9840", "CVE-2016-9841", "CVE-2016-9842", "CVE-2016-9843", "CVE-2018-5764");
  script_name("Debian LTS: Security Advisory for rsync (DLA-1725-1)");
  script_tag(name:"last_modification", value:"2020-01-29 08:22:52 +0000 (Wed, 29 Jan 2020)");
  script_tag(name:"creation_date", value:"2019-03-24 23:00:00 +0100 (Sun, 24 Mar 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/03/msg00027.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_tag(name:"affected", value:"rsync on Debian Linux");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
3.1.1-3+deb8u2.

We recommend that you upgrade your rsync packages.");

  script_tag(name:"summary", value:"Trail of Bits used the automated vulnerability discovery tools developed
for the DARPA Cyber Grand Challenge to audit zlib. As rsync, a fast,
versatile, remote (and local) file-copying tool, uses an embedded copy of
zlib, those issues are also present in rsync.

CVE-2016-9840
In order to avoid undefined behavior, remove offset pointer
optimization, as this is not compliant with the C standard.

CVE-2016-9841
Only use post-increment to be compliant with the C standard.

CVE-2016-9842
In order to avoid undefined behavior, do not shift negative values,
as this is not compliant with the C standard.

CVE-2016-9843
In order to avoid undefined behavior, do not pre-decrement a pointer
in big-endian CRC calculation, as this is not compliant with the
C standard.

CVE-2018-5764
Prevent remote attackers from being able to bypass the
argument-sanitization protection mechanism by ignoring --protect-args
when already sent by client.");

  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"rsync", ver:"3.1.1-3+deb8u2", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
