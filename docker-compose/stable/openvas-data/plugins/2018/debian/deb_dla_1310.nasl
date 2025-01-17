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
  script_oid("1.3.6.1.4.1.25623.1.0.891310");
  script_version("2021-06-21T11:00:26+0000");
  script_cve_id("CVE-2017-18233", "CVE-2017-18234", "CVE-2017-18236", "CVE-2017-18238", "CVE-2018-7728", "CVE-2018-7730");
  script_name("Debian LTS: Security Advisory for exempi (DLA-1310-1)");
  script_tag(name:"last_modification", value:"2021-06-21 11:00:26 +0000 (Mon, 21 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-03-27 00:00:00 +0200 (Tue, 27 Mar 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-06 17:15:00 +0000 (Tue, 06 Aug 2019)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/03/msg00013.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_tag(name:"affected", value:"exempi on Debian Linux");

  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
2.2.0-1+deb7u1.

We recommend that you upgrade your exempi packages.");

  script_tag(name:"summary", value:"Various issues were discovered in exempi, a library to parse XMP
metadata that may cause a denial-of-service or may have other
unspecified impact via crafted files.

CVE-2017-18233
An Integer overflow in the Chunk class in RIFF.cpp allows remote
attackers to cause a denial of service (infinite loop) via crafted
XMP data in an .avi file.

CVE-2017-18234
An issue was discovered that allows remote attackers to cause a
denial of service (invalid memcpy with resultant use-after-free)
or possibly have unspecified other impact via a .pdf file containing
JPEG data.

CVE-2017-18236
The ASF_Support::ReadHeaderObject function in ASF_Support.cpp allows
remote attackers to cause a denial of service (infinite loop) via a
crafted .asf file.

CVE-2017-18238
The TradQT_Manager::ParseCachedBoxes function in
QuickTime_Support.cpp allows remote attackers to cause
a denial of service (infinite loop) via crafted XMP data in
a .qt file.

CVE-2018-7728
TIFF_Handler.cpp mishandles a case of a zero length, leading to a
heap-based buffer over-read in the MD5Update() function in
MD5.cpp.

CVE-2018-7730
A certain case of a 0xffffffff length is mishandled in
PSIR_FileWriter.cpp, leading to a heap-based buffer over-read
in the PSD_MetaHandler::CacheFileData() function.");

  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libexempi-dev", ver:"2.2.0-1+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libexempi3", ver:"2.2.0-1+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libexempi3-dbg", ver:"2.2.0-1+deb7u1", rls:"DEB7"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
