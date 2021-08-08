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
  script_oid("1.3.6.1.4.1.25623.1.0.891042");
  script_version("2021-06-21T11:00:26+0000");
  script_cve_id("CVE-2017-9122", "CVE-2017-9123", "CVE-2017-9124", "CVE-2017-9125", "CVE-2017-9126", "CVE-2017-9127", "CVE-2017-9128");
  script_name("Debian LTS: Security Advisory for libquicktime (DLA-1042-1)");
  script_tag(name:"last_modification", value:"2021-06-21 11:00:26 +0000 (Mon, 21 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-02-08 00:00:00 +0100 (Thu, 08 Feb 2018)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-28 21:15:00 +0000 (Mon, 28 Sep 2020)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2017/07/msg00036.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_tag(name:"affected", value:"libquicktime on Debian Linux");

  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
2:1.2.4-3+deb7u2.

We recommend that you upgrade your libquicktime packages.");

  script_tag(name:"summary", value:"CVE-2017-9122

The quicktime_read_moov function in moov.c in libquicktime 1.2.4 allows
remote attackers to cause a denial of service (infinite loop and CPU
consumption) via a crafted mp4 file.

CVE-2017-9123

The lqt_frame_duration function in lqt_quicktime.c in libquicktime
1.2.4 allows remote attackers to cause a denial of service (invalid
memory read and application crash) via a crafted mp4 file.

CVE-2017-9124

The quicktime_match_32 function in util.c in libquicktime 1.2.4 allows
remote attackers to cause a denial of service (NULL pointer dereference
and application crash) via a crafted mp4 file.

CVE-2017-9125

The lqt_frame_duration function in lqt_quicktime.c in libquicktime
1.2.4 allows remote attackers to cause a denial of service (heap-based
buffer over-read) via a crafted mp4 file.

CVE-2017-9126

The quicktime_read_dref_table function in dref.c in libquicktime 1.2.4
allows remote attackers to cause a denial of service (heap-based buffer
overflow and application crash) via a crafted mp4 file.

CVE-2017-9127

The quicktime_user_atoms_read_atom function in useratoms.c in
libquicktime 1.2.4 allows remote attackers to cause a denial of service
(heap-based buffer overflow and application crash) via a crafted mp4
file.

CVE-2017-9128

The quicktime_video_width function in lqt_quicktime.c in libquicktime
1.2.4 allows remote attackers to cause a denial of service (heap-based
buffer over-read and application crash) via a crafted mp4 file.");

  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libquicktime-dev", ver:"2:1.2.4-3+deb7u2", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libquicktime-doc", ver:"2:1.2.4-3+deb7u2", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libquicktime2", ver:"2:1.2.4-3+deb7u2", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"quicktime-utils", ver:"2:1.2.4-3+deb7u2", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"quicktime-x11utils", ver:"2:1.2.4-3+deb7u2", rls:"DEB7"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
