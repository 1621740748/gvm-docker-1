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
  script_oid("1.3.6.1.4.1.25623.1.0.891142");
  script_version("2021-06-18T02:00:26+0000");
  script_cve_id("CVE-2015-8365", "CVE-2017-7208", "CVE-2017-7862", "CVE-2017-9992");
  script_name("Debian LTS: Security Advisory for libav (DLA-1142-1)");
  script_tag(name:"last_modification", value:"2021-06-18 02:00:26 +0000 (Fri, 18 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-02-07 00:00:00 +0100 (Wed, 07 Feb 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-27 11:29:00 +0000 (Tue, 27 Nov 2018)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2017/10/msg00021.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_tag(name:"affected", value:"libav on Debian Linux");

  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
6:0.8.21-0+deb7u1.

We recommend that you upgrade your libav packages.");

  script_tag(name:"summary", value:"Multiple vulnerabilities have been found in libav:

CVE-2015-8365

The smka_decode_frame function in libavcodec/smacker.c does not verify that
the data size is consistent with the number of channels, which allows remote
attackers to cause a denial of service (out-of-bounds array access) or
possibly have unspecified other impact via crafted Smacker data.

CVE-2017-7208

The decode_residual function in libavcodec allows remote attackers to cause
a denial of service (buffer over-read) or obtain sensitive information from
process memory via a crafted h264 video file.

CVE-2017-7862

The decode_frame function in libavcodec/pictordec.c is vulnerable to an
out-of-bounds write caused by a heap-based buffer overflow.

CVE-2017-9992

The decode_dds1 function in libavcodec/dfa.c allows remote attackers to
cause a denial of service (Heap-based buffer overflow and application crash)
or possibly have unspecified other impact via a crafted file.");

  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"ffmpeg", ver:"6:0.8.21-0+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ffmpeg-dbg", ver:"6:0.8.21-0+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ffmpeg-doc", ver:"6:0.8.21-0+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libav-dbg", ver:"6:0.8.21-0+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libav-doc", ver:"6:0.8.21-0+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libav-extra-dbg", ver:"6:0.8.21-0+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libav-tools", ver:"6:0.8.21-0+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavcodec-dev", ver:"6:0.8.21-0+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavcodec-extra-53", ver:"6:0.8.21-0+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavcodec53", ver:"6:0.8.21-0+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavdevice-dev", ver:"6:0.8.21-0+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavdevice-extra-53", ver:"6:0.8.21-0+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavdevice53", ver:"6:0.8.21-0+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavfilter-dev", ver:"6:0.8.21-0+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavfilter-extra-2", ver:"6:0.8.21-0+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavfilter2", ver:"6:0.8.21-0+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavformat-dev", ver:"6:0.8.21-0+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavformat-extra-53", ver:"6:0.8.21-0+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavformat53", ver:"6:0.8.21-0+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavutil-dev", ver:"6:0.8.21-0+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavutil-extra-51", ver:"6:0.8.21-0+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavutil51", ver:"6:0.8.21-0+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpostproc-dev", ver:"6:0.8.21-0+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpostproc-extra-52", ver:"6:0.8.21-0+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpostproc52", ver:"6:0.8.21-0+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libswscale-dev", ver:"6:0.8.21-0+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libswscale-extra-2", ver:"6:0.8.21-0+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libswscale2", ver:"6:0.8.21-0+deb7u1", rls:"DEB7"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
