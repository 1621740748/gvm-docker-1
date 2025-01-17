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
  script_oid("1.3.6.1.4.1.25623.1.0.891809");
  script_version("2020-01-29T08:22:52+0000");
  script_cve_id("CVE-2018-15822", "CVE-2019-11338");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-29 08:22:52 +0000 (Wed, 29 Jan 2020)");
  script_tag(name:"creation_date", value:"2019-06-01 09:22:32 +0000 (Sat, 01 Jun 2019)");
  script_name("Debian LTS: Security Advisory for libav (DLA-1809-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/05/msg00043.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-1809-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libav'
  package(s) announced via the DLA-1809-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two more security issues have been corrected in multiple demuxers and
decoders of the libav multimedia library.

CVE-2018-15822

The flv_write_packet function in libavformat/flvenc.c in libav did
not check for an empty audio packet, leading to an assertion failure.

CVE-2019-11338

libavcodec/hevcdec.c in libav mishandled detection of duplicate first
slices, which allowed remote attackers to cause a denial of service
(NULL pointer dereference and out-of-array access) or possibly have
unspecified other impact via crafted HEVC data.");

  script_tag(name:"affected", value:"'libav' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
6:11.12-1~deb8u7.

We recommend that you upgrade your libav packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libav-dbg", ver:"6:11.12-1~deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libav-doc", ver:"6:11.12-1~deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libav-tools", ver:"6:11.12-1~deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavcodec-dev", ver:"6:11.12-1~deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavcodec-extra", ver:"6:11.12-1~deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavcodec-extra-56", ver:"6:11.12-1~deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavcodec56", ver:"6:11.12-1~deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavdevice-dev", ver:"6:11.12-1~deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavdevice55", ver:"6:11.12-1~deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavfilter-dev", ver:"6:11.12-1~deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavfilter5", ver:"6:11.12-1~deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavformat-dev", ver:"6:11.12-1~deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavformat56", ver:"6:11.12-1~deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavresample-dev", ver:"6:11.12-1~deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavresample2", ver:"6:11.12-1~deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavutil-dev", ver:"6:11.12-1~deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavutil54", ver:"6:11.12-1~deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libswscale-dev", ver:"6:11.12-1~deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libswscale3", ver:"6:11.12-1~deb8u7", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
