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
  script_oid("1.3.6.1.4.1.25623.1.0.891882");
  script_version("2020-01-29T08:22:52+0000");
  script_cve_id("CVE-2017-1000159", "CVE-2019-1010006", "CVE-2019-11459");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-29 08:22:52 +0000 (Wed, 29 Jan 2020)");
  script_tag(name:"creation_date", value:"2019-08-14 02:00:12 +0000 (Wed, 14 Aug 2019)");
  script_name("Debian LTS: Security Advisory for atril (DLA-1882-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/08/msg00014.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-1882-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'atril'
  package(s) announced via the DLA-1882-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A few issues were found in Atril, the MATE document viewer.

CVE-2017-1000159

When printing from DVI to PDF, the dvipdfm tool was called without
properly sanitizing the filename, which could lead to a command
injection attack via the filename.

CVE-2019-11459

The tiff_document_render() and tiff_document_get_thumbnail() did
not check the status of TIFFReadRGBAImageOriented(), leading to
uninitialized memory access if that function fails.

CVE-2019-1010006

Some buffer overflow checks were not properly done, leading to
application crash or possibly arbitrary code execution when
opening maliciously crafted files.");

  script_tag(name:"affected", value:"'atril' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
1.8.1+dfsg1-4+deb8u2.

We recommend that you upgrade your atril packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"atril", ver:"1.8.1+dfsg1-4+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"atril-common", ver:"1.8.1+dfsg1-4+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"atril-dbg", ver:"1.8.1+dfsg1-4+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libatrildocument-dev", ver:"1.8.1+dfsg1-4+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libatrildocument3", ver:"1.8.1+dfsg1-4+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libatrildocument3-dbg", ver:"1.8.1+dfsg1-4+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libatrilview-dev", ver:"1.8.1+dfsg1-4+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libatrilview3", ver:"1.8.1+dfsg1-4+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libatrilview3-dbg", ver:"1.8.1+dfsg1-4+deb8u2", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
