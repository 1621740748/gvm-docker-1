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
  script_oid("1.3.6.1.4.1.25623.1.0.892009");
  script_version("2020-01-29T08:22:52+0000");
  script_cve_id("CVE-2017-17095", "CVE-2018-12900", "CVE-2018-18661", "CVE-2019-17546", "CVE-2019-6128");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-29 08:22:52 +0000 (Wed, 29 Jan 2020)");
  script_tag(name:"creation_date", value:"2019-11-27 03:00:12 +0000 (Wed, 27 Nov 2019)");
  script_name("Debian LTS: Security Advisory for tiff (DLA-2009-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/11/msg00027.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2009-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tiff'
  package(s) announced via the DLA-2009-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several issues have been found in tiff, a Tag Image File Format library.

CVE-2019-17546

The RGBA interface contains an integer overflow that might lead
to heap buffer overflow write.

CVE-2019-6128

A memory leak exists due to missing cleanup code.

CVE-2018-18661

In case of exhausted memory there is a null pointer dereference
in tiff2bw.

CVE-2018-12900

Fix for heap-based buffer overflow, that could be used to crash an
application or even to execute arbitrary code (with the permission
of the user running this application).

CVE-2017-17095

A crafted tiff file could lead to a heap buffer overflow in pal2rgb.");

  script_tag(name:"affected", value:"'tiff' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
4.0.3-12.3+deb8u10.

We recommend that you upgrade your tiff packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libtiff-doc", ver:"4.0.3-12.3+deb8u10", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libtiff-opengl", ver:"4.0.3-12.3+deb8u10", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libtiff-tools", ver:"4.0.3-12.3+deb8u10", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libtiff5", ver:"4.0.3-12.3+deb8u10", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libtiff5-dev", ver:"4.0.3-12.3+deb8u10", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libtiffxx5", ver:"4.0.3-12.3+deb8u10", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
