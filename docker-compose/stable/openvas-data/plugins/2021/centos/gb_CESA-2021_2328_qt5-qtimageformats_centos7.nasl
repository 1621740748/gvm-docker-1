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
  script_oid("1.3.6.1.4.1.25623.1.0.883358");
  script_version("2021-06-17T06:11:17+0000");
  script_cve_id("CVE-2018-25011", "CVE-2018-25014", "CVE-2020-36328", "CVE-2020-36329");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-06-17 06:11:17 +0000 (Thu, 17 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-15 03:01:12 +0000 (Tue, 15 Jun 2021)");
  script_name("CentOS: Security Advisory for qt5-qtimageformats (CESA-2021:2328)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"Advisory-ID", value:"CESA-2021:2328");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2021-June/048335.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qt5-qtimageformats'
  package(s) announced via the CESA-2021:2328 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Qt Image Formats in an add-on module for the core Qt Gui library that
provides support for additional image formats including MNG, TGA, TIFF,
WBMP, and WebP.

Security Fix(es):

  * libwebp: heap-based buffer overflow in PutLE16() (CVE-2018-25011)

  * libwebp: use of uninitialized value in ReadSymbol() (CVE-2018-25014)

  * libwebp: heap-based buffer overflow in WebPDecode*Into functions
(CVE-2020-36328)

  * libwebp: use-after-free in EmitFancyRGB() in dec/io_dec.c
(CVE-2020-36329)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.");

  script_tag(name:"affected", value:"'qt5-qtimageformats' package(s) on CentOS 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "CentOS7") {

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtimageformats", rpm:"qt5-qtimageformats~5.9.7~2.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtimageformats-doc", rpm:"qt5-qtimageformats-doc~5.9.7~2.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);