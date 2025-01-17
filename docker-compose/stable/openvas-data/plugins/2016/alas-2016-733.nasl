# Copyright (C) 2016 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of their respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.120722");
  script_version("2020-03-13T13:19:50+0000");
  script_tag(name:"creation_date", value:"2016-10-26 15:38:19 +0300 (Wed, 26 Oct 2016)");
  script_tag(name:"last_modification", value:"2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)");
  script_name("Amazon Linux: Security Advisory (ALAS-2016-733)");
  script_tag(name:"insight", value:"Multiple flaws have been discovered in libtiff. A remote attacker could exploit these flaws to cause a crash or memory corruption and, possibly, execute arbitrary code by tricking an application linked against libtiff into processing specially crafted files. (CVE-2014-9655, CVE-2015-1547, CVE-2015-8784, CVE-2015-8683, CVE-2015-8665, CVE-2015-8781, CVE-2015-8782, CVE-2015-8783, CVE-2016-3990, CVE-2016-5320 )Multiple flaws have been discovered in various libtiff tools (bmp2tiff, pal2rgb, thumbnail, tiff2bw, tiff2pdf, tiffcrop, tiffdither, tiffsplit, tiff2rgba). By tricking a user into processing a specially crafted file, a remote attacker could exploit these flaws to cause a crash or memory corruption and, possibly, execute arbitrary code with the privileges of the user running the libtiff tool. (CVE-2014-8127, CVE-2014-8129, CVE-2014-8130, CVE-2014-9330, CVE-2015-7554, CVE-2015-8668, CVE-2016-3632, CVE-2016-3945, CVE-2016-3991 )");
  script_tag(name:"solution", value:"Run yum update libtiff to update your system.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2016-733.html");
  script_cve_id("CVE-2016-3991", "CVE-2015-7554", "CVE-2016-3990", "CVE-2016-3632", "CVE-2014-8130", "CVE-2015-8781", "CVE-2015-8782", "CVE-2015-8783", "CVE-2014-8127", "CVE-2015-1547", "CVE-2015-8683", "CVE-2015-8784", "CVE-2014-9655", "CVE-2016-3945", "CVE-2016-5320", "CVE-2015-8665", "CVE-2014-8129", "CVE-2014-9330", "CVE-2015-8668");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"The remote host is missing an update announced via the referenced Security Advisory.");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Amazon Linux Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "AMAZON") {
  if(!isnull(res = isrpmvuln(pkg:"libtiff-devel", rpm:"libtiff-devel~4.0.3~25.27.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff", rpm:"libtiff~4.0.3~25.27.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff-static", rpm:"libtiff-static~4.0.3~25.27.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff-debuginfo", rpm:"libtiff-debuginfo~4.0.3~25.27.amzn1", rls:"AMAZON"))) {
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
