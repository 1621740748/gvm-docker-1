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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.1939.1");
  script_cve_id("CVE-2015-2304", "CVE-2015-8918", "CVE-2015-8920", "CVE-2015-8921", "CVE-2015-8924", "CVE-2015-8929", "CVE-2016-4809");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:05 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-01 01:29:00 +0000 (Sat, 01 Jul 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:1939-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4|SLES11\.0SP3|SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:1939-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20161939-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bsdtar' package(s) announced via the SUSE-SU-2016:1939-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"bsdtar was updated to fix seven security issues.
These security issues were fixed:
- CVE-2015-8929: Memory leak in tar parser (bsc#985669).
- CVE-2016-4809: Memory allocate error with symbolic links in cpio
 archives (bsc#984990).
- CVE-2015-8920: Stack out of bounds read in ar parser (bsc#985675).
- CVE-2015-8921: Global out of bounds read in mtree parser (bsc#985682).
- CVE-2015-8924: Heap buffer read overflow in tar (bsc#985609).
- CVE-2015-8918: Overlapping memcpy in CAB parser (bsc#985698).
- CVE-2015-2304: Reject absolute paths in input mode of bsdcpio exactly
 when '..' is rejected (bsc#920870).");

  script_tag(name:"affected", value:"'bsdtar' package(s) on SUSE Studio Onsite 1.3, SUSE OpenStack Cloud 5, SUSE Manager Proxy 2.1, SUSE Manager 2.1, SUSE Linux Enterprise Software Development Kit 11-SP4, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server 11-SP2, SUSE Linux Enterprise Point of Sale 11-SP3, SUSE Linux Enterprise Debuginfo 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libarchive2", rpm:"libarchive2~2.5.5~9.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libarchive2", rpm:"libarchive2~2.5.5~9.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libarchive2", rpm:"libarchive2~2.5.5~9.1", rls:"SLES11.0SP2"))) {
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
