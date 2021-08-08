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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0298.1");
  script_cve_id("CVE-2014-9328", "CVE-2015-1461", "CVE-2015-1462", "CVE-2015-1463");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:14 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-03 02:59:00 +0000 (Tue, 03 Jan 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0298-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3|SLES11\.0SP2|SLES11\.0SP1|SLES10\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0298-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150298-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'clamav' package(s) announced via the SUSE-SU-2015:0298-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"clamav was updated to version 0.98.6 to fix four security issues.

These security issues have been fixed:

 * CVE-2015-1462: ClamAV allowed remote attackers to have unspecified
 impact via a crafted upx packer file, related to a heap out of
 bounds condition (bnc#916214).
 * CVE-2015-1463: ClamAV allowed remote attackers to cause a denial of
 service (crash) via a crafted petite packer file, related to an
 incorrect compiler optimization (bnc#916215).
 * CVE-2014-9328: ClamAV allowed remote attackers to have unspecified
 impact via a crafted upack packer file, related to a heap out of
 bounds condition (bnc#915512).
 * CVE-2015-1461: ClamAV allowed remote attackers to have unspecified
 impact via a crafted (1) Yoda's crypter or (2) mew packer file,
 related to a heap out of bounds condition (bnc#916217).

Security Issues:

 * CVE-2015-1462
 * CVE-2014-9328
 * CVE-2015-1463
 * CVE-2015-1461");

  script_tag(name:"affected", value:"'clamav' package(s) on SUSE Linux Enterprise Server 11 SP3, SUSE Linux Enterprise Server 11 SP2, SUSE Linux Enterprise Server 11 SP1, SUSE Linux Enterprise Server 10 SP4, SUSE Linux Enterprise Desktop 11 SP3.");

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

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.98.6~0.6.1", rls:"SLES11.0SP3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.98.6~0.6.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.98.6~0.6.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES10.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.98.6~0.8.1", rls:"SLES10.0SP4"))) {
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
