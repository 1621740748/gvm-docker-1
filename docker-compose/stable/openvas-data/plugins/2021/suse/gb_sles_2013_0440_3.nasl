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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2013.0440.3");
  script_cve_id("CVE-2013-0424", "CVE-2013-0425", "CVE-2013-0426", "CVE-2013-0428", "CVE-2013-0432", "CVE-2013-0434", "CVE-2013-0440", "CVE-2013-0442", "CVE-2013-0443", "CVE-2013-1476", "CVE-2013-1478", "CVE-2013-1480", "CVE-2013-1481");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:25 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-19 01:35:00 +0000 (Tue, 19 Sep 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2013:0440-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP1|SLES10\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2013:0440-3");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2013/suse-su-20130440-3/");
  script_xref(name:"URL", value:"http://www.ibm.com/developerworks/java/jdk/alerts/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Java' package(s) announced via the SUSE-SU-2013:0440-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"IBM Java 1.4.2 has been updated to SR13-FP15 which fixes various critical security issues and bugs.

Please see the IBM JDK Alert page for more information:

[link moved to references]

Security issues fixed:

CVE-2013-1478, CVE-2013-1480, CVE-2013-1476, CVE-2013-0442,
CVE-2013-0425, CVE-2013-0426, CVE-2013-0428,
CVE-2013-1481, CVE-2013-0432, CVE-2013-0434,
CVE-2013-0424, CVE-2013-0440, CVE-2013-0443.");

  script_tag(name:"affected", value:"'Java' package(s) on SUSE Linux Enterprise Server 11 SP1, SUSE Linux Enterprise Server 10 SP3.");

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

if(release == "SLES11.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_4_2-ibm", rpm:"java-1_4_2-ibm~1.4.2_sr13.15~0.3.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_4_2-ibm-jdbc", rpm:"java-1_4_2-ibm-jdbc~1.4.2_sr13.15~0.3.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_4_2-ibm-plugin", rpm:"java-1_4_2-ibm-plugin~1.4.2_sr13.15~0.3.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES10.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_4_2-ibm", rpm:"java-1_4_2-ibm~1.4.2_sr13.15~0.6.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_4_2-ibm-devel", rpm:"java-1_4_2-ibm-devel~1.4.2_sr13.15~0.6.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_4_2-ibm-jdbc", rpm:"java-1_4_2-ibm-jdbc~1.4.2_sr13.15~0.6.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_4_2-ibm-plugin", rpm:"java-1_4_2-ibm-plugin~1.4.2_sr13.15~0.6.1", rls:"SLES10.0SP3"))) {
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
