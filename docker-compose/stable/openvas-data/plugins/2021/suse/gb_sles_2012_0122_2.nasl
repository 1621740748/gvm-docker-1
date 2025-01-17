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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2012.0122.2");
  script_cve_id("CVE-2011-3389", "CVE-2011-3545", "CVE-2011-3547", "CVE-2011-3548", "CVE-2011-3549", "CVE-2011-3552", "CVE-2011-3556", "CVE-2011-3557", "CVE-2011-3560");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:28 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-06 02:29:00 +0000 (Sat, 06 Jan 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2012:0122-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP2|SLES11\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2012:0122-2");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2012/suse-su-20120122-2/");
  script_xref(name:"URL", value:"http://www.ibm.com/developerworks/java/jdk/alerts/");
  script_xref(name:"URL", value:"http://www.ibm.com/developerworks/java/jdk/alerts/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'IBM Java 1.4.2' package(s) announced via the SUSE-SU-2012:0122-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"IBM Java 1.4.2 SR13 FP11 has been released and contains various security fixes.

[link moved to references]
[link moved to references]

(CVEs fixed: CVE-2011-3547 CVE-2011-3548 CVE-2011-3549 CVE-2011-3552 CVE-2011-3545 CVE-2011-3556 CVE-2011-3557 CVE-2011-3389 CVE-2011-3560 )

Security Issues:

 * CVE-2011-3389
>
 * CVE-2011-3545
>
 * CVE-2011-3547
>
 * CVE-2011-3548
>
 * CVE-2011-3549
>
 * CVE-2011-3552
>
 * CVE-2011-3556
>
 * CVE-2011-3557
>
 * CVE-2011-3560
>");

  script_tag(name:"affected", value:"'IBM Java 1.4.2' package(s) on SUSE Linux Enterprise for SAP Applications 11 SP1, SUSE Linux Enterprise Software Development Kit 11 SP2, SUSE Linux Enterprise Software Development Kit 11 SP1, SUSE Linux Enterprise Server 11 SP2, SUSE Linux Enterprise Server 11 SP1, SUSE Linux Enterprise Java 11 SP1.");

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

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_4_2-ibm", rpm:"java-1_4_2-ibm~1.4.2_sr13.11~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_4_2-ibm-jdbc", rpm:"java-1_4_2-ibm-jdbc~1.4.2_sr13.11~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_4_2-ibm-plugin", rpm:"java-1_4_2-ibm-plugin~1.4.2_sr13.11~0.5.1", rls:"SLES11.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"java-1_4_2-ibm", rpm:"java-1_4_2-ibm~1.4.2_sr13.11~0.5.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_4_2-ibm-jdbc", rpm:"java-1_4_2-ibm-jdbc~1.4.2_sr13.11~0.5.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_4_2-ibm-plugin", rpm:"java-1_4_2-ibm-plugin~1.4.2_sr13.11~0.5.1", rls:"SLES11.0SP1"))) {
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
