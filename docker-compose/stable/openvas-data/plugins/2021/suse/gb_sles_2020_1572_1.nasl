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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.1572.1");
  script_cve_id("CVE-2020-2754", "CVE-2020-2755", "CVE-2020-2756", "CVE-2020-2757", "CVE-2020-2767", "CVE-2020-2773", "CVE-2020-2778", "CVE-2020-2781", "CVE-2020-2800", "CVE-2020-2803", "CVE-2020-2805", "CVE-2020-2816", "CVE-2020-2830");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-08 13:00:00 +0000 (Tue, 08 Sep 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:1572-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:1572-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20201572-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-11-openjdk' package(s) announced via the SUSE-SU-2020:1572-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-11-openjdk fixes the following issues:

Java was updated to jdk-11.0.7+10 (April 2020 CPU, bsc#1169511).

Security issues fixed:

CVE-2020-2754: Fixed an incorrect handling of regular expressions that
 could have resulted in denial of service (bsc#1169511).

CVE-2020-2755: Fixed an incorrect handling of regular expressions that
 could have resulted in denial of service (bsc#1169511).

CVE-2020-2756: Fixed an incorrect handling of regular expressions that
 could have resulted in denial of service (bsc#1169511).

CVE-2020-2757: Fixed an object deserialization issue that could have
 resulted in denial of service via crafted serialized input (bsc#1169511).

CVE-2020-2767: Fixed an incorrect handling of certificate messages
 during TLS handshakes (bsc#1169511).

CVE-2020-2773: Fixed the incorrect handling of exceptions thrown by
 unmarshalKeyInfo() and unmarshalXMLSignature() (bsc#1169511).

CVE-2020-2778: Fixed the incorrect handling of SSLParameters in
 setAlgorithmConstraints(), which could have been abused to override the
 defined systems security policy and lead to the use of weak crypto
 algorithms (bsc#1169511).

CVE-2020-2781: Fixed the incorrect re-use of single null TLS sessions
 (bsc#1169511).

CVE-2020-2800: Fixed an HTTP header injection issue caused by
 mishandling of CR/LF in header values (bsc#1169511).

CVE-2020-2803: Fixed a boundary check and type check issue that could
 have led to a sandbox bypass (bsc#1169511).

CVE-2020-2805: Fixed a boundary check and type check issue that could
 have led to a sandbox bypass (bsc#1169511).

CVE-2020-2816: Fixed an incorrect handling of application data packets
 during TLS handshakes (bsc#1169511).

CVE-2020-2830: Fixed an incorrect handling of regular expressions that
 could have resulted in denial of service (bsc#1169511).");

  script_tag(name:"affected", value:"'java-11-openjdk' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk", rpm:"java-11-openjdk~11.0.7.0~3.9.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-debuginfo", rpm:"java-11-openjdk-debuginfo~11.0.7.0~3.9.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-debugsource", rpm:"java-11-openjdk-debugsource~11.0.7.0~3.9.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-demo", rpm:"java-11-openjdk-demo~11.0.7.0~3.9.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-devel", rpm:"java-11-openjdk-devel~11.0.7.0~3.9.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-headless", rpm:"java-11-openjdk-headless~11.0.7.0~3.9.2", rls:"SLES12.0SP5"))) {
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
