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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0392.1");
  script_cve_id("CVE-2014-3065", "CVE-2014-3566", "CVE-2014-4209", "CVE-2014-4218", "CVE-2014-4219", "CVE-2014-4227", "CVE-2014-4244", "CVE-2014-4252", "CVE-2014-4262", "CVE-2014-4263", "CVE-2014-4265", "CVE-2014-4268", "CVE-2014-4288", "CVE-2014-6457", "CVE-2014-6458", "CVE-2014-6466", "CVE-2014-6492", "CVE-2014-6493", "CVE-2014-6502", "CVE-2014-6503", "CVE-2014-6506", "CVE-2014-6511", "CVE-2014-6512", "CVE-2014-6513", "CVE-2014-6515", "CVE-2014-6531", "CVE-2014-6532", "CVE-2014-6558", "CVE-2014-8891", "CVE-2014-8892");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:14 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-16 12:15:00 +0000 (Wed, 16 Jun 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0392-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP2|SLES11\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0392-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150392-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_6_0-ibm' package(s) announced via the SUSE-SU-2015:0392-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"java-1_6_0-ibm has been updated to version 1.6.0_sr16.3 to fix 30 security issues:

 * CVE-2014-8891: Unspecified vulnerability (bnc#916266)
 * CVE-2014-8892: Unspecified vulnerability (bnc#916265)
 * CVE-2014-3065: Unspecified vulnerability in IBM Java Runtime
 Environment (JRE) 7 R1 before SR2 (7.1.2.0), 7 before SR8 (7.0.8.0),
 6 R1 before SR8 FP2 (6.1.8.2), 6 before SR16 FP2 (6.0.16.2), and
 before SR16 FP8 (5.0.16.8) allowed local users to execute arbitrary
 code via vectors related to the shared classes cache (bnc#904889).
 * CVE-2014-3566: The SSL protocol 3.0, as used in OpenSSL through
 1.0.1i and other products, used nondeterministic CBC padding, which
 made it easier for man-in-the-middle attackers to obtain cleartext
 data via a padding-oracle attack, aka the 'POODLE' issue
 (bnc#901223).
 * CVE-2014-6513: Unspecified vulnerability in Oracle Java SE 6u81,
 7u67, and 8u20, and Java SE Embedded 7u60, allowed remote attackers
 to affect confidentiality, integrity, and availability via vectors
 related to AWT (bnc#904889).
 * CVE-2014-6503: Unspecified vulnerability in Oracle Java SE 6u81,
 7u67, and 8u20 allowed remote attackers to affect confidentiality,
 integrity, and availability via unknown vectors related to
 Deployment, a different vulnerability than CVE-2014-4288,
 CVE-2014-6493, and CVE-2014-6532 (bnc#904889).
 * CVE-2014-6532: Unspecified vulnerability in Oracle Java SE 6u81,
 7u67, and 8u20 allowed remote attackers to affect confidentiality,
 integrity, and availability via unknown vectors related to
 Deployment, a different vulnerability than CVE-2014-4288,
 CVE-2014-6493, and CVE-2014-6503 (bnc#904889).
 * CVE-2014-4288: Unspecified vulnerability in Oracle Java SE 6u81,
 7u67, and 8u20 allowed remote attackers to affect confidentiality,
 integrity, and availability via unknown vectors related to
 Deployment, a different vulnerability than CVE-2014-6493,
 CVE-2014-6503, and CVE-2014-6532 (bnc#904889).
 * CVE-2014-6493: Unspecified vulnerability in Oracle Java SE 6u81,
 7u67, and 8u20 allowed remote attackers to affect confidentiality,
 integrity, and availability via unknown vectors related to
 Deployment, a different vulnerability than CVE-2014-4288,
 CVE-2014-6503, and CVE-2014-6532 (bnc#904889).
 * CVE-2014-6492: Unspecified vulnerability in Oracle Java SE 6u81,
 7u67, and 8u20, when running on Firefox, allowed remote attackers to
 affect confidentiality, integrity, and availability via unknown
 vectors related to Deployment (bnc#904889).
 * CVE-2014-6458: Unspecified vulnerability in Oracle Java SE 6u81,
 7u67, and 8u20 allowed local users to affect confidentiality,
 integrity, and availability via unknown vectors related to
 Deployment (bnc#904889).
 * CVE-2014-6466: Unspecified vulnerability in Oracle Java SE 6u81,
 7u67, and 8u20, when running on Internet Explorer, allowed local
 users to affect confidentiality, integrity, and availability ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'java-1_6_0-ibm' package(s) on SUSE Linux Enterprise Server 11 SP2, SUSE Linux Enterprise Server 11 SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-ibm", rpm:"java-1_6_0-ibm~1.6.0_sr16.3~0.4.5", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-ibm-devel", rpm:"java-1_6_0-ibm-devel~1.6.0_sr16.3~0.4.5", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-ibm-fonts", rpm:"java-1_6_0-ibm-fonts~1.6.0_sr16.3~0.4.5", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-ibm-jdbc", rpm:"java-1_6_0-ibm-jdbc~1.6.0_sr16.3~0.4.5", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-ibm-plugin", rpm:"java-1_6_0-ibm-plugin~1.6.0_sr16.3~0.4.5", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-ibm-alsa", rpm:"java-1_6_0-ibm-alsa~1.6.0_sr16.3~0.4.5", rls:"SLES11.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-ibm", rpm:"java-1_6_0-ibm~1.6.0_sr16.3~0.4.5", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-ibm-fonts", rpm:"java-1_6_0-ibm-fonts~1.6.0_sr16.3~0.4.5", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-ibm-jdbc", rpm:"java-1_6_0-ibm-jdbc~1.6.0_sr16.3~0.4.5", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-ibm-plugin", rpm:"java-1_6_0-ibm-plugin~1.6.0_sr16.3~0.4.5", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-ibm-alsa", rpm:"java-1_6_0-ibm-alsa~1.6.0_sr16.3~0.4.5", rls:"SLES11.0SP1"))) {
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
