# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.850889");
  script_version("2020-01-31T07:58:03+0000");
  script_tag(name:"last_modification", value:"2020-01-31 07:58:03 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2015-10-16 13:36:02 +0200 (Fri, 16 Oct 2015)");
  script_cve_id("CVE-2014-3065", "CVE-2014-3566", "CVE-2014-4288", "CVE-2014-6456", "CVE-2014-6457", "CVE-2014-6458", "CVE-2014-6466", "CVE-2014-6476", "CVE-2014-6492", "CVE-2014-6493", "CVE-2014-6502", "CVE-2014-6503", "CVE-2014-6506", "CVE-2014-6511", "CVE-2014-6512", "CVE-2014-6513", "CVE-2014-6515", "CVE-2014-6527", "CVE-2014-6531", "CVE-2014-6532", "CVE-2014-6558");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SUSE: Security Advisory for java-1_7_1-ibm (SUSE-SU-2014:1549-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_7_1-ibm'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"java-1_7_1-ibm was updated to version 1.7.1_sr1.2 to fix 21 security
  issues.

  These security issues were fixed:

  - Unspecified vulnerability in Oracle Java (CVE-2014-3065).

  - The SSL protocol 3.0, as used in OpenSSL through 1.0.1i and
  other products, uses nondeterministic CBC padding, which makes it easier
  for man-in-the-middle attackers to obtain cleartext data via a
  padding-oracle attack, aka the 'POODLE' issue (CVE-2014-3566).

  - Unspecified vulnerability in Oracle Java SE 6u81, 7u67, and 8u20, and
  Java SE Embedded 7u60, allows remote attackers to affect
  confidentiality, integrity, and availability via vectors related to AWT
  (CVE-2014-6513).

  - Unspecified vulnerability in Oracle Java SE 7u67 and 8u20 allows remote
  attackers to affect confidentiality, integrity, and availability via
  unknown vectors (CVE-2014-6456).

  - Unspecified vulnerability in Oracle Java SE 6u81, 7u67, and 8u20 allows
  remote attackers to affect confidentiality, integrity, and availability
  via unknown vectors related to Deployment, a different vulnerability
  than CVE-2014-4288, CVE-2014-6493, and CVE-2014-6532 (CVE-2014-6503).

  - Unspecified vulnerability in Oracle Java SE 6u81, 7u67, and 8u20 allows
  remote attackers to affect confidentiality, integrity, and availability
  via unknown vectors related to Deployment, a different vulnerability
  than CVE-2014-4288, CVE-2014-6493, and CVE-2014-6503 (CVE-2014-6532).

  - Unspecified vulnerability in Oracle Java SE 6u81, 7u67, and 8u20 allows
  remote attackers to affect confidentiality, integrity, and availability
  via unknown vectors related to Deployment, a different vulnerability
  than CVE-2014-6493, CVE-2014-6503, and CVE-2014-6532 (CVE-2014-4288).

  - Unspecified vulnerability in Oracle Java SE 6u81, 7u67, and 8u20 allows
  remote attackers to affect confidentiality, integrity, and availability
  via unknown vectors related to Deployment, a different vulnerability
  than CVE-2014-4288, CVE-2014-6503, and CVE-2014-6532 (CVE-2014-6493).

  - Unspecified vulnerability in Oracle Java SE 6u81, 7u67, and 8u20, when
  running on Firefox, allows remote attackers to affect confidentiality,
  integrity, and availability via unknown vectors related to Deployment
  (CVE-2014-6492).

  - Unspecified vulnerability in Oracle Java SE 6u81, 7u67, and 8u20 allows
  local users to affect confidentiality, integrity, and availability via
  unknown vectors related to Deployment (CVE-2014-6458).

  - Unspecified vulnerability in Oracle Java SE 6u81, 7u67, and 8u20, when
  running on Internet Explorer, allows local users to affect
   ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"affected", value:"java-1_7_1-ibm on SUSE Linux Enterprise Server 12");

  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"SUSE-SU", value:"2014:1549-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=SLES12\.0SP0");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES12.0SP0") {
  if(!isnull(res = isrpmvuln(pkg:"java-1_7_1-ibm", rpm:"java-1_7_1-ibm~1.7.1_sr2.0~4.1", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_1-ibm-jdbc", rpm:"java-1_7_1-ibm-jdbc~1.7.1_sr2.0~4.1", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_1-ibm-alsa", rpm:"java-1_7_1-ibm-alsa~1.7.1_sr2.0~4.1", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_1-ibm-plugin", rpm:"java-1_7_1-ibm-plugin~1.7.1_sr2.0~4.1", rls:"SLES12.0SP0"))) {
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
