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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.2411.1");
  script_cve_id("CVE-2018-3058", "CVE-2018-3063", "CVE-2018-3066", "CVE-2018-3070", "CVE-2018-3081");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:38 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:2411-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:2411-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20182411-1/");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-61.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql' package(s) announced via the SUSE-SU-2018:2411-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for mysql to version 5.5.61 fixes the following issues:
The following security vulnerabilities were addressed:
- CVE-2018-3066: Fixed a difficult to exploit vulnerability that allowed
 high privileged attacker with network access via multiple protocols to
 compromise MySQL Server. Successful attacks of this vulnerability can
 result in unauthorized update, insert or delete access to some of MySQL
 Server accessible data as well as unauthorized read access to a subset
 of MySQL Server accessible data. (bsc#1101678)
- CVE-2018-3070: Fixed an easily exploitable vulnerability that allowed
 low privileged attacker with network access via multiple protocols to
 compromise MySQL Server. Successful attacks of this vulnerability can
 result in unauthorized ability to cause a hang or frequently repeatable
 crash (complete DOS) of MySQL Server. (bsc#1101679)
- CVE-2018-3081: Fixed a difficult to exploit vulnerability that allowed
 high privileged attacker with network access via multiple protocols to
 compromise MySQL Client. Successful attacks of this vulnerability can
 result in unauthorized ability to cause a hang or frequently repeatable
 crash (complete DOS) of MySQL Client as well as unauthorized update,
 insert or delete access to some of MySQL Client accessible data.
 (bsc#1101680)
- CVE-2018-3058: Fixed an easily exploitable vulnerability that allowed
 low privileged attacker with network access via multiple protocols to
 compromise MySQL Server. Successful attacks of this vulnerability can
 result in unauthorized update, insert or delete access to some of MySQL
 Server accessible data. (bsc#1101676)
- CVE-2018-3063: Fixed an easily exploitable vulnerability allowed high
 privileged attacker with network access via multiple protocols to
 compromise MySQL Server. Successful attacks of this vulnerability can
 result in unauthorized ability to cause a hang or frequently repeatable
 crash (complete DOS) of MySQL Server. (bsc#1101677)
 You can find more detailed information about this update in the [release notes]([link moved to references])");

  script_tag(name:"affected", value:"'mysql' package(s) on SUSE Linux Enterprise Software Development Kit 11-SP4, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Debuginfo 11-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"libmysql55client18", rpm:"libmysql55client18~5.5.61~0.39.15.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql55client_r18", rpm:"libmysql55client_r18~5.5.61~0.39.15.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql", rpm:"mysql~5.5.61~0.39.15.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-client", rpm:"mysql-client~5.5.61~0.39.15.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-tools", rpm:"mysql-tools~5.5.61~0.39.15.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql55client18-32bit", rpm:"libmysql55client18-32bit~5.5.61~0.39.15.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql55client_r18-32bit", rpm:"libmysql55client_r18-32bit~5.5.61~0.39.15.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql55client18-x86", rpm:"libmysql55client18-x86~5.5.61~0.39.15.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql55client_r18-x86", rpm:"libmysql55client_r18-x86~5.5.61~0.39.15.1", rls:"SLES11.0SP4"))) {
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
