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
  script_oid("1.3.6.1.4.1.25623.1.0.850827");
  script_version("2020-01-31T07:58:03+0000");
  script_tag(name:"last_modification", value:"2020-01-31 07:58:03 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2015-10-13 18:35:01 +0530 (Tue, 13 Oct 2015)");
  script_cve_id("CVE-2014-3569", "CVE-2014-3570", "CVE-2014-3571", "CVE-2014-3572", "CVE-2014-8275",
                "CVE-2015-0204", "CVE-2015-0205", "CVE-2015-0206", "CVE-2015-0405", "CVE-2015-0423",
                "CVE-2015-0433", "CVE-2015-0438", "CVE-2015-0439", "CVE-2015-0441", "CVE-2015-0498",
                "CVE-2015-0499", "CVE-2015-0500", "CVE-2015-0501", "CVE-2015-0503", "CVE-2015-0505",
                "CVE-2015-0506", "CVE-2015-0507", "CVE-2015-0508", "CVE-2015-0511", "CVE-2015-2305",
                "CVE-2015-2566", "CVE-2015-2567", "CVE-2015-2568", "CVE-2015-2571", "CVE-2015-2573",
                "CVE-2015-2576");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SUSE: Security Advisory for MySQL (SUSE-SU-2015:0946-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MySQL'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"MySQL was updated to version 5.5.43 to fix several security and non
  security issues:

  * CVEs fixed: CVE-2014-3569, CVE-2014-3570, CVE-2014-3571,
  CVE-2014-3572, CVE-2014-8275, CVE-2015-0204, CVE-2015-0205,
  CVE-2015-0206, CVE-2015-0405, CVE-2015-0423, CVE-2015-0433,
  CVE-2015-0438, CVE-2015-0439, CVE-2015-0441, CVE-2015-0498,
  CVE-2015-0499, CVE-2015-0500, CVE-2015-0501, CVE-2015-0503,
  CVE-2015-0505, CVE-2015-0506, CVE-2015-0507, CVE-2015-0508,
  CVE-2015-0511, CVE-2015-2566, CVE-2015-2567, CVE-2015-2568,
  CVE-2015-2571, CVE-2015-2573, CVE-2015-2576.

  * Fix integer overflow in regcomp (Henry Spencer's regex library) for
  excessively long pattern strings. (bnc#922043, CVE-2015-2305)");

  script_tag(name:"affected", value:"MySQL on SUSE Linux Enterprise Server 11 SP3");

  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"SUSE-SU", value:"2015:0946-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=SLES11\.0SP3");

  script_xref(name:"URL", value:"http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-43.html");

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
  if(!isnull(res = isrpmvuln(pkg:"libmysql55client18", rpm:"libmysql55client18~5.5.43~0.7.3", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql55client_r18", rpm:"libmysql55client_r18~5.5.43~0.7.3", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient15", rpm:"libmysqlclient15~5.0.96~0.6.20", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient_r15", rpm:"libmysqlclient_r15~5.0.96~0.6.20", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql", rpm:"mysql~5.5.43~0.7.3", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-client", rpm:"mysql-client~5.5.43~0.7.3", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-tools", rpm:"mysql-tools~5.5.43~0.7.3", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql55client18-32bit", rpm:"libmysql55client18-32bit~5.5.43~0.7.3", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient15-32bit", rpm:"libmysqlclient15-32bit~5.0.96~0.6.20", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql55client18-x86", rpm:"libmysql55client18-x86~5.5.43~0.7.3", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient15-x86", rpm:"libmysqlclient15-x86~5.0.96~0.6.20", rls:"SLES11.0SP3"))) {
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
