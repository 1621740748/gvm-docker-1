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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.3092.1");
  script_cve_id("CVE-2017-12837", "CVE-2017-12883", "CVE-2017-6512");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-15 03:15:00 +0000 (Wed, 15 Jul 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:3092-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3|SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:3092-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20173092-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl' package(s) announced via the SUSE-SU-2017:3092-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for perl fixes the following issues:
Security issues fixed:
- CVE-2017-12837: Heap-based buffer overflow in the S_regatom function in
 regcomp.c in Perl 5 before 5.24.3-RC1 and 5.26.x before 5.26.1-RC1
 allows remote attackers to cause a denial of service (out-of-bounds
 write) via a regular expression with a '\N{}' escape and the
 case-insensitive modifier. (bnc#1057724)
- CVE-2017-12883: Buffer overflow in the S_grok_bslash_N function in
 regcomp.c in Perl 5 before 5.24.3-RC1 and 5.26.x before 5.26.1-RC1
 allows remote attackers to disclose sensitive information
 or cause a denial of service (application crash) via a crafted regular
 expression with an invalid '\N{U+...}' escape. (bnc#1057721)
- CVE-2017-6512: Race condition in the rmtree and remove_tree functions in
 the File-Path module before 2.13 for Perl allows attackers to set the
 mode on arbitrary files via vectors involving directory-permission
 loosening logic. (bnc#1047178)
Bug fixes:
- backport set_capture_string changes from upstream (bsc#999735)
- reformat baselibs.conf as source validator workaround");

  script_tag(name:"affected", value:"'perl' package(s) on SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Desktop 12-SP2, SUSE Container as a Service Platform ALL, OpenStack Cloud Magnum Orchestration 7.");

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

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"perl", rpm:"perl~5.18.2~12.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-base", rpm:"perl-base~5.18.2~12.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-base-debuginfo", rpm:"perl-base-debuginfo~5.18.2~12.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-debuginfo", rpm:"perl-debuginfo~5.18.2~12.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-debugsource", rpm:"perl-debugsource~5.18.2~12.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-32bit", rpm:"perl-32bit~5.18.2~12.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-debuginfo-32bit", rpm:"perl-debuginfo-32bit~5.18.2~12.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-doc", rpm:"perl-doc~5.18.2~12.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"perl", rpm:"perl~5.18.2~12.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-base", rpm:"perl-base~5.18.2~12.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-base-debuginfo", rpm:"perl-base-debuginfo~5.18.2~12.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-debuginfo", rpm:"perl-debuginfo~5.18.2~12.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-debugsource", rpm:"perl-debugsource~5.18.2~12.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-32bit", rpm:"perl-32bit~5.18.2~12.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-debuginfo-32bit", rpm:"perl-debuginfo-32bit~5.18.2~12.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-doc", rpm:"perl-doc~5.18.2~12.3.1", rls:"SLES12.0SP2"))) {
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
