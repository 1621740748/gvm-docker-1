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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.1772.1");
  script_cve_id("CVE-2019-18934", "CVE-2020-12662", "CVE-2020-12663");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:00 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-17 21:00:00 +0000 (Wed, 17 Feb 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:1772-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2|SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:1772-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20201772-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'unbound' package(s) announced via the SUSE-SU-2020:1772-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for unbound fixes the following issues:

CVE-2020-12662: Fixed an issue where unbound could have been tricked
 into amplifying an incoming query into a large number of queries
 directed to a target (bsc#1171889).

CVE-2020-12663: Fixed an issue where malformed answers from upstream
 name servers could have been used to make unbound unresponsive
 (bsc#1171889).

CVE-2019-18934: Fixed a vulnerability in the IPSec module which could
 have allowed code execution after receiving a special crafted answer
 (bsc#1157268).");

  script_tag(name:"affected", value:"'unbound' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP2, SUSE Linux Enterprise Module for Basesystem 15-SP1.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libunbound2", rpm:"libunbound2~1.6.8~10.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libunbound2-debuginfo", rpm:"libunbound2-debuginfo~1.6.8~10.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unbound-anchor", rpm:"unbound-anchor~1.6.8~10.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unbound-anchor-debuginfo", rpm:"unbound-anchor-debuginfo~1.6.8~10.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unbound-debuginfo", rpm:"unbound-debuginfo~1.6.8~10.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unbound-debugsource", rpm:"unbound-debugsource~1.6.8~10.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unbound-devel", rpm:"unbound-devel~1.6.8~10.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"libunbound2", rpm:"libunbound2~1.6.8~10.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libunbound2-debuginfo", rpm:"libunbound2-debuginfo~1.6.8~10.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unbound-anchor", rpm:"unbound-anchor~1.6.8~10.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unbound-anchor-debuginfo", rpm:"unbound-anchor-debuginfo~1.6.8~10.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unbound-debuginfo", rpm:"unbound-debuginfo~1.6.8~10.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unbound-debugsource", rpm:"unbound-debugsource~1.6.8~10.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unbound-devel", rpm:"unbound-devel~1.6.8~10.3.1", rls:"SLES15.0SP1"))) {
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
