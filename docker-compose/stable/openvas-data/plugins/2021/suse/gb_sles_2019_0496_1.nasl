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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.0496.1");
  script_cve_id("CVE-2019-6109", "CVE-2019-6111");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:30 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:0496-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:0496-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20190496-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssh' package(s) announced via the SUSE-SU-2019:0496-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openssh fixes the following issues:

Security vulnerabilities addressed:
CVE-2019-6109: Fixed an character encoding issue in the progress display
 of the scp client that could be used to manipulate client output,
 allowing for spoofing during file transfers (bsc#1121816)

CVE-2019-6111: Properly validate object names received by the scp client
 to prevent arbitrary file overwrites when interacting with a malicious
 SSH server (bsc#1121821)

Other bug fixes and changes:
Handle brace expansion in scp when checking that filenames sent by the
 server side match what the client requested (bsc#1125687)");

  script_tag(name:"affected", value:"'openssh' package(s) on SUSE Linux Enterprise Module for Server Applications 15, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15, SUSE Linux Enterprise Module for Desktop Applications 15, SUSE Linux Enterprise Module for Basesystem 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"openssh-debuginfo", rpm:"openssh-debuginfo~7.6p1~9.23.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-debugsource", rpm:"openssh-debugsource~7.6p1~9.23.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-fips", rpm:"openssh-fips~7.6p1~9.23.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-askpass-gnome", rpm:"openssh-askpass-gnome~7.6p1~9.23.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-askpass-gnome-debuginfo", rpm:"openssh-askpass-gnome-debuginfo~7.6p1~9.23.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh", rpm:"openssh~7.6p1~9.23.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-helpers", rpm:"openssh-helpers~7.6p1~9.23.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-helpers-debuginfo", rpm:"openssh-helpers-debuginfo~7.6p1~9.23.1", rls:"SLES15.0"))) {
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
