# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.852114");
  script_version("2021-06-25T11:00:33+0000");
  script_cve_id("CVE-2018-1000802", "CVE-2018-1060", "CVE-2018-1061");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-06-25 11:00:33 +0000 (Fri, 25 Jun 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-07 21:14:00 +0000 (Mon, 07 Dec 2020)");
  script_tag(name:"creation_date", value:"2018-11-10 05:58:12 +0100 (Sat, 10 Nov 2018)");
  script_name("openSUSE: Security Advisory for python (openSUSE-SU-2018:3703-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");

  script_xref(name:"openSUSE-SU", value:"2018:3703-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-11/msg00011.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python'
  package(s) announced via the openSUSE-SU-2018:3703-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python, python-base fixes the following issues:

  Security issues fixed:

  - CVE-2018-1000802: Prevent command injection in shutil module
  (make_archive function) via passage of unfiltered user input
  (bsc#1109663).

  - CVE-2018-1061: Fixed DoS via regular expression backtracking in
  difflib.IS_LINE_JUNK method in difflib (bsc#1088004).

  - CVE-2018-1060: Fixed DoS via regular expression catastrophic
  backtracking in apop() method in pop3lib (bsc#1088009).

  Bug fixes:

  - bsc#1086001: python tarfile uses random order.

  This update was imported from the SUSE:SLE-12-SP1:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1363=1");

  script_tag(name:"affected", value:"python, on openSUSE Leap 42.3.");

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

if(release == "openSUSELeap42.3") {
  if(!isnull(res = isrpmvuln(pkg:"libpython2_7-1_0", rpm:"libpython2_7-1_0~2.7.13~27.9.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython2_7-1_0-debuginfo", rpm:"libpython2_7-1_0-debuginfo~2.7.13~27.9.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python", rpm:"python~2.7.13~27.9.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-base", rpm:"python-base~2.7.13~27.9.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-base-debuginfo", rpm:"python-base-debuginfo~2.7.13~27.9.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-base-debugsource", rpm:"python-base-debugsource~2.7.13~27.9.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-curses", rpm:"python-curses~2.7.13~27.9.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-curses-debuginfo", rpm:"python-curses-debuginfo~2.7.13~27.9.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-debuginfo", rpm:"python-debuginfo~2.7.13~27.9.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-debugsource", rpm:"python-debugsource~2.7.13~27.9.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-demo", rpm:"python-demo~2.7.13~27.9.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-devel", rpm:"python-devel~2.7.13~27.9.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-gdbm", rpm:"python-gdbm~2.7.13~27.9.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-gdbm-debuginfo", rpm:"python-gdbm-debuginfo~2.7.13~27.9.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-idle", rpm:"python-idle~2.7.13~27.9.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-tk", rpm:"python-tk~2.7.13~27.9.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-tk-debuginfo", rpm:"python-tk-debuginfo~2.7.13~27.9.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-xml", rpm:"python-xml~2.7.13~27.9.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-xml-debuginfo", rpm:"python-xml-debuginfo~2.7.13~27.9.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-doc", rpm:"python-doc~2.7.13~27.9.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-doc-pdf", rpm:"python-doc-pdf~2.7.13~27.9.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython2_7-1_0-32bit", rpm:"libpython2_7-1_0-32bit~2.7.13~27.9.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython2_7-1_0-debuginfo-32bit", rpm:"libpython2_7-1_0-debuginfo-32bit~2.7.13~27.9.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-32bit", rpm:"python-32bit~2.7.13~27.9.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-base-32bit", rpm:"python-base-32bit~2.7.13~27.9.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-base-debuginfo-32bit", rpm:"python-base-debuginfo-32bit~2.7.13~27.9.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-debuginfo-32bit", rpm:"python-debuginfo-32bit~2.7.13~27.9.1", rls:"openSUSELeap42.3"))) {
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
