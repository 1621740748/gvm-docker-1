# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.853055");
  script_version("2020-03-10T07:36:36+0000");
  script_cve_id("CVE-2019-9674", "CVE-2020-8492");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2020-03-10 07:36:36 +0000 (Tue, 10 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-03-02 04:00:38 +0000 (Mon, 02 Mar 2020)");
  script_name("openSUSE: Security Advisory for python3 (openSUSE-SU-2020:0274-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"openSUSE-SU", value:"2020:0274-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-03/msg00003.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python3'
  package(s) announced via the openSUSE-SU-2020:0274-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python3 fixes the following issues:

  Security issues fixed:

  - CVE-2019-9674: Improved the documentation to reflect the dangers of
  zip-bombs (bsc#1162825).

  - CVE-2020-8492: Fixed a regular expression in urllib that was prone to
  denial of service via HTTP (bsc#1162367).

  Non-security issue fixed:

  - If the locale is 'C', coerce it to C.UTF-8 (bsc#1162423).

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-274=1");

  script_tag(name:"affected", value:"'python3' package(s) on openSUSE Leap 15.1.");

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

if(release == "openSUSELeap15.1") {

  if(!isnull(res = isrpmvuln(pkg:"libpython3_6m1_0", rpm:"libpython3_6m1_0~3.6.10~lp151.6.11.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3_6m1_0-debuginfo", rpm:"libpython3_6m1_0-debuginfo~3.6.10~lp151.6.11.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3", rpm:"python3~3.6.10~lp151.6.11.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-base", rpm:"python3-base~3.6.10~lp151.6.11.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-base-debuginfo", rpm:"python3-base-debuginfo~3.6.10~lp151.6.11.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-base-debugsource", rpm:"python3-base-debugsource~3.6.10~lp151.6.11.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-curses", rpm:"python3-curses~3.6.10~lp151.6.11.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-curses-debuginfo", rpm:"python3-curses-debuginfo~3.6.10~lp151.6.11.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-dbm", rpm:"python3-dbm~3.6.10~lp151.6.11.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-dbm-debuginfo", rpm:"python3-dbm-debuginfo~3.6.10~lp151.6.11.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-debuginfo", rpm:"python3-debuginfo~3.6.10~lp151.6.11.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-debugsource", rpm:"python3-debugsource~3.6.10~lp151.6.11.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-devel", rpm:"python3-devel~3.6.10~lp151.6.11.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-devel-debuginfo", rpm:"python3-devel-debuginfo~3.6.10~lp151.6.11.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-idle", rpm:"python3-idle~3.6.10~lp151.6.11.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-testsuite", rpm:"python3-testsuite~3.6.10~lp151.6.11.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-testsuite-debuginfo", rpm:"python3-testsuite-debuginfo~3.6.10~lp151.6.11.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-tk", rpm:"python3-tk~3.6.10~lp151.6.11.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-tk-debuginfo", rpm:"python3-tk-debuginfo~3.6.10~lp151.6.11.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-tools", rpm:"python3-tools~3.6.10~lp151.6.11.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3_6m1_0-32bit", rpm:"libpython3_6m1_0-32bit~3.6.10~lp151.6.11.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3_6m1_0-32bit-debuginfo", rpm:"libpython3_6m1_0-32bit-debuginfo~3.6.10~lp151.6.11.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-32bit", rpm:"python3-32bit~3.6.10~lp151.6.11.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-32bit-debuginfo", rpm:"python3-32bit-debuginfo~3.6.10~lp151.6.11.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-base-32bit", rpm:"python3-base-32bit~3.6.10~lp151.6.11.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-base-32bit-debuginfo", rpm:"python3-base-32bit-debuginfo~3.6.10~lp151.6.11.1", rls:"openSUSELeap15.1"))) {
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
