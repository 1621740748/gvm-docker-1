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
  script_oid("1.3.6.1.4.1.25623.1.0.852954");
  script_version("2020-01-31T08:04:39+0000");
  script_cve_id("CVE-2019-5481", "CVE-2019-5482");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-31 08:04:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-09 09:47:37 +0000 (Thu, 09 Jan 2020)");
  script_name("openSUSE: Security Advisory for curl (openSUSE-SU-2019:2149-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"openSUSE-SU", value:"2019:2149-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2019-09/msg00048.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'curl'
  package(s) announced via the openSUSE-SU-2019:2149-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for curl fixes the following issues:

  Security issues fixed:

  - CVE-2019-5481: Fixed FTP-KRB double-free during kerberos FTP data
  transfer (bsc#1149495).

  - CVE-2019-5482: Fixed TFTP small blocksize heap buffer overflow
  (bsc#1149496).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-2149=1");

  script_tag(name:"affected", value:"'curl' package(s) on openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"curl", rpm:"curl~7.60.0~lp151.5.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"curl-debuginfo", rpm:"curl-debuginfo~7.60.0~lp151.5.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"curl-debugsource", rpm:"curl-debugsource~7.60.0~lp151.5.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"curl-mini", rpm:"curl-mini~7.60.0~lp151.5.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"curl-mini-debuginfo", rpm:"curl-mini-debuginfo~7.60.0~lp151.5.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"curl-mini-debugsource", rpm:"curl-mini-debugsource~7.60.0~lp151.5.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl-devel", rpm:"libcurl-devel~7.60.0~lp151.5.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl-mini-devel", rpm:"libcurl-mini-devel~7.60.0~lp151.5.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl4", rpm:"libcurl4~7.60.0~lp151.5.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl4-debuginfo", rpm:"libcurl4-debuginfo~7.60.0~lp151.5.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl4-mini", rpm:"libcurl4-mini~7.60.0~lp151.5.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl4-mini-debuginfo", rpm:"libcurl4-mini-debuginfo~7.60.0~lp151.5.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl-devel-32bit", rpm:"libcurl-devel-32bit~7.60.0~lp151.5.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl4-32bit", rpm:"libcurl4-32bit~7.60.0~lp151.5.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl4-32bit-debuginfo", rpm:"libcurl4-32bit-debuginfo~7.60.0~lp151.5.6.1", rls:"openSUSELeap15.1"))) {
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
