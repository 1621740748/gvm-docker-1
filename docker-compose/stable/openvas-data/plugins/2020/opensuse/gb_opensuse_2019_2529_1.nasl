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
  script_oid("1.3.6.1.4.1.25623.1.0.852958");
  script_version("2020-01-31T08:04:39+0000");
  script_cve_id("CVE-2019-2201");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-01-31 08:04:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-09 09:47:55 +0000 (Thu, 09 Jan 2020)");
  script_name("openSUSE: Security Advisory for libjpeg-turbo (openSUSE-SU-2019:2529-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"openSUSE-SU", value:"2019:2529-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2019-11/msg00047.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libjpeg-turbo'
  package(s) announced via the openSUSE-SU-2019:2529-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libjpeg-turbo fixes the following issues:

  - CVE-2019-2201: Several integer overflow issues and subsequent segfaults
  occurred in libjpeg-turbo, when attempting to compress or decompress
  gigapixel images. [bsc#1156402]


  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-2529=1");

  script_tag(name:"affected", value:"'libjpeg-turbo' package(s) on openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"libjpeg-turbo", rpm:"libjpeg-turbo~1.5.3~lp151.6.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg-turbo-debuginfo", rpm:"libjpeg-turbo-debuginfo~1.5.3~lp151.6.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg-turbo-debugsource", rpm:"libjpeg-turbo-debugsource~1.5.3~lp151.6.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg62", rpm:"libjpeg62~62.2.0~lp151.6.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg62-debuginfo", rpm:"libjpeg62-debuginfo~62.2.0~lp151.6.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg62-devel", rpm:"libjpeg62-devel~62.2.0~lp151.6.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg62-turbo", rpm:"libjpeg62-turbo~1.5.3~lp151.6.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg62-turbo-debugsource", rpm:"libjpeg62-turbo-debugsource~1.5.3~lp151.6.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg8", rpm:"libjpeg8~8.1.2~lp151.6.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg8-debuginfo", rpm:"libjpeg8-debuginfo~8.1.2~lp151.6.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg8-devel", rpm:"libjpeg8-devel~8.1.2~lp151.6.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libturbojpeg0", rpm:"libturbojpeg0~8.1.2~lp151.6.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libturbojpeg0-debuginfo", rpm:"libturbojpeg0-debuginfo~8.1.2~lp151.6.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg62-32bit", rpm:"libjpeg62-32bit~62.2.0~lp151.6.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg62-32bit-debuginfo", rpm:"libjpeg62-32bit-debuginfo~62.2.0~lp151.6.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg62-devel-32bit", rpm:"libjpeg62-devel-32bit~62.2.0~lp151.6.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg8-32bit", rpm:"libjpeg8-32bit~8.1.2~lp151.6.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg8-32bit-debuginfo", rpm:"libjpeg8-32bit-debuginfo~8.1.2~lp151.6.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg8-devel-32bit", rpm:"libjpeg8-devel-32bit~8.1.2~lp151.6.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libturbojpeg0-32bit", rpm:"libturbojpeg0-32bit~8.1.2~lp151.6.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libturbojpeg0-32bit-debuginfo", rpm:"libturbojpeg0-32bit-debuginfo~8.1.2~lp151.6.3.1", rls:"openSUSELeap15.1"))) {
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
