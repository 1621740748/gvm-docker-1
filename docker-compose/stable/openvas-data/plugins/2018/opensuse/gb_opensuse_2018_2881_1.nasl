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
  script_oid("1.3.6.1.4.1.25623.1.0.851914");
  script_version("2021-06-29T02:00:29+0000");
  script_tag(name:"last_modification", value:"2021-06-29 02:00:29 +0000 (Tue, 29 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-09-27 08:11:17 +0200 (Thu, 27 Sep 2018)");
  script_cve_id("CVE-2018-7685");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:42:00 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for libzypp (openSUSE-SU-2018:2881-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libzypp'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libzypp, zypper fixes the following issues:

  Update libzypp to version 16.17.20:

  Security issues fixed:

  - PackageProvider: Validate delta rpms before caching (bsc#1091624,
  bsc#1088705, CVE-2018-7685)

  - PackageProvider: Validate downloaded rpm package signatures before
  caching (bsc#1091624, bsc#1088705, CVE-2018-7685)

  Other bugs fixed:

  - lsof: use '-K i' if lsof supports it (bsc#1099847, bsc#1036304)

  - Handle http error 502 Bad Gateway in curl backend (bsc#1070851)

  - RepoManager: Explicitly request repo2solv to generate application pseudo
  packages.

  - libzypp-devel should not require cmake (bsc#1101349)

  - HardLocksFile: Prevent against empty commit without Target having been
  been loaded (bsc#1096803)

  - Avoid zombie tar processes (bsc#1076192)

  Update to zypper to version 1.13.45:

  Other bugs fixed:

  - XML  install-summary  attribute `packages-to-change` added (bsc#1102429)

  - man: Strengthen that `--config FILE' affects zypper.conf, not zypp.conf
  (bsc#1100028)

  - Prevent nested calls to exit() if aborted by a signal (bsc#1092413)

  - ansi.h: Prevent ESC sequence strings from going out of scope
  (bsc#1092413)

  - Fix: zypper bash completion expands non-existing options (bsc#1049825)

  This update was imported from the SUSE:SLE-12-SP3:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1054=1");

  script_tag(name:"affected", value:"libzypp, on openSUSE Leap 42.3");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2018:2881-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-09/msg00079.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");
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
  if(!isnull(res = isrpmvuln(pkg:"libzypp", rpm:"libzypp~16.17.20~27.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzypp-debuginfo", rpm:"libzypp-debuginfo~16.17.20~27.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzypp-debugsource", rpm:"libzypp-debugsource~16.17.20~27.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzypp-devel", rpm:"libzypp-devel~16.17.20~27.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzypp-devel-doc", rpm:"libzypp-devel-doc~16.17.20~27.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zypper", rpm:"zypper~1.13.45~20.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zypper-debuginfo", rpm:"zypper-debuginfo~1.13.45~20.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zypper-debugsource", rpm:"zypper-debugsource~1.13.45~20.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zypper-aptitude", rpm:"zypper-aptitude~1.13.45~20.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zypper-log", rpm:"zypper-log~1.13.45~20.1", rls:"openSUSELeap42.3"))) {
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
