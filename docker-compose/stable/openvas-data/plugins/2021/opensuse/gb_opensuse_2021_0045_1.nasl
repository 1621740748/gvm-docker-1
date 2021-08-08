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
  script_oid("1.3.6.1.4.1.25623.1.0.853649");
  script_version("2021-04-21T07:29:02+0000");
  # TODO: No CVE assigned yet.
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-04-21 07:29:02 +0000 (Wed, 21 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-16 04:58:41 +0000 (Fri, 16 Apr 2021)");
  script_name("openSUSE: Security Advisory for rpmlint (openSUSE-SU-2021:0045-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0045-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/K3I2WEUESPFLE2MV2TILF3SCTSEQDWYA");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rpmlint'
  package(s) announced via the openSUSE-SU-2021:0045-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for rpmlint fixes the following issues:

  - Whitelist PAM modules and DBUS rules for cockpit (bsc#1169614)

     This update was imported from the SUSE:SLE-15:Update update project.");

  script_tag(name:"affected", value:"'rpmlint' package(s) on openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"rpmlint-mini", rpm:"rpmlint-mini~1.10~lp151.5.19.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpmlint-mini-debuginfo", rpm:"rpmlint-mini-debuginfo~1.10~lp151.5.19.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpmlint-mini-debugsource", rpm:"rpmlint-mini-debugsource~1.10~lp151.5.19.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpmlint", rpm:"rpmlint~1.10~lp151.9.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpmlint-tests-debugsource", rpm:"rpmlint-tests-debugsource~84.87+git20181018.60e0249~lp151.9.12.1", rls:"openSUSELeap15.1"))) {
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