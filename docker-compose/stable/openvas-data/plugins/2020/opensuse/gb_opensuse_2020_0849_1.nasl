# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.853222");
  script_version("2020-09-25T09:18:25+0000");
  script_cve_id("CVE-2020-10759");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2020-09-25 09:18:25 +0000 (Fri, 25 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-06-23 03:00:54 +0000 (Tue, 23 Jun 2020)");
  script_name("openSUSE: Security Advisory for fwupd (openSUSE-SU-2020:0849-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"openSUSE-SU", value:"2020:0849-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-06/msg00041.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'fwupd'
  package(s) announced via the openSUSE-SU-2020:0849-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for fwupd fixes the following issues:

  - CVE-2020-10759: Fixed a potential PGP signature bypass, which could have
  led to installation of unsigned firmware (bsc#1172643)

  This update was imported from the SUSE:SLE-15-SP1:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-849=1");

  script_tag(name:"affected", value:"'fwupd' package(s) on openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"dfu-tool", rpm:"dfu-tool~1.0.9~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dfu-tool-debuginfo", rpm:"dfu-tool-debuginfo~1.0.9~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fwupd", rpm:"fwupd~1.0.9~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fwupd-debuginfo", rpm:"fwupd-debuginfo~1.0.9~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fwupd-debugsource", rpm:"fwupd-debugsource~1.0.9~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fwupd-devel", rpm:"fwupd-devel~1.0.9~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfwupd2", rpm:"libfwupd2~1.0.9~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfwupd2-debuginfo", rpm:"libfwupd2-debuginfo~1.0.9~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-Fwupd-2_0", rpm:"typelib-1_0-Fwupd-2_0~1.0.9~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fwupd-lang", rpm:"fwupd-lang~1.0.9~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
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