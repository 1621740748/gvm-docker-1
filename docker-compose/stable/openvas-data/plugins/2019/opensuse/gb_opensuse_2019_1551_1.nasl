# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.852556");
  script_version("2020-01-31T08:04:39+0000");
  script_cve_id("CVE-2019-12735");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-01-31 08:04:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2019-06-14 02:00:36 +0000 (Fri, 14 Jun 2019)");
  script_name("openSUSE: Security Advisory for neovim (openSUSE-SU-2019:1551-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap42\.3|openSUSELeap15\.0)");

  script_xref(name:"openSUSE-SU", value:"2019:1551-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2019-06/msg00031.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'neovim'
  package(s) announced via the openSUSE-SU-2019:1551-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for neovim fixes the following issues:

  Security issue fixed:

  - CVE-2019-12735: Fixed a potential arbitrary code execution vulnerability
  in getchar.c (bsc#1137443).

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-1551=1

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-1551=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1551=1

  - openSUSE Backports SLE-15:

  zypper in -t patch openSUSE-2019-1551=1");

  script_tag(name:"affected", value:"'neovim' package(s) on openSUSE Leap 42.3, openSUSE Leap 15.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"neovim", rpm:"neovim~0.2.0~6.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"neovim-debuginfo", rpm:"neovim-debuginfo~0.2.0~6.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"neovim-debugsource", rpm:"neovim-debugsource~0.2.0~6.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"neovim-lang", rpm:"neovim-lang~0.2.0~6.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.0") {

  if(!isnull(res = isrpmvuln(pkg:"neovim", rpm:"neovim~0.3.1~lp150.7.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"neovim-debuginfo", rpm:"neovim-debuginfo~0.3.1~lp150.7.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"neovim-debugsource", rpm:"neovim-debugsource~0.3.1~lp150.7.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"neovim-lang", rpm:"neovim-lang~0.3.1~lp150.7.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
