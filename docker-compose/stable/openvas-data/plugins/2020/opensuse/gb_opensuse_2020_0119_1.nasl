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
  script_oid("1.3.6.1.4.1.25623.1.0.853016");
  script_version("2020-02-11T08:37:57+0000");
  script_cve_id("CVE-2020-7040");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-02-11 08:37:57 +0000 (Tue, 11 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-01-29 04:01:48 +0000 (Wed, 29 Jan 2020)");
  script_name("openSUSE: Security Advisory for storeBackup (openSUSE-SU-2020:0119_1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"openSUSE-SU", value:"2020:0119-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2020-01/msg00054.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'storeBackup'
  package(s) announced via the openSUSE-SU-2020:0119-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for storeBackup fixes the following issues:

  - CVE-2020-7040: Fixed a symlink attack which could lead to denial of
  service (boo#1156767).

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-119=1

  - openSUSE Backports SLE-15-SP1:

  zypper in -t patch openSUSE-2020-119=1

  - openSUSE Backports SLE-15:

  zypper in -t patch openSUSE-2020-119=1");

  script_tag(name:"affected", value:"'storeBackup' package(s) on openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"storeBackup", rpm:"storeBackup~3.5~lp151.5.3.1", rls:"openSUSELeap15.1"))) {
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
