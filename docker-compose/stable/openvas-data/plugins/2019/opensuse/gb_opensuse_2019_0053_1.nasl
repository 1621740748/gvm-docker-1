# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of their respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852243");
  script_version("2020-01-31T08:23:39+0000");
  script_cve_id("CVE-2018-15126", "CVE-2018-15127", "CVE-2018-20019", "CVE-2018-20020",
                "CVE-2018-20021", "CVE-2018-20022", "CVE-2018-20023", "CVE-2018-20024",
                "CVE-2018-6307");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2019-01-18 04:02:52 +0100 (Fri, 18 Jan 2019)");
  script_name("openSUSE: Security Advisory for LibVNCServer (openSUSE-SU-2019:0053-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"openSUSE-SU", value:"2019:0053-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2019-01/msg00021.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'LibVNCServer'
  package(s) announced via the openSUSE-SU-2019:0053-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for LibVNCServer fixes the following issues:

  Security issues fixed:

  - CVE-2018-15126: Fixed use-after-free in file transfer extension
  (bsc#1120114)

  - CVE-2018-6307: Fixed use-after-free in file transfer extension server
  code (bsc#1120115)

  - CVE-2018-20020: Fixed heap out-of-bound write inside structure in VNC
  client code (bsc#1120116)

  - CVE-2018-15127: Fixed heap out-of-bounds write in rfbserver.c
  (bsc#1120117)

  - CVE-2018-20019: Fixed multiple heap out-of-bound writes in VNC client
  code (bsc#1120118)

  - CVE-2018-20023: Fixed information disclosure through improper
  initialization in VNC Repeater client code (bsc#1120119)

  - CVE-2018-20022: Fixed information disclosure through improper
  initialization in VNC client code (bsc#1120120)

  - CVE-2018-20024: Fixed NULL pointer dereference in VNC client code
  (bsc#1120121)

  - CVE-2018-20021: Fixed infinite loop in VNC client code (bsc#1120122)

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-53=1");

  script_tag(name:"affected", value:"LibVNCServer on openSUSE Leap 15.0.");

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

if(release == "openSUSELeap15.0") {
  if(!isnull(res = isrpmvuln(pkg:"LibVNCServer-debugsource", rpm:"LibVNCServer-debugsource~0.9.10~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"LibVNCServer-devel", rpm:"LibVNCServer-devel~0.9.10~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvncclient0", rpm:"libvncclient0~0.9.10~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvncclient0-debuginfo", rpm:"libvncclient0-debuginfo~0.9.10~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvncserver0", rpm:"libvncserver0~0.9.10~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvncserver0-debuginfo", rpm:"libvncserver0-debuginfo~0.9.10~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
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
