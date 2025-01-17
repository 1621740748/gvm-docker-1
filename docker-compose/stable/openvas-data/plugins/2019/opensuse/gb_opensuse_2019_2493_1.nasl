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
  script_oid("1.3.6.1.4.1.25623.1.0.852769");
  script_version("2020-01-31T08:04:39+0000");
  script_cve_id("CVE-2019-1010180");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-31 08:04:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2019-11-13 03:01:25 +0000 (Wed, 13 Nov 2019)");
  script_name("openSUSE: Security Advisory for gdb (openSUSE-SU-2019:2493-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"openSUSE-SU", value:"2019:2493-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2019-11/msg00029.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gdb'
  package(s) announced via the openSUSE-SU-2019:2493-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gdb fixes the following issues:

  Update to gdb 8.3.1: (jsc#ECO-368)

  Security issues fixed:

  - CVE-2019-1010180: Fixed a potential buffer overflow when loading ELF
  sections larger than the file. (bsc#1142772)

  Upgrade libipt from v2.0 to v2.0.1.

  - Enable librpm for version > librpm.so.3 [bsc#1145692]:

  * Allow any librpm.so.x

  * Add %build test to check for 'zypper install <rpm-packagename>' message

  - Copy gdbinit from fedora master @ 25caf28.  Add gdbinit.without-python,
  and use it for --without=python.

  Rebase to 8.3 release (as in fedora 30 @ 1e222a3).

  * DWARF index cache: GDB can now automatically save indices of DWARF
  symbols on disk to speed up further loading of the same binaries.

  * Ada task switching is now supported on aarch64-elf targets when
  debugging a program using the Ravenscar Profile.

  * Terminal styling is now available for the CLI and the TUI.

  * Removed support for old demangling styles arm, edg, gnu, hp and lucid.

  * Support for new native configuration RISC-V GNU/Linux (riscv*-*-linux*).

  - Implemented access to more POWER8 registers.  [fate#326120, fate#325178]

  - Handle most of new s390 arch13 instructions. [fate#327369, jsc#ECO-368]

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-2493=1");

  script_tag(name:"affected", value:"'gdb' package(s) on openSUSE Leap 15.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"gdb", rpm:"gdb~8.3.1~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdb-debuginfo", rpm:"gdb-debuginfo~8.3.1~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdb-debugsource", rpm:"gdb-debugsource~8.3.1~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdb-testresults", rpm:"gdb-testresults~8.3.1~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdbserver", rpm:"gdbserver~8.3.1~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdbserver-debuginfo", rpm:"gdbserver-debuginfo~8.3.1~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
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
