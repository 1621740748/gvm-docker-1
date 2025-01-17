# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.852025");
  script_version("2020-01-31T08:23:39+0000");
  script_cve_id("CVE-2015-0247", "CVE-2015-1572");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2018-10-26 06:35:16 +0200 (Fri, 26 Oct 2018)");
  script_name("openSUSE: Security Advisory for e2fsprogs (openSUSE-SU-2018:2133-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"openSUSE-SU", value:"2018:2133-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-07/msg00050.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'e2fsprogs'
  package(s) announced via the openSUSE-SU-2018:2133-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for e2fsprogs fixes the following issues:

  Security issues fixed:

  - CVE-2015-0247: Fixed couple of heap overflows in e2fsprogs (fsck,
  dumpe2fs, e2image...) (bsc#915402).

  - CVE-2015-1572: Fixed potential buffer overflow in closefs() (bsc#918346).

  Bug fixes:

  - bsc#1038194: generic/405 test fails with /dev/mapper/thin-vol is
  inconsistent on ext4 file system.

  - bsc#1009532: resize2fs hangs when trying to resize a large ext4 file
  system.

  - bsc#960273: xfsprogs does not call %{?regenerate_initrd_post}.

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-771=1");

  script_tag(name:"affected", value:"e2fsprogs on openSUSE Leap 15.0.");

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
  if(!isnull(res = isrpmvuln(pkg:"e2fsprogs", rpm:"e2fsprogs~1.43.8~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"e2fsprogs-debuginfo", rpm:"e2fsprogs-debuginfo~1.43.8~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"e2fsprogs-debugsource", rpm:"e2fsprogs-debugsource~1.43.8~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"e2fsprogs-devel", rpm:"e2fsprogs-devel~1.43.8~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcom_err-devel", rpm:"libcom_err-devel~1.43.8~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcom_err-devel-static", rpm:"libcom_err-devel-static~1.43.8~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcom_err2", rpm:"libcom_err2~1.43.8~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcom_err2-debuginfo", rpm:"libcom_err2-debuginfo~1.43.8~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libext2fs-devel", rpm:"libext2fs-devel~1.43.8~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libext2fs-devel-static", rpm:"libext2fs-devel-static~1.43.8~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libext2fs2", rpm:"libext2fs2~1.43.8~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libext2fs2-debuginfo", rpm:"libext2fs2-debuginfo~1.43.8~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"e2fsprogs-32bit-debuginfo", rpm:"e2fsprogs-32bit-debuginfo~1.43.8~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcom_err-devel-32bit", rpm:"libcom_err-devel-32bit~1.43.8~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcom_err2-32bit", rpm:"libcom_err2-32bit~1.43.8~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcom_err2-32bit-debuginfo", rpm:"libcom_err2-32bit-debuginfo~1.43.8~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libext2fs-devel-32bit", rpm:"libext2fs-devel-32bit~1.43.8~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libext2fs2-32bit", rpm:"libext2fs2-32bit~1.43.8~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libext2fs2-32bit-debuginfo", rpm:"libext2fs2-32bit-debuginfo~1.43.8~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
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
