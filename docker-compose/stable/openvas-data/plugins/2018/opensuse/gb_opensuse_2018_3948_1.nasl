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
  script_oid("1.3.6.1.4.1.25623.1.0.852153");
  script_version("2021-06-28T11:00:33+0000");
  script_cve_id("CVE-2018-12900", "CVE-2018-18557", "CVE-2018-18661");
  script_bugtraq_id(106054);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-06-28 11:00:33 +0000 (Mon, 28 Jun 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-05 19:15:00 +0000 (Fri, 05 Mar 2021)");
  script_tag(name:"creation_date", value:"2018-12-04 12:40:33 +0530 (Tue, 04 Dec 2018)");
  script_name("openSUSE: Security Advisory for tiff (openSUSE-SU-2018:3948-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"openSUSE-SU", value:"2018:3948-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-11/msg00050.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tiff'
  package(s) announced via the openSUSE-SU-2018:3948-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tiff fixes the following issues:

  Security issues fixed:

  - CVE-2018-12900: Fixed heap-based buffer overflow in the
  cpSeparateBufToContigBuf (bsc#1099257).

  - CVE-2018-18661: Fixed NULL pointer dereference in the function LZWDecode
  in the file tif_lzw.c (bsc#1113672).

  - CVE-2018-18557: Fixed JBIG decode can lead to out-of-bounds write
  (bsc#1113094).

  Non-security issues fixed:

  - asan_build: build ASAN included

  - debug_build: build more suitable for debugging

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1480=1");

  script_tag(name:"affected", value:"tiff on openSUSE Leap 15.0.");

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
  if(!isnull(res = isrpmvuln(pkg:"libtiff-devel", rpm:"libtiff-devel~4.0.9~lp150.4.9.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff5", rpm:"libtiff5~4.0.9~lp150.4.9.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff5-debuginfo", rpm:"libtiff5-debuginfo~4.0.9~lp150.4.9.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tiff", rpm:"tiff~4.0.9~lp150.4.9.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tiff-debuginfo", rpm:"tiff-debuginfo~4.0.9~lp150.4.9.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tiff-debugsource", rpm:"tiff-debugsource~4.0.9~lp150.4.9.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff-devel-32bit", rpm:"libtiff-devel-32bit~4.0.9~lp150.4.9.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff5-32bit", rpm:"libtiff5-32bit~4.0.9~lp150.4.9.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff5-32bit-debuginfo", rpm:"libtiff5-32bit-debuginfo~4.0.9~lp150.4.9.1", rls:"openSUSELeap15.0"))) {
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
