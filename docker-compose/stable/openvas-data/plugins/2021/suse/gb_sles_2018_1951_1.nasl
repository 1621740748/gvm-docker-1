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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.1951.1");
  script_cve_id("CVE-2018-10017", "CVE-2018-11710");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:43 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-07-16 12:06:00 +0000 (Mon, 16 Jul 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:1951-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:1951-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20181951-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libopenmpt' package(s) announced via the SUSE-SU-2018:1951-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libopenmpt to version 0.3.9 fixes the following issues:
These security issues were fixed:
- CVE-2018-11710: Prevent write near address 0 in out-of-memory situations
 when reading AMS files (bsc#1095644)
- CVE-2018-10017: Preven out-of-bounds memory read with IT/ITP/MO3 files
 containing pattern loops (bsc#1089080)
These non-security issues were fixed:
- [Bug] openmpt123: Fixed build failure in C++17 due to use of removed
 feature std::random_shuffle.
- STM: Having both Bxx and Cxx commands in a pattern imported the Bxx
 command incorrectly.
- STM: Last character of sample name was missing.
- Speed up reading of truncated ULT files.
- ULT: Portamento import was sometimes broken.
- The resonant filter was sometimes unstable when combining low-volume
 samples, low cutoff and high mixing rates.
- Keep track of active SFx macro during seeking.
- The 'note cut' duplicate note action did not volume-ramp the previously
 playing sample.
- A song starting with non-existing patterns could not be played.
- DSM: Support restart position and 16-bit samples.
- DTM: Import global volume.");

  script_tag(name:"affected", value:"'libopenmpt' package(s) on SUSE Linux Enterprise Module for Desktop Applications 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"libmodplug-devel", rpm:"libmodplug-devel~0.3.9~3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmodplug1", rpm:"libmodplug1~0.3.9~3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmodplug1-debuginfo", rpm:"libmodplug1-debuginfo~0.3.9~3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenmpt-debugsource", rpm:"libopenmpt-debugsource~0.3.9~3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenmpt-devel", rpm:"libopenmpt-devel~0.3.9~3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenmpt0", rpm:"libopenmpt0~0.3.9~3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenmpt0-debuginfo", rpm:"libopenmpt0-debuginfo~0.3.9~3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenmpt_modplug1", rpm:"libopenmpt_modplug1~0.3.9~3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenmpt_modplug1-debuginfo", rpm:"libopenmpt_modplug1-debuginfo~0.3.9~3.3.1", rls:"SLES15.0"))) {
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
