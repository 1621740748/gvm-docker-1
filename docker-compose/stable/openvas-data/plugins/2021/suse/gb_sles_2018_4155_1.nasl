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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.4155.1");
  script_cve_id("CVE-2017-5731", "CVE-2017-5732", "CVE-2017-5733", "CVE-2017-5734", "CVE-2017-5735", "CVE-2018-3613");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:32 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-18 17:38:00 +0000 (Mon, 18 Nov 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:4155-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:4155-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20184155-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ovmf' package(s) announced via the SUSE-SU-2018:4155-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ovmf fixes the following issues:

Security issues fixed:
CVE-2018-3613: Fixed AuthVariable Timestamp zeroing issue on
 APPEND_WRITE (bsc#1115916).

CVE-2017-5731: Fixed privilege escalation via processing of malformed
 files in TianoCompress.c (bsc#1115917).

CVE-2017-5732: Fixed privilege escalation via processing of malformed
 files in BaseUefiDecompressLib.c (bsc#1115917).

CVE-2017-5733: Fixed privilege escalation via heap-based buffer overflow
 in MakeTable() function (bsc#1115917).

CVE-2017-5734: Fixed privilege escalation via stack-based buffer
 overflow in MakeTable() function (bsc#1115917).

CVE-2017-5735: Fixed privilege escalation via heap-based buffer overflow
 in Decode() function (bsc#1115917).

Non security issues fixed:
Fixed an issue with the default owner of PK/KEK/db/dbx and make the
 auto-enrollment only happen at the very first time. (bsc#1117998)");

  script_tag(name:"affected", value:"'ovmf' package(s) on SUSE Linux Enterprise Module for Server Applications 15.");

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

  if(!isnull(res = isrpmvuln(pkg:"ovmf", rpm:"ovmf~2017+git1510945757.b2662641d5~5.11.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovmf-tools", rpm:"ovmf-tools~2017+git1510945757.b2662641d5~5.11.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ovmf-x86_64", rpm:"qemu-ovmf-x86_64~2017+git1510945757.b2662641d5~5.11.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-uefi-aarch64", rpm:"qemu-uefi-aarch64~2017+git1510945757.b2662641d5~5.11.1", rls:"SLES15.0"))) {
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
