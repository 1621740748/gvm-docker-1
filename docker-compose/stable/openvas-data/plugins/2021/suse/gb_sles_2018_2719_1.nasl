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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.2719.1");
  script_cve_id("CVE-2008-1483", "CVE-2016-10012", "CVE-2016-10708", "CVE-2017-15906");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:37 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-11 10:29:00 +0000 (Tue, 11 Sep 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:2719-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:2719-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20182719-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssh-openssl1' package(s) announced via the SUSE-SU-2018:2719-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openssh-openssl1 fixes the following issues:

These security issues were fixed:
CVE-2016-10708: Prevent NULL pointer dereference via an out-of-sequence
 NEWKEYS message allowed remote attackers to cause a denial of service
 (bsc#1076957).

CVE-2017-15906: The process_open function did not properly prevent write
 operations in readonly mode, which allowed attackers to create
 zero-length files (bsc#1065000).

CVE-2016-10012: The shared memory manager (associated with
 pre-authentication compression) did not ensure that a bounds check is
 enforced by all compilers, which might have allowed local users to gain
 privileges by leveraging access to a sandboxed privilege-separation
 process, related to the m_zback and m_zlib data structures (bsc#1016370).

CVE-2008-1483: Prevent local users from hijacking forwarded X
 connections by causing ssh to set DISPLAY to :10, even when another
 process is listening on the associated port. This problem was
 reontroduced by another patch and was previously fixed by another update
 (bsc#1069509).

These non-security issues were fixed:
Remove duplicate KEX method (bsc#1053972)

New switch for printing diagnostic messages in sftp client's batch mode
 (bsc#1023275)

Enable case-insensitive hostname matching (bsc#1017099)");

  script_tag(name:"affected", value:"'openssh-openssl1' package(s) on SUSE Linux Enterprise Server 11.");

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

if(release == "SLES11.0") {

  if(!isnull(res = isrpmvuln(pkg:"openssh-openssl1", rpm:"openssh-openssl1~6.6p1~19.3.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-openssl1-helpers", rpm:"openssh-openssl1-helpers~6.6p1~19.3.1", rls:"SLES11.0"))) {
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
