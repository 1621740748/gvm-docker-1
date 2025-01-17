# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.851613");
  script_version("2020-01-31T08:23:39+0000");
  script_tag(name:"last_modification", value:"2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2017-09-09 07:20:39 +0200 (Sat, 09 Sep 2017)");
  script_cve_id("CVE-2016-9603", "CVE-2017-10664", "CVE-2017-11434", "CVE-2017-12135",
                "CVE-2017-12136", "CVE-2017-12137", "CVE-2017-12855");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for xen (openSUSE-SU-2017:2398-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen to version 4.7.3 fixes several issues.

  These security issues were fixed:

  - CVE-2017-12135: Unbounded recursion in grant table code allowed a
  malicious guest to crash the host or potentially escalate
  privileges/leak information (XSA-226, bsc#1051787).

  - CVE-2017-12137: Incorrectly-aligned updates to pagetables allowed for
  privilege escalation (XSA-227, bsc#1051788).

  - CVE-2017-12136: Race conditions with maptrack free list handling allows
  a malicious guest administrator to crash the host or escalate their
  privilege to that of the host (XSA-228, bsc#1051789).

  - CVE-2017-11434: The dhcp_decode function in slirp/bootp.c allowed local
  guest OS users to cause a denial of service (out-of-bounds read) via a
  crafted DHCP
  options string (bsc#1049578).

  - CVE-2017-10664: qemu-nbd did not ignore SIGPIPE, which allowed remote
  attackers to cause a denial of service (daemon crash) by disconnecting
  during a server-to-client reply attempt (bsc#1046637).

  - CVE-2017-12855: Premature clearing of GTF_writing / GTF_reading lead to
  potentially leaking sensitive information (XSA-230 CVE-2017-12855).

  These non-security issues were fixed:

  - bsc#1055695: XEN: 11SP4 and 12SP3 HVM guests can not be restored after
  the save using xl stack

  - bsc#1035231: Migration of HVM domU did not use superpages on destination
  dom0

  - bsc#1002573: Optimized LVM functions in block-dmmd block-dmmd

  - bsc#1037840: Xen-detect always showed HVM for PV guests

  This update was imported from the SUSE:SLE-12-SP2:Update update project.");

  script_tag(name:"affected", value:"xen on openSUSE Leap 42.2");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2017:2398-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.2");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap42.2") {
  if(!isnull(res = isrpmvuln(pkg:"xen-debugsource", rpm:"xen-debugsource~4.7.3_03~11.12.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-devel", rpm:"xen-devel~4.7.3_03~11.12.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.7.3_03~11.12.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-debuginfo", rpm:"xen-libs-debuginfo~4.7.3_03~11.12.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.7.3_03~11.12.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU-debuginfo", rpm:"xen-tools-domU-debuginfo~4.7.3_03~11.12.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.7.3_03~11.12.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.7.3_03~11.12.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.7.3_03~11.12.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-debuginfo-32bit", rpm:"xen-libs-debuginfo-32bit~4.7.3_03~11.12.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.7.3_03~11.12.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-debuginfo", rpm:"xen-tools-debuginfo~4.7.3_03~11.12.1", rls:"openSUSELeap42.2"))) {
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
