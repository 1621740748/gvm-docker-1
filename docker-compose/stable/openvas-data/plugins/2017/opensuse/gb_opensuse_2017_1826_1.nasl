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
  script_oid("1.3.6.1.4.1.25623.1.0.851577");
  script_version("2020-01-31T08:23:39+0000");
  script_tag(name:"last_modification", value:"2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2017-07-14 15:54:54 +0530 (Fri, 14 Jul 2017)");
  script_cve_id("CVE-2017-10912", "CVE-2017-10913", "CVE-2017-10914", "CVE-2017-10915",
                "CVE-2017-10917", "CVE-2017-10918", "CVE-2017-10920", "CVE-2017-10921",
                "CVE-2017-10922", "CVE-2017-8309", "CVE-2017-9330");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for xen (openSUSE-SU-2017:1826-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes several issues.

  These security issues were fixed:

  - CVE-2017-10912: Page transfer might have allowed PV guest to elevate
  privilege (XSA-217, bsc#1042882)

  - CVE-2017-10913 CVE-2017-10914: Races in the grant table unmap code
  allowed for information leaks and potentially privilege escalation
  (XSA-218, bsc#1042893)

  - CVE-2017-10915: Insufficient reference counts during shadow emulation
  allowed a malicious pair of guest to elevate their privileges to the
  privileges that XEN runs under (XSA-219, bsc#1042915)

  - CVE-2017-10917: Missing NULL pointer check in event channel poll allows
  guests to DoS the host (XSA-221, bsc#1042924)

  - CVE-2017-10918: Stale P2M mappings due to insufficient error checking
  allowed malicious guest to leak information or elevate privileges
  (XSA-222, bsc#1042931)

  - CVE-2017-10920, CVE-2017-10921, CVE-2017-10922: Grant table operations
  mishandled reference counts allowing malicious guests to escape
  (XSA-224, bsc#1042938)

  - CVE-2017-9330: USB OHCI Emulation in qemu allowed local guest OS users
  to cause a denial of service (infinite loop) by leveraging an incorrect
  return value (bsc#1042160)

  - CVE-2017-8309: Memory leak in the audio/audio.c allowed remote attackers
  to cause a denial of service (memory consumption) by repeatedly starting
  and stopping audio capture (bsc#1037243)

  - PKRU and BND* leakage between vCPU-s might have leaked information to
  other guests (XSA-220, bsc#1042923)

  These non-security issues were fixed:

  - bsc#1027519: Included various upstream patches

  - bsc#1035642: Ensure that rpmbuild works

  This update was imported from the SUSE:SLE-12-SP2:Update update project.");

  script_tag(name:"affected", value:"xen on openSUSE Leap 42.2");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2017:1826-1");
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
  if(!isnull(res = isrpmvuln(pkg:"xen-debugsource", rpm:"xen-debugsource~4.7.2_06~11.9.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-devel", rpm:"xen-devel~4.7.2_06~11.9.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.7.2_06~11.9.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-debuginfo", rpm:"xen-libs-debuginfo~4.7.2_06~11.9.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.7.2_06~11.9.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU-debuginfo", rpm:"xen-tools-domU-debuginfo~4.7.2_06~11.9.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.7.2_06~11.9.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.7.2_06~11.9.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.7.2_06~11.9.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-debuginfo-32bit", rpm:"xen-libs-debuginfo-32bit~4.7.2_06~11.9.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.7.2_06~11.9.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-debuginfo", rpm:"xen-tools-debuginfo~4.7.2_06~11.9.1", rls:"openSUSELeap42.2"))) {
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
