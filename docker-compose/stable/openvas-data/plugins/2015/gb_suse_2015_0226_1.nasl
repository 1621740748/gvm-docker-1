# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.850634");
  script_version("2020-01-31T08:23:39+0000");
  script_tag(name:"last_modification", value:"2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2015-02-07 05:42:20 +0100 (Sat, 07 Feb 2015)");
  script_cve_id("CVE-2013-3495", "CVE-2014-5146", "CVE-2014-5149", "CVE-2014-8594", "CVE-2014-8595", "CVE-2014-8866", "CVE-2014-8867", "CVE-2014-9030", "CVE-2014-9065", "CVE-2014-9066", "CVE-2015-0361");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("openSUSE: Security Advisory for xen (openSUSE-SU-2015:0226-1)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The virtualization software XEN was updated to version 4.3.3 and also to
  fix bugs and security issues.

  Security issues fixed: CVE-2015-0361: XSA-116: xen: xen crash due to use
  after free on hvm guest teardown

  CVE-2014-9065, CVE-2014-9066: XSA-114: xen: p2m lock starvation

  CVE-2014-9030: XSA-113: Guest effectable page reference leak in
  MMU_MACHPHYS_UPDATE handling

  CVE-2014-8867: XSA-112: xen: Insufficient bounding of 'REP MOVS' to MMIO
  emulated inside the hypervisor

  CVE-2014-8866: XSA-111: xen: Excessive checking in compatibility mode
  hypercall argument translation

  CVE-2014-8595: XSA-110: xen: Missing privilege level checks in x86
  emulation of far branches

  CVE-2014-8594: XSA-109: xen: Insufficient restrictions on certain MMU
  update hypercalls

  CVE-2013-3495: XSA-59: xen: Intel VT-d Interrupt Remapping engines can be
  evaded by native NMI interrupts

  CVE-2014-5146, CVE-2014-5149: xen: XSA-97 Long latency virtual-mmu
  operations are not preemptible

  Bugs fixed:

  - bnc#903357 - Corrupted save/restore test leaves orphaned data in xenstore

  - bnc#903359 - Temporary migration name is not cleaned up after migration

  - bnc#903850 - VUL-0: Xen: guest user mode triggerable VM exits not
  handled by hypervisor

  - bnc#866902 - L3: Xen save/restore of HVM guests cuts off disk and
  networking

  - bnc#901317 - L3: increase limit domUloader to 32MB domUloader.py

  - bnc#882089 - Windows 2012 R2 fails to boot up with greater than 60 vcpus

  - bsc#900292 - xl: change default dump directory

  - Update to Xen 4.3.3");

  script_tag(name:"affected", value:"xen on openSUSE 13.1");

  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"openSUSE-SU", value:"2015:0226-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE13\.1");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSE13.1") {
  if(!isnull(res = isrpmvuln(pkg:"xen-debugsource", rpm:"xen-debugsource~4.3.3_04~34.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-devel", rpm:"xen-devel~4.3.3_04~34.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.3.3_04_k3.11.10_25~34.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default-debuginfo", rpm:"xen-kmp-default-debuginfo~4.3.3_04_k3.11.10_25~34.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-desktop", rpm:"xen-kmp-desktop~4.3.3_04_k3.11.10_25~34.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-desktop-debuginfo", rpm:"xen-kmp-desktop-debuginfo~4.3.3_04_k3.11.10_25~34.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.3.3_04~34.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-debuginfo", rpm:"xen-libs-debuginfo~4.3.3_04~34.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.3.3_04~34.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU-debuginfo", rpm:"xen-tools-domU-debuginfo~4.3.3_04~34.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.3.3_04~34.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.3.3_04~34.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.3.3_04~34.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-debuginfo-32bit", rpm:"xen-libs-debuginfo-32bit~4.3.3_04~34.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.3.3_04~34.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-debuginfo", rpm:"xen-tools-debuginfo~4.3.3_04~34.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-xend-tools", rpm:"xen-xend-tools~4.3.3_04~34.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-xend-tools-debuginfo", rpm:"xen-xend-tools-debuginfo~4.3.3_04~34.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-pae", rpm:"xen-kmp-pae~4.3.3_04_k3.11.10_25~34.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-pae-debuginfo", rpm:"xen-kmp-pae-debuginfo~4.3.3_04_k3.11.10_25~34.1", rls:"openSUSE13.1"))) {
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
