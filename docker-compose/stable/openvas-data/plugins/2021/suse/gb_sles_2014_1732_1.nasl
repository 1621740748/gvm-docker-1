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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2014.1732.1");
  script_cve_id("CVE-2013-3495", "CVE-2014-4021", "CVE-2014-7154", "CVE-2014-7155", "CVE-2014-7156", "CVE-2014-8594", "CVE-2014-8595", "CVE-2014-8867", "CVE-2014-9030");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:15 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2014:1732-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2014:1732-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2014/suse-su-20141732-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2014:1732-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"xen was updated to fix 10 security issues:

 * Guest effectable page reference leak in MMU_MACHPHYS_UPDATE handling
 (CVE-2014-9030).
 * Insufficient bounding of 'REP MOVS' to MMIO emulated inside the
 hypervisor (CVE-2014-8867).
 * Missing privilege level checks in x86 emulation of far branches
 (CVE-2014-8595).
 * Missing privilege level checks in x86 HLT, LGDT, LIDT, and LMSW
 emulation (CVE-2014-7155).
 * Hypervisor heap contents leaked to guests (CVE-2014-4021).
 * Missing privilege level checks in x86 emulation of far branches
 (CVE-2014-8595).
 * Insufficient restrictions on certain MMU update hypercalls
 (CVE-2014-8594).
 * Intel VT-d Interrupt Remapping engines can be evaded by native NMI
 interrupts (CVE-2013-3495).
 * Missing privilege level checks in x86 emulation of software
 interrupts (CVE-2014-7156).
 * Race condition in HVMOP_track_dirty_vram (CVE-2014-7154).

Security Issues:

 * CVE-2014-9030
 * CVE-2014-8867
 * CVE-2014-8595
 * CVE-2014-7155
 * CVE-2014-4021
 * CVE-2014-8595
 * CVE-2014-8594
 * CVE-2013-3495
 * CVE-2014-7156
 * CVE-2014-7154Special Instructions and Notes:
Please reboot the system after installing this update.");

  script_tag(name:"affected", value:"'xen' package(s) on SUSE Linux Enterprise Server 11 SP1.");

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

if(release == "SLES11.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.0.3_21548_18~0.9.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.0.3_21548_18~0.9.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-pdf", rpm:"xen-doc-pdf~4.0.3_21548_18~0.9.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.0.3_21548_18_2.6.32.59_0.15~0.9.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-trace", rpm:"xen-kmp-trace~4.0.3_21548_18_2.6.32.59_0.15~0.9.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.0.3_21548_18~0.9.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.0.3_21548_18~0.9.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.0.3_21548_18~0.9.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-pae", rpm:"xen-kmp-pae~4.0.3_21548_18_2.6.32.59_0.15~0.9.1", rls:"SLES11.0SP1"))) {
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
