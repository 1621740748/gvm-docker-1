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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.2507.1");
  script_cve_id("CVE-2016-6258", "CVE-2016-6833", "CVE-2016-6834", "CVE-2016-6835", "CVE-2016-6836", "CVE-2016-6888", "CVE-2016-7092", "CVE-2016-7093", "CVE-2016-7094", "CVE-2016-7154");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:04 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-01 01:29:00 +0000 (Sat, 01 Jul 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:2507-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:2507-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20162507-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2016:2507-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes several issues.
These security issues were fixed:
- CVE-2016-7092: The get_page_from_l3e function in arch/x86/mm.c in Xen
 allowed local 32-bit PV guest OS administrators to gain host OS
 privileges via vectors related to L3 recursive pagetables (bsc#995785)
- CVE-2016-7093: Xen allowed local HVM guest OS administrators to
 overwrite hypervisor memory and consequently gain host OS privileges by
 leveraging mishandling of instruction pointer truncation during
 emulation (bsc#995789)
- CVE-2016-7094: Buffer overflow in Xen allowed local x86 HVM guest OS
 administrators on guests running with shadow paging to cause a denial of
 service via a pagetable update (bsc#995792)
- CVE-2016-7154: Use-after-free vulnerability in the FIFO event channel
 code in Xen allowed local guest OS administrators to cause a denial of
 service (host crash) and possibly execute arbitrary code or obtain
 sensitive information via an invalid guest frame number (bsc#997731)
- CVE-2016-6836: VMWARE VMXNET3 NIC device allowed privileged user inside
 the guest to leak information. It occured while processing transmit(tx)
 queue, when it reaches the end of packet (bsc#994761)
- CVE-2016-6888: A integer overflow int the VMWARE VMXNET3 NIC device
 support, during the initialisation of new packets in the device, could
 have allowed a privileged user inside guest to crash the Qemu instance
 resulting in DoS (bsc#994772)
- CVE-2016-6833: A use-after-free issue in the VMWARE VMXNET3 NIC device
 support allowed privileged user inside guest to crash the Qemu instance
 resulting in DoS (bsc#994775)
- CVE-2016-6835: Buffer overflow in the VMWARE VMXNET3 NIC device support,
 causing an OOB read access (bsc#994625)
- CVE-2016-6834: A infinite loop during packet fragmentation in the VMWARE
 VMXNET3 NIC device support allowed privileged user inside guest to crash
 the Qemu instance resulting in DoS (bsc#994421)
- CVE-2016-6258: The PV pagetable code in arch/x86/mm.c in Xen allowed
 local 32-bit PV guest OS administrators to gain host OS privileges by
 leveraging fast-paths for updating pagetable entries (bsc#988675)
These non-security issues were fixed:
- bsc#993507: virsh detach-disk failing to detach disk
- bsc#991934: Xen hypervisor crash in csched_acct
- bsc#992224: During boot of Xen Hypervisor, Failed to get contiguous
 memory for DMA
- bsc#970135: New virtualization project clock test randomly fails on Xen
- bsc#994136: Unplug also SCSI disks in qemu-xen-traditional for upstream
 unplug protocol
- bsc#994136: xen_platform: unplug also SCSI disks in qemu-xen
- bsc#971949: xl: Support (by ignoring) xl migrate --live. xl migrations
 are always live
- bsc#990970: Add PMU support for Intel E7-8867 v4 (fam=6, model=79)
- bsc#966467: Live Migration SLES 11 SP3 to SP4 on AMD");

  script_tag(name:"affected", value:"'xen' package(s) on SUSE Linux Enterprise Software Development Kit 11-SP4, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Debuginfo 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.4.4_08_3.0.101_80~40.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.4.4_08~40.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.4.4_08~40.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.4.4_08~40.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.4.4_08~40.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.4.4_08~40.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.4.4_08~40.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-pae", rpm:"xen-kmp-pae~4.4.4_08_3.0.101_80~40.2", rls:"SLES11.0SP4"))) {
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
