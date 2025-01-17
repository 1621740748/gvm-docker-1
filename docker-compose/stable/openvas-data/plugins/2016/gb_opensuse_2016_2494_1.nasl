# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.851407");
  script_version("2020-01-31T08:23:39+0000");
  script_tag(name:"last_modification", value:"2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2016-10-12 05:46:28 +0200 (Wed, 12 Oct 2016)");
  script_cve_id("CVE-2014-3615", "CVE-2014-3672", "CVE-2015-7512", "CVE-2015-8504",
                "CVE-2015-8558", "CVE-2015-8568", "CVE-2015-8613", "CVE-2015-8743",
                "CVE-2016-1714", "CVE-2016-1981", "CVE-2016-3158", "CVE-2016-3159",
                "CVE-2016-3710", "CVE-2016-3712", "CVE-2016-3960", "CVE-2016-4001",
                "CVE-2016-4002", "CVE-2016-4020", "CVE-2016-4037", "CVE-2016-4439",
                "CVE-2016-4441", "CVE-2016-4453", "CVE-2016-4454", "CVE-2016-4480",
                "CVE-2016-4952", "CVE-2016-4962", "CVE-2016-4963", "CVE-2016-5105",
                "CVE-2016-5106", "CVE-2016-5107", "CVE-2016-5126", "CVE-2016-5238",
                "CVE-2016-5337", "CVE-2016-5338", "CVE-2016-5403", "CVE-2016-6258",
                "CVE-2016-6259", "CVE-2016-6351", "CVE-2016-6833", "CVE-2016-6834",
                "CVE-2016-6835", "CVE-2016-6836", "CVE-2016-6888", "CVE-2016-7092",
                "CVE-2016-7093", "CVE-2016-7094");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for xen (openSUSE-SU-2016:2494-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes the following issues:

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

  - CVE-2016-6836: VMWARE VMXNET3 NIC device support was leaging information
  leakage. A privileged user inside guest could have used this to leak
  host memory bytes to a guest (boo#994761)

  - CVE-2016-6888: Integer overflow in packet initialisation in VMXNET3
  device driver. A privileged user inside guest could have used this flaw
  to crash the Qemu instance resulting in DoS (bsc#994772)

  - CVE-2016-6833: Use-after-free issue in the VMWARE VMXNET3 NIC device
  support. A privileged user inside guest could have used this issue to
  crash the Qemu instance resulting in DoS (boo#994775)

  - CVE-2016-6835: Buffer overflow in the VMWARE VMXNET3 NIC device support,
  causing an OOB read access (bsc#994625)

  - CVE-2016-6834: A infinite loop during packet fragmentation in the VMWARE
  VMXNET3 NIC device support allowed privileged user inside guest to crash
  the Qemu instance resulting in DoS (bsc#994421)

  - CVE-2016-6258: The PV pagetable code in arch/x86/mm.c in Xen allowed
  local 32-bit PV guest OS administrators to gain host OS privileges by
  leveraging fast-paths for updating pagetable entries (bsc#988675)

  - CVE-2016-6259: Xen did not implement Supervisor Mode Access Prevention
  (SMAP) whitelisting in 32-bit exception and event delivery, which
  allowed local 32-bit PV guest OS kernels to cause a denial of service
  (hypervisor and VM crash) by triggering a safety check (bsc#988676)

  - CVE-2016-5403: The virtqueue_pop function in hw/virtio/virtio.c in QEMU
  allowed local guest OS administrators to cause a denial of service
  (memory consumption and QEMU process crash) by submitting requests
  without waiting for completion (boo#990923)

  - CVE-2016-6351: The esp_do_dma function in hw/scsi/esp.c, when built with
  ESP/NCR53C9x controller emulation support, allowed local guest OS
  administrators to cause a denial of service (out-of-bounds write and
  QEMU process c ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"affected", value:"xen on openSUSE Leap 42.1");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2016:2494-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.1");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap42.1") {
  if(!isnull(res = isrpmvuln(pkg:"xen-debugsource", rpm:"xen-debugsource~4.5.3_10~15.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-devel", rpm:"xen-devel~4.5.3_10~15.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.5.3_10~15.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-debuginfo", rpm:"xen-libs-debuginfo~4.5.3_10~15.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.5.3_10~15.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU-debuginfo", rpm:"xen-tools-domU-debuginfo~4.5.3_10~15.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.5.3_10~15.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.5.3_10~15.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.5.3_10_k4.1.31_30~15.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default-debuginfo", rpm:"xen-kmp-default-debuginfo~4.5.3_10_k4.1.31_30~15.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.5.3_10~15.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-debuginfo-32bit", rpm:"xen-libs-debuginfo-32bit~4.5.3_10~15.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.5.3_10~15.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-debuginfo", rpm:"xen-tools-debuginfo~4.5.3_10~15.2", rls:"openSUSELeap42.1"))) {
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
