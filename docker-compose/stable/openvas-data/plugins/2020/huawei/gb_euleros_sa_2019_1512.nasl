# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1512");
  script_version("2021-08-04T02:01:00+0000");
  script_cve_id("CVE-2016-10741", "CVE-2017-18360", "CVE-2017-7518", "CVE-2018-16862", "CVE-2018-17972", "CVE-2018-18281", "CVE-2018-18559", "CVE-2018-18710", "CVE-2018-19824", "CVE-2018-5332", "CVE-2018-5333", "CVE-2018-5344", "CVE-2018-5391", "CVE-2018-5750", "CVE-2018-6927", "CVE-2018-7757", "CVE-2018-8781", "CVE-2019-3701", "CVE-2019-5489", "CVE-2019-9213");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2021-08-04 02:01:00 +0000 (Wed, 04 Aug 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-21 16:00:00 +0000 (Thu, 21 Mar 2019)");
  script_tag(name:"creation_date", value:"2020-01-23 12:00:28 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2019-1512)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT-3\.0\.1\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-1512");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1512");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'kernel' package(s) announced via the EulerOS-SA-2019-1512 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In the Linux kernel through 4.14.13, the rds_message_alloc_sgs() function does not validate a value that is used during DMA page allocation, leading to a heap-based out-of-bounds write (related to the rds_rdma_extra_size() function in 'net/rds/rdma.c') and thus to a system panic. Due to the nature of the flaw, privilege escalation cannot be fully ruled out, although we believe it is unlikely.(CVE-2018-5332)

In the Linux kernel through 4.14.13, the rds_cmsg_atomic() function in 'net/rds/rdma.c' mishandles cases where page pinning fails or an invalid address is supplied by a user. This can lead to a NULL pointer dereference in rds_atomic_free_op() and thus to a system panic.(CVE-2018-5333)

A flaw was found in the Linux kernel's handling of loopback devices. An attacker, who has permissions to setup loopback disks, may create a denial of service or other unspecified actions.(CVE-2018-5344)

The acpi_smbus_hc_add function in drivers/acpi/sbshc.c in the Linux kernel, through 4.14.15, allows local users to obtain sensitive address information by reading dmesg data from an SBS HC printk call.(CVE-2018-5750)

The futex_requeue function in kernel/futex.c in the Linux kernel, before 4.14.15, might allow attackers to cause a denial of service (integer overflow) or possibly have unspecified other impacts by triggering a negative wake or requeue value. Due to the nature of the flaw, privilege escalation cannot be fully ruled out, although we believe it is unlikely.(CVE-2018-6927)

Memory leak in the sas_smp_get_phy_events function in drivers/scsi/libsas/sas_expander.c in the Linux kernel allows local users to cause a denial of service (kernel memory exhaustion) via multiple read accesses to files in the /sys/class/sas_phy directory.(CVE-2018-7757)

A an integer overflow vulnerability was discovered in the Linux kernel, from version 3.4 through 4.15, in the drivers/gpu/drm/udl/udl_fb.c:udl_fb_mmap() function. An attacker with access to the udldrmfb driver could exploit this to obtain full read and write permissions on kernel physical pages, resulting in a code execution in kernel space.(CVE-2018-8781)

A flaw was found in the way the Linux KVM module processed the trap flag(TF) bit in EFLAGS during emulation of the syscall instruction, which leads to a debug exception(#DB) being raised in the guest stack. A user/process inside a guest could use this flaw to potentially escalate their privileges inside the guest. Linux guests are not affected by this.(CVE-2017-7518)

A division-by-zero in set_termios(), when debugging is enabled, was found in the Linux kernel. When the [io_ti] driver is l ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS Virtualization 3.0.1.0.");

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

if(release == "EULEROSVIRT-3.0.1.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
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
