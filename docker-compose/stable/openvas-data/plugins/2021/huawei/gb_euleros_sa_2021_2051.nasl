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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.2051");
  script_version("2021-07-01T07:40:52+0000");
  script_cve_id("CVE-2020-27171", "CVE-2020-35519", "CVE-2020-36310", "CVE-2020-36311", "CVE-2020-36312", "CVE-2020-36313", "CVE-2020-36322", "CVE-2021-20292", "CVE-2021-23133", "CVE-2021-28660", "CVE-2021-28964", "CVE-2021-28971", "CVE-2021-29154", "CVE-2021-29264", "CVE-2021-29647", "CVE-2021-29650", "CVE-2021-30002", "CVE-2021-3483");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-07-01 07:40:52 +0000 (Thu, 01 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-01 07:40:52 +0000 (Thu, 01 Jul 2021)");
  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2021-2051)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP9-x86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-2051");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2051");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'kernel' package(s) announced via the EulerOS-SA-2021-2051 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in the Nosy driver in the Linux kernel. This issue allows a device to be inserted twice into a doubly-linked list, leading to a use-after-free when one of these devices is removed. The highest threat from this vulnerability is to confidentiality, integrity, as well as system availability.(CVE-2021-3483)

An issue was discovered in the Linux kernel before 5.11.3 when a webcam device exists. video_usercopy in drivers/media/v4l2-core/v4l2-ioctl.c has a memory leak for large arguments, aka CID-fb18802a338b.(CVE-2021-30002)

An issue was discovered in the FUSE filesystem implementation in the Linux kernel before 5.10.6, aka CID-5d069dbe8aaf. fuse_do_getattr() calls make_bad_inode() in inappropriate situations, causing a system crash. NOTE: the original fix for this vulnerability was incomplete, and its incompleteness is tracked as CVE-2021-28950.(CVE-2020-36322)

There is a flaw reported in drivers/gpu/drm/nouveau/nouveau_sgdma.c in nouveau_sgdma_create_ttm in Nouveau DRM subsystem. The issue results from the lack of validating the existence of an object prior to performing operations on the object. An attacker with a local account with a root privilege, can leverage this vulnerability to escalate privileges and execute code in the context of the kernel.(CVE-2021-20292)

An issue was discovered in the Linux kernel before 5.8. arch/x86/kvm/svm/svm.c allows a set_memory_region_test infinite loop for certain nested page faults, aka CID-e72436bc3a52.(CVE-2020-36310)

A race condition was found in the Linux kernel in sctp_destroy_sock. If sctp_destroy_sock is called without sock_net(sk)-sctp.addr_wq_lock held and sp-do_auto_asconf is true, then an element is removed from the auto_asconf_splist without any proper locking. This can lead to kernel privilege escalation from the context of a network service or from an unprivileged process if certain conditions are met.(CVE-2021-23133)

In intel_pmu_drain_pebs_nhm in arch/x86/events/intel/ds.c in the Linux kernel through 5.11.8 on some Haswell CPUs, userspace applications (such as perf-fuzzer) can cause a system crash because the PEBS status in a PEBS record is mishandled, aka CID-d88d05a9e0b6.(CVE-2021-28971)

BPF JIT compilers in the Linux kernel through 5.11.12 have incorrect computation of branch displacements, allowing them to execute arbitrary code within the kernel context. This affects arch/x86/net/bpf_jit_comp.c and arch/x86/net/bpf_jit_comp32.c.(CVE-2021-29154)

An issue was discovered in the Linux kernel before 5.11.11. qrtr_recvmsg in net/qrtr/qrtr.c allows attackers to obtain sensitive information from kernel memory be ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP9(x86_64).");

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

if(release == "EULEROS-2.0SP9-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.18.0~147.5.1.6.h451.eulerosv2r9", rls:"EULEROS-2.0SP9-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.18.0~147.5.1.6.h451.eulerosv2r9", rls:"EULEROS-2.0SP9-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.18.0~147.5.1.6.h451.eulerosv2r9", rls:"EULEROS-2.0SP9-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~4.18.0~147.5.1.6.h451.eulerosv2r9", rls:"EULEROS-2.0SP9-x86_64"))) {
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