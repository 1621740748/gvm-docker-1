# Copyright (C) 2014 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.850605");
  script_version("2020-01-31T08:23:39+0000");
  script_tag(name:"last_modification", value:"2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2014-08-11 12:26:14 +0200 (Mon, 11 Aug 2014)");
  script_cve_id("CVE-2014-0100", "CVE-2014-0131", "CVE-2014-2309", "CVE-2014-3917",
                "CVE-2014-4014", "CVE-2014-4171", "CVE-2014-4508", "CVE-2014-4652",
                "CVE-2014-4653", "CVE-2014-4654", "CVE-2014-4655", "CVE-2014-4656",
                "CVE-2014-4667", "CVE-2014-4699");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("openSUSE: Security Advisory for kernel (openSUSE-SU-2014:0985-1)");

  script_tag(name:"affected", value:"kernel on openSUSE 13.1");

  script_tag(name:"insight", value:"The Linux kernel was updated to fix security issues and bugs:

  Security issues fixed: CVE-2014-4699: The Linux kernel on Intel processors
  did not properly restrict use of a non-canonical value for the saved RIP
  address in the case of a system call that does not use IRET, which allowed
  local users to leverage a race condition and gain privileges, or cause a
  denial of service (double fault), via a crafted application that makes
  ptrace and fork system calls.

  CVE-2014-4667: The sctp_association_free function in net/sctp/associola.c
  in the Linux kernel did not properly manage a certain backlog value, which
  allowed remote attackers to cause a denial of service (socket
  outage) via a crafted SCTP packet.

  CVE-2014-4171: mm/shmem.c in the Linux kernel did not properly implement
  the interaction between range notification and hole punching, which
  allowed local users to cause a denial of service (i_mutex hold) by using
  the mmap system call to access a hole, as demonstrated by interfering with
  intended shmem activity by blocking completion of (1) an MADV_REMOVE
  madvise call or (2) an FALLOC_FL_PUNCH_HOLE fallocate call.

  CVE-2014-4508: arch/x86/kernel/entry_32.S in the Linux kernel on 32-bit
  x86 platforms, when syscall auditing is enabled and the sep CPU feature
  flag is set, allowed local users to cause a denial of service (OOPS and
  system crash) via an invalid syscall number, as demonstrated by number
  1000.

  CVE-2014-0100: Race condition in the inet_frag_intern function in
  net/ipv4/inet_fragment.c in the Linux kernel allowed remote attackers to
  cause a denial of service (use-after-free error) or possibly have
  unspecified other impact via a large series of fragmented ICMP Echo
  Request packets to a system with a heavy CPU load.

  CVE-2014-4656: Multiple integer overflows in sound/core/control.c in the
  ALSA control implementation in the Linux kernel allowed local users to
  cause a denial of service by leveraging /dev/snd/controlCX access, related
  to (1) index values in the snd_ctl_add function and (2) numid values in
  the snd_ctl_remove_numid_conflict function.

  CVE-2014-4655: The snd_ctl_elem_add function in sound/core/control.c in
  the ALSA control implementation in the Linux kernel did not properly
  maintain the user_ctl_count value, which allowed local users to cause a
  denial of service (integer overflow and limit bypass) by leveraging
  /dev/snd/controlCX access for a large number of
  SNDRV_CTL_IOCTL_ELEM_REPLACE ioctl calls.

  CVE-2014-4654: The snd_ctl_elem_add function in sound/core/control.c in
  the ALSA control implementation  ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"openSUSE-SU", value:"2014:0985-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
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
  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-base", rpm:"kernel-debug-base~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-base-debuginfo", rpm:"kernel-debug-base-debuginfo~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-debuginfo", rpm:"kernel-debug-debuginfo~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-debugsource", rpm:"kernel-debug-debugsource~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel-debuginfo", rpm:"kernel-debug-devel-debuginfo~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop", rpm:"kernel-desktop~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-base", rpm:"kernel-desktop-base~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-base-debuginfo", rpm:"kernel-desktop-base-debuginfo~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-debuginfo", rpm:"kernel-desktop-debuginfo~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-debugsource", rpm:"kernel-desktop-debugsource~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel", rpm:"kernel-desktop-devel~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel-debuginfo", rpm:"kernel-desktop-devel-debuginfo~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base-debuginfo", rpm:"kernel-ec2-base-debuginfo~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debuginfo", rpm:"kernel-ec2-debuginfo~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debugsource", rpm:"kernel-ec2-debugsource~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel-debuginfo", rpm:"kernel-ec2-devel-debuginfo~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base-debuginfo", rpm:"kernel-trace-base-debuginfo~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-debuginfo", rpm:"kernel-trace-debuginfo~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-debugsource", rpm:"kernel-trace-debugsource~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel-debuginfo", rpm:"kernel-trace-devel-debuginfo~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla", rpm:"kernel-vanilla~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-debuginfo", rpm:"kernel-vanilla-debuginfo~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-debugsource", rpm:"kernel-vanilla-debugsource~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-devel", rpm:"kernel-vanilla-devel~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-devel-debuginfo", rpm:"kernel-vanilla-devel-debuginfo~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base-debuginfo", rpm:"kernel-xen-base-debuginfo~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-debuginfo", rpm:"kernel-xen-debuginfo~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-debugsource", rpm:"kernel-xen-debugsource~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel-debuginfo", rpm:"kernel-xen-devel-debuginfo~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cloop", rpm:"cloop~2.639~11.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cloop-debuginfo", rpm:"cloop-debuginfo~2.639~11.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cloop-debugsource", rpm:"cloop-debugsource~2.639~11.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cloop-kmp-default", rpm:"cloop-kmp-default~2.639_k3.11.10_21~11.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cloop-kmp-default-debuginfo", rpm:"cloop-kmp-default-debuginfo~2.639_k3.11.10_21~11.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cloop-kmp-desktop", rpm:"cloop-kmp-desktop~2.639_k3.11.10_21~11.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cloop-kmp-desktop-debuginfo", rpm:"cloop-kmp-desktop-debuginfo~2.639_k3.11.10_21~11.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cloop-kmp-xen", rpm:"cloop-kmp-xen~2.639_k3.11.10_21~11.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cloop-kmp-xen-debuginfo", rpm:"cloop-kmp-xen-debuginfo~2.639_k3.11.10_21~11.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crash", rpm:"crash~7.0.2~2.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crash-debuginfo", rpm:"crash-debuginfo~7.0.2~2.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crash-debugsource", rpm:"crash-debugsource~7.0.2~2.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crash-devel", rpm:"crash-devel~7.0.2~2.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crash-doc", rpm:"crash-doc~7.0.2~2.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crash-eppic", rpm:"crash-eppic~7.0.2~2.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crash-eppic-debuginfo", rpm:"crash-eppic-debuginfo~7.0.2~2.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crash-gcore", rpm:"crash-gcore~7.0.2~2.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crash-gcore-debuginfo", rpm:"crash-gcore-debuginfo~7.0.2~2.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crash-kmp-default", rpm:"crash-kmp-default~7.0.2_k3.11.10_21~2.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crash-kmp-default-debuginfo", rpm:"crash-kmp-default-debuginfo~7.0.2_k3.11.10_21~2.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crash-kmp-desktop", rpm:"crash-kmp-desktop~7.0.2_k3.11.10_21~2.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crash-kmp-desktop-debuginfo", rpm:"crash-kmp-desktop-debuginfo~7.0.2_k3.11.10_21~2.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crash-kmp-xen", rpm:"crash-kmp-xen~7.0.2_k3.11.10_21~2.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crash-kmp-xen-debuginfo", rpm:"crash-kmp-xen-debuginfo~7.0.2_k3.11.10_21~2.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdjmod-debugsource", rpm:"hdjmod-debugsource~1.28~16.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdjmod-kmp-default", rpm:"hdjmod-kmp-default~1.28_k3.11.10_21~16.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdjmod-kmp-default-debuginfo", rpm:"hdjmod-kmp-default-debuginfo~1.28_k3.11.10_21~16.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdjmod-kmp-desktop", rpm:"hdjmod-kmp-desktop~1.28_k3.11.10_21~16.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdjmod-kmp-desktop-debuginfo", rpm:"hdjmod-kmp-desktop-debuginfo~1.28_k3.11.10_21~16.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdjmod-kmp-xen", rpm:"hdjmod-kmp-xen~1.28_k3.11.10_21~16.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdjmod-kmp-xen-debuginfo", rpm:"hdjmod-kmp-xen-debuginfo~1.28_k3.11.10_21~16.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipset", rpm:"ipset~6.21.1~2.17.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipset-debuginfo", rpm:"ipset-debuginfo~6.21.1~2.17.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipset-debugsource", rpm:"ipset-debugsource~6.21.1~2.17.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipset-devel", rpm:"ipset-devel~6.21.1~2.17.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipset-kmp-default", rpm:"ipset-kmp-default~6.21.1_k3.11.10_21~2.17.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipset-kmp-default-debuginfo", rpm:"ipset-kmp-default-debuginfo~6.21.1_k3.11.10_21~2.17.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipset-kmp-desktop", rpm:"ipset-kmp-desktop~6.21.1_k3.11.10_21~2.17.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipset-kmp-desktop-debuginfo", rpm:"ipset-kmp-desktop-debuginfo~6.21.1_k3.11.10_21~2.17.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipset-kmp-xen", rpm:"ipset-kmp-xen~6.21.1_k3.11.10_21~2.17.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipset-kmp-xen-debuginfo", rpm:"ipset-kmp-xen-debuginfo~6.21.1_k3.11.10_21~2.17.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iscsitarget", rpm:"iscsitarget~1.4.20.3~13.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iscsitarget-debuginfo", rpm:"iscsitarget-debuginfo~1.4.20.3~13.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iscsitarget-debugsource", rpm:"iscsitarget-debugsource~1.4.20.3~13.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iscsitarget-kmp-default", rpm:"iscsitarget-kmp-default~1.4.20.3_k3.11.10_21~13.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iscsitarget-kmp-default-debuginfo", rpm:"iscsitarget-kmp-default-debuginfo~1.4.20.3_k3.11.10_21~13.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iscsitarget-kmp-desktop", rpm:"iscsitarget-kmp-desktop~1.4.20.3_k3.11.10_21~13.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iscsitarget-kmp-desktop-debuginfo", rpm:"iscsitarget-kmp-desktop-debuginfo~1.4.20.3_k3.11.10_21~13.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iscsitarget-kmp-xen", rpm:"iscsitarget-kmp-xen~1.4.20.3_k3.11.10_21~13.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iscsitarget-kmp-xen-debuginfo", rpm:"iscsitarget-kmp-xen-debuginfo~1.4.20.3_k3.11.10_21~13.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libipset3", rpm:"libipset3~6.21.1~2.17.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libipset3-debuginfo", rpm:"libipset3-debuginfo~6.21.1~2.17.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ndiswrapper", rpm:"ndiswrapper~1.58~13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ndiswrapper-debuginfo", rpm:"ndiswrapper-debuginfo~1.58~13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ndiswrapper-debugsource", rpm:"ndiswrapper-debugsource~1.58~13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ndiswrapper-kmp-default", rpm:"ndiswrapper-kmp-default~1.58_k3.11.10_21~13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ndiswrapper-kmp-default-debuginfo", rpm:"ndiswrapper-kmp-default-debuginfo~1.58_k3.11.10_21~13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ndiswrapper-kmp-desktop", rpm:"ndiswrapper-kmp-desktop~1.58_k3.11.10_21~13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ndiswrapper-kmp-desktop-debuginfo", rpm:"ndiswrapper-kmp-desktop-debuginfo~1.58_k3.11.10_21~13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcfclock", rpm:"pcfclock~0.44~258.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcfclock-debuginfo", rpm:"pcfclock-debuginfo~0.44~258.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcfclock-debugsource", rpm:"pcfclock-debugsource~0.44~258.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcfclock-kmp-default", rpm:"pcfclock-kmp-default~0.44_k3.11.10_21~258.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcfclock-kmp-default-debuginfo", rpm:"pcfclock-kmp-default-debuginfo~0.44_k3.11.10_21~258.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcfclock-kmp-desktop", rpm:"pcfclock-kmp-desktop~0.44_k3.11.10_21~258.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcfclock-kmp-desktop-debuginfo", rpm:"pcfclock-kmp-desktop-debuginfo~0.44_k3.11.10_21~258.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-virtualbox", rpm:"python-virtualbox~4.2.18~2.18.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-virtualbox-debuginfo", rpm:"python-virtualbox-debuginfo~4.2.18~2.18.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vhba-kmp-debugsource", rpm:"vhba-kmp-debugsource~20130607~2.14.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vhba-kmp-default", rpm:"vhba-kmp-default~20130607_k3.11.10_21~2.14.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vhba-kmp-default-debuginfo", rpm:"vhba-kmp-default-debuginfo~20130607_k3.11.10_21~2.14.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vhba-kmp-desktop", rpm:"vhba-kmp-desktop~20130607_k3.11.10_21~2.14.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vhba-kmp-desktop-debuginfo", rpm:"vhba-kmp-desktop-debuginfo~20130607_k3.11.10_21~2.14.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vhba-kmp-xen", rpm:"vhba-kmp-xen~20130607_k3.11.10_21~2.14.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vhba-kmp-xen-debuginfo", rpm:"vhba-kmp-xen-debuginfo~20130607_k3.11.10_21~2.14.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox", rpm:"virtualbox~4.2.18~2.18.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-debuginfo", rpm:"virtualbox-debuginfo~4.2.18~2.18.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-debugsource", rpm:"virtualbox-debugsource~4.2.18~2.18.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-devel", rpm:"virtualbox-devel~4.2.18~2.18.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-kmp-default", rpm:"virtualbox-guest-kmp-default~4.2.18_k3.11.10_21~2.18.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-kmp-default-debuginfo", rpm:"virtualbox-guest-kmp-default-debuginfo~4.2.18_k3.11.10_21~2.18.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-kmp-desktop", rpm:"virtualbox-guest-kmp-desktop~4.2.18_k3.11.10_21~2.18.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-kmp-desktop-debuginfo", rpm:"virtualbox-guest-kmp-desktop-debuginfo~4.2.18_k3.11.10_21~2.18.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-tools", rpm:"virtualbox-guest-tools~4.2.18~2.18.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-tools-debuginfo", rpm:"virtualbox-guest-tools-debuginfo~4.2.18~2.18.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-x11", rpm:"virtualbox-guest-x11~4.2.18~2.18.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-x11-debuginfo", rpm:"virtualbox-guest-x11-debuginfo~4.2.18~2.18.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-host-kmp-default", rpm:"virtualbox-host-kmp-default~4.2.18_k3.11.10_21~2.18.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-host-kmp-default-debuginfo", rpm:"virtualbox-host-kmp-default-debuginfo~4.2.18_k3.11.10_21~2.18.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-host-kmp-desktop", rpm:"virtualbox-host-kmp-desktop~4.2.18_k3.11.10_21~2.18.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-host-kmp-desktop-debuginfo", rpm:"virtualbox-host-kmp-desktop-debuginfo~4.2.18_k3.11.10_21~2.18.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-qt", rpm:"virtualbox-qt~4.2.18~2.18.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-qt-debuginfo", rpm:"virtualbox-qt-debuginfo~4.2.18~2.18.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-websrv", rpm:"virtualbox-websrv~4.2.18~2.18.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-websrv-debuginfo", rpm:"virtualbox-websrv-debuginfo~4.2.18~2.18.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-debugsource", rpm:"xen-debugsource~4.3.2_01~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-devel", rpm:"xen-devel~4.3.2_01~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.3.2_01_k3.11.10_21~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default-debuginfo", rpm:"xen-kmp-default-debuginfo~4.3.2_01_k3.11.10_21~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-desktop", rpm:"xen-kmp-desktop~4.3.2_01_k3.11.10_21~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-desktop-debuginfo", rpm:"xen-kmp-desktop-debuginfo~4.3.2_01_k3.11.10_21~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.3.2_01~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-debuginfo", rpm:"xen-libs-debuginfo~4.3.2_01~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.3.2_01~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU-debuginfo", rpm:"xen-tools-domU-debuginfo~4.3.2_01~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons", rpm:"xtables-addons~2.3~2.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-debuginfo", rpm:"xtables-addons-debuginfo~2.3~2.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-debugsource", rpm:"xtables-addons-debugsource~2.3~2.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kmp-default", rpm:"xtables-addons-kmp-default~2.3_k3.11.10_21~2.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kmp-default-debuginfo", rpm:"xtables-addons-kmp-default-debuginfo~2.3_k3.11.10_21~2.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kmp-desktop", rpm:"xtables-addons-kmp-desktop~2.3_k3.11.10_21~2.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kmp-desktop-debuginfo", rpm:"xtables-addons-kmp-desktop-debuginfo~2.3_k3.11.10_21~2.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kmp-xen", rpm:"xtables-addons-kmp-xen~2.3_k3.11.10_21~2.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kmp-xen-debuginfo", rpm:"xtables-addons-kmp-xen-debuginfo~2.3_k3.11.10_21~2.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~3.11.10~21.3", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-vanilla", rpm:"kernel-source-vanilla~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.3.2_01~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.3.2_01~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.3.2_01~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-debuginfo-32bit", rpm:"xen-libs-debuginfo-32bit~4.3.2_01~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.3.2_01~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-debuginfo", rpm:"xen-tools-debuginfo~4.3.2_01~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-xend-tools", rpm:"xen-xend-tools~4.3.2_01~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-xend-tools-debuginfo", rpm:"xen-xend-tools-debuginfo~4.3.2_01~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base-debuginfo", rpm:"kernel-pae-base-debuginfo~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-debuginfo", rpm:"kernel-pae-debuginfo~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-debugsource", rpm:"kernel-pae-debugsource~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel-debuginfo", rpm:"kernel-pae-devel-debuginfo~3.11.10~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cloop-kmp-pae", rpm:"cloop-kmp-pae~2.639_k3.11.10_21~11.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cloop-kmp-pae-debuginfo", rpm:"cloop-kmp-pae-debuginfo~2.639_k3.11.10_21~11.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crash-kmp-pae", rpm:"crash-kmp-pae~7.0.2_k3.11.10_21~2.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crash-kmp-pae-debuginfo", rpm:"crash-kmp-pae-debuginfo~7.0.2_k3.11.10_21~2.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdjmod-kmp-pae", rpm:"hdjmod-kmp-pae~1.28_k3.11.10_21~16.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdjmod-kmp-pae-debuginfo", rpm:"hdjmod-kmp-pae-debuginfo~1.28_k3.11.10_21~16.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipset-kmp-pae", rpm:"ipset-kmp-pae~6.21.1_k3.11.10_21~2.17.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipset-kmp-pae-debuginfo", rpm:"ipset-kmp-pae-debuginfo~6.21.1_k3.11.10_21~2.17.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iscsitarget-kmp-pae", rpm:"iscsitarget-kmp-pae~1.4.20.3_k3.11.10_21~13.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iscsitarget-kmp-pae-debuginfo", rpm:"iscsitarget-kmp-pae-debuginfo~1.4.20.3_k3.11.10_21~13.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ndiswrapper-kmp-pae", rpm:"ndiswrapper-kmp-pae~1.58_k3.11.10_21~13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ndiswrapper-kmp-pae-debuginfo", rpm:"ndiswrapper-kmp-pae-debuginfo~1.58_k3.11.10_21~13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcfclock-kmp-pae", rpm:"pcfclock-kmp-pae~0.44_k3.11.10_21~258.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcfclock-kmp-pae-debuginfo", rpm:"pcfclock-kmp-pae-debuginfo~0.44_k3.11.10_21~258.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vhba-kmp-pae", rpm:"vhba-kmp-pae~20130607_k3.11.10_21~2.14.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vhba-kmp-pae-debuginfo", rpm:"vhba-kmp-pae-debuginfo~20130607_k3.11.10_21~2.14.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-kmp-pae", rpm:"virtualbox-guest-kmp-pae~4.2.18_k3.11.10_21~2.18.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-kmp-pae-debuginfo", rpm:"virtualbox-guest-kmp-pae-debuginfo~4.2.18_k3.11.10_21~2.18.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-host-kmp-pae", rpm:"virtualbox-host-kmp-pae~4.2.18_k3.11.10_21~2.18.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-host-kmp-pae-debuginfo", rpm:"virtualbox-host-kmp-pae-debuginfo~4.2.18_k3.11.10_21~2.18.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-pae", rpm:"xen-kmp-pae~4.3.2_01_k3.11.10_21~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-pae-debuginfo", rpm:"xen-kmp-pae-debuginfo~4.3.2_01_k3.11.10_21~21.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kmp-pae", rpm:"xtables-addons-kmp-pae~2.3_k3.11.10_21~2.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kmp-pae-debuginfo", rpm:"xtables-addons-kmp-pae-debuginfo~2.3_k3.11.10_21~2.13.1", rls:"openSUSE13.1"))) {
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
