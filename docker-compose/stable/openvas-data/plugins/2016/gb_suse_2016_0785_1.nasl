# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.851242");
  script_version("2020-10-22T06:41:10+0000");
  script_tag(name:"last_modification", value:"2020-10-22 06:41:10 +0000 (Thu, 22 Oct 2020)");
  script_tag(name:"creation_date", value:"2016-03-17 05:11:31 +0100 (Thu, 17 Mar 2016)");
  script_cve_id("CVE-2013-7446", "CVE-2015-5707", "CVE-2015-8709", "CVE-2015-8767",
                "CVE-2015-8785", "CVE-2015-8812", "CVE-2016-0723", "CVE-2016-0774",
                "CVE-2016-2069", "CVE-2016-2384");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SUSE: Security Advisory for kernel (SUSE-SU-2016:0785-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 kernel was updated to 3.12.55 to receive
  various security and bugfixes.

  Features added:

  - A improved XEN blkfront module was added, which allows more I/O
  bandwidth. (FATE#320625) It is called xen-blkfront in PV, and
  xen-vbd-upstream in HVM mode.

  The following security bugs were fixed:

  - CVE-2013-7446: Use-after-free vulnerability in net/unix/af_unix.c in the
  Linux kernel allowed local users to bypass intended AF_UNIX socket
  permissions or cause a denial of service (panic) via crafted epoll_ctl
  calls (bnc#955654).

  - CVE-2015-5707: Integer overflow in the sg_start_req function in
  drivers/scsi/sg.c in the Linux kernel allowed local users to cause a
  denial of service or possibly have unspecified other impact via a large
  iov_count value in a write request (bnc#940338).

  - CVE-2015-8709: kernel/ptrace.c in the Linux kernel mishandled uid and
  gid mappings, which allowed local users to gain privileges by
  establishing a user namespace, waiting for a root process to enter that
  namespace with an unsafe uid or gid, and then using the ptrace system
  call.  NOTE: the vendor states 'there is no kernel bug here' (bnc#959709
  bnc#960561).

  - CVE-2015-8767: net/sctp/sm_sideeffect.c in the Linux kernel did not
  properly manage the relationship between a lock and a socket, which
  allowed local users to cause a denial of service (deadlock) via a
  crafted sctp_accept call (bnc#961509).

  - CVE-2015-8785: The fuse_fill_write_pages function in fs/fuse/file.c in
  the Linux kernel allowed local users to cause a denial of service
  (infinite loop) via a writev system call that triggers a zero length for
  the first segment of an iov (bnc#963765).

  - CVE-2015-8812: A use-after-free flaw was found in the CXGB3 kernel
  driver when the network was considered to be congested. This could be
  used by local attackers to cause machine crashes or potentially code
  execution (bsc#966437).

  - CVE-2016-0723: Race condition in the tty_ioctl function in
  drivers/tty/tty_io.c in the Linux kernel allowed local users to obtain
  sensitive information from kernel memory or cause a denial of service
  (use-after-free and system crash) by making a TIOCGETD ioctl call during
  processing of a TIOCSETD ioctl call (bnc#961500).

  - CVE-2016-0774: A pipe buffer state corruption after unsuccessful atomic
  read from pipe was fixed (bsc#964730).

  - CVE-2016-2069: Race conditions in TLB syncing was fixed which could leak
  to information leaks (bnc#963767).

  - CVE-2016-2384: A double-free triggered by invalid USB de ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"affected", value:"kernel on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Desktop 12");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"SUSE-SU", value:"2016:0785-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(SLED12\.0SP0|SLES12\.0SP0)");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLED12.0SP0") {
  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.12.55~52.42.1", rls:"SLED12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~3.12.55~52.42.1", rls:"SLED12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~3.12.55~52.42.1", rls:"SLED12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.12.55~52.42.1", rls:"SLED12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~3.12.55~52.42.1", rls:"SLED12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-extra-debuginfo", rpm:"kernel-default-extra-debuginfo~3.12.55~52.42.1", rls:"SLED12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.12.55~52.42.1", rls:"SLED12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.12.55~52.42.1", rls:"SLED12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-debuginfo", rpm:"kernel-xen-debuginfo~3.12.55~52.42.1", rls:"SLED12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-debugsource", rpm:"kernel-xen-debugsource~3.12.55~52.42.1", rls:"SLED12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.12.55~52.42.1", rls:"SLED12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.12.55~52.42.1", rls:"SLED12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~3.12.55~52.42.1", rls:"SLED12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.12.55~52.42.1", rls:"SLED12.0SP0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP0") {
  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.12.55~52.42.1", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.12.55~52.42.1", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~3.12.55~52.42.1", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~3.12.55~52.42.1", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~3.12.55~52.42.1", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.12.55~52.42.1", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.12.55~52.42.1", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.12.55~52.42.1", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.12.55~52.42.1", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base-debuginfo", rpm:"kernel-xen-base-debuginfo~3.12.55~52.42.1", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-debuginfo", rpm:"kernel-xen-debuginfo~3.12.55~52.42.1", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-debugsource", rpm:"kernel-xen-debugsource~3.12.55~52.42.1", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.12.55~52.42.1", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.12.55~52.42.1", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~3.12.55~52.42.1", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.12.55~52.42.1", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.12.55~52.42.1", rls:"SLES12.0SP0"))) {
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
