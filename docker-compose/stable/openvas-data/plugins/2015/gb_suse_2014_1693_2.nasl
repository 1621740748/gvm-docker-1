# Copyright (C) 2015 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.850805");
  script_version("2020-01-31T07:58:03+0000");
  script_tag(name:"last_modification", value:"2020-01-31 07:58:03 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2015-10-13 18:35:01 +0530 (Tue, 13 Oct 2015)");
  script_cve_id("CVE-2012-4398", "CVE-2013-2889", "CVE-2013-2893", "CVE-2013-2897", "CVE-2013-2899", "CVE-2013-7263", "CVE-2014-3181", "CVE-2014-3184", "CVE-2014-3185", "CVE-2014-3186", "CVE-2014-3601", "CVE-2014-3610", "CVE-2014-3646", "CVE-2014-3647", "CVE-2014-3673", "CVE-2014-4508", "CVE-2014-4608", "CVE-2014-7826", "CVE-2014-7841", "CVE-2014-8709", "CVE-2014-8884");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SUSE: Security Advisory for Linux (SUSE-SU-2014:1693-2)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 Service Pack 3 kernel has been updated to fix
  various bugs and security issues.

  The following security bugs have been fixed:

  * CVE-2012-4398: The __request_module function in kernel/kmod.c in the
  Linux kernel before 3.4 did not set a certain killable attribute,
  which allowed local users to cause a denial of service (memory
  consumption) via a crafted application (bnc#779488).

  * CVE-2013-2889: drivers/hid/hid-zpff.c in the Human Interface Device
  (HID) subsystem in the Linux kernel through 3.11, when
  CONFIG_HID_ZEROPLUS is enabled, allowed physically proximate
  attackers to cause a denial of service (heap-based out-of-bounds
  write) via a crafted device (bnc#835839).

  * CVE-2013-2893: The Human Interface Device (HID) subsystem in the
  Linux kernel through 3.11, when CONFIG_LOGITECH_FF,
  CONFIG_LOGIG940_FF, or CONFIG_LOGIWHEELS_FF is enabled, allowed
  physically proximate attackers to cause a denial of service
  (heap-based out-of-bounds write) via a crafted device, related to
  (1) drivers/hid/hid-lgff.c, (2) drivers/hid/hid-lg3ff.c, and (3)
  drivers/hid/hid-lg4ff.c (bnc#835839).

  * CVE-2013-2897: Multiple array index errors in
  drivers/hid/hid-multitouch.c in the Human Interface Device (HID)
  subsystem in the Linux kernel through 3.11, when
  CONFIG_HID_MULTITOUCH is enabled, allowed physically proximate
  attackers to cause a denial of service (heap memory corruption, or
  NULL pointer dereference and OOPS) via a crafted device (bnc#835839).

  * CVE-2013-2899: drivers/hid/hid-picolcd_core.c in the Human Interface
  Device (HID) subsystem in the Linux kernel through 3.11, when
  CONFIG_HID_PICOLCD is enabled, allowed physically proximate
  attackers to cause a denial of service (NULL pointer dereference and
  OOPS) via a crafted device (bnc#835839).

  * CVE-2013-7263: The Linux kernel before 3.12.4 updates certain length
  values before ensuring that associated data structures have been
  initialized, which allowed local users to obtain sensitive
  information from kernel stack memory via a (1) recvfrom, (2)
  recvmmsg, or (3) recvmsg system call, related to net/ipv4/ping.c,
  net/ipv4/raw.c, net/ipv4/udp.c, net/ipv6/raw.c, and net/ipv6/udp.c
  (bnc#853040, bnc#857643).

  * CVE-2014-3181: Multiple stack-based buffer overflows in the
  magicmouse_raw_event function in drivers/hid/hid-magicmouse.c in the
  Magic Mouse HID driver in the Linux kernel through 3.16.3 allowed
  physically proximate attackers to cause a denial of service (system
  crash) or possibly execute arbitrary code via a crafted device that
  prov ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"affected", value:"Linux on SUSE Linux Enterprise Server 11 SP3");

  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"SUSE-SU", value:"2014:1693-2");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=SLES11\.0SP3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES11.0SP3") {
  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~0.42.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~0.42.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~0.42.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~0.42.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~0.42.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~0.42.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~0.42.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~0.42.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.0.101~0.42.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64", rpm:"kernel-ppc64~3.0.101~0.42.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-base", rpm:"kernel-ppc64-base~3.0.101~0.42.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-devel", rpm:"kernel-ppc64-devel~3.0.101~0.42.1", rls:"SLES11.0SP3"))) {
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
