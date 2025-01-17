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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.3372.1");
  script_cve_id("CVE-2019-0154", "CVE-2019-14895", "CVE-2019-14901", "CVE-2019-15213", "CVE-2019-15916", "CVE-2019-16231", "CVE-2019-17055", "CVE-2019-18660", "CVE-2019-18683", "CVE-2019-18805", "CVE-2019-18809", "CVE-2019-19046", "CVE-2019-19049", "CVE-2019-19052", "CVE-2019-19056", "CVE-2019-19057", "CVE-2019-19058", "CVE-2019-19060", "CVE-2019-19062", "CVE-2019-19063", "CVE-2019-19065", "CVE-2019-19067", "CVE-2019-19068", "CVE-2019-19073", "CVE-2019-19074", "CVE-2019-19075", "CVE-2019-19077", "CVE-2019-19078", "CVE-2019-19080", "CVE-2019-19081", "CVE-2019-19082", "CVE-2019-19083", "CVE-2019-19227", "CVE-2019-19524", "CVE-2019-19525", "CVE-2019-19528", "CVE-2019-19529", "CVE-2019-19530", "CVE-2019-19531", "CVE-2019-19534", "CVE-2019-19536", "CVE-2019-19543");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:11 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-12 16:15:00 +0000 (Thu, 12 Dec 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:3372-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:3372-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20193372-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:3372-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP1 Azure kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:
CVE-2019-15213: An issue was discovered in the Linux kernel, there was a
 use-after-free caused by a malicious USB device in the
 drivers/media/usb/dvb-usb/dvb-usb-init.c driver (bnc#1146544).

CVE-2019-19531: There was a use-after-free bug that can be caused by a
 malicious USB device in the drivers/usb/misc/yurex.c driver
 (bnc#1158445).

CVE-2019-19543: There was a use-after-free in serial_ir_init_module() in
 drivers/media/rc/serial_ir.c (bnc#1158427).

CVE-2019-19525: There was a use-after-free bug that can be caused by a
 malicious USB device in the drivers/net/ieee802154/atusb.c driver
 (bnc#1158417).

CVE-2019-19530: There was a use-after-free bug that can be caused by a
 malicious USB device in the drivers/usb/class/cdc-acm.c driver
 (bnc#1158410).

CVE-2019-19536: There was an info-leak bug that can be caused by a
 malicious USB device in the drivers/net/can/usb/peak_usb/pcan_usb_pro.c
 driver (bnc#1158394).

CVE-2019-19524: There was a use-after-free bug that can be caused by a
 malicious USB device in the drivers/input/ff-memless.c driver
 (bnc#1158413).

CVE-2019-19528: There was a use-after-free bug that can be caused by a
 malicious USB device in the drivers/usb/misc/iowarrior.c driver
 (bnc#1158407).

CVE-2019-19534: There was an info-leak bug that can be caused by a
 malicious USB device in the drivers/net/can/usb/peak_usb/pcan_usb_core.c
 driver (bnc#1158398).

CVE-2019-19529: There was a use-after-free bug that can be caused by a
 malicious USB device in the drivers/net/can/usb/mcba_usb.c driver
 (bnc#1158381).

CVE-2019-14901: A heap overflow flaw was found in the Linux kernel in
 Marvell WiFi chip driver. The vulnerability allowed a remote attacker to
 cause a system crash, resulting in a denial of service, or execute
 arbitrary code. The highest threat with this vulnerability is with the
 availability of the system. If code execution occurs, the code will run
 with the permissions of root. This will affect both confidentiality and
 integrity of files on the system (bnc#1157042).

CVE-2019-14895: A heap-based buffer overflow was discovered in the Linux
 kernel in Marvell WiFi chip driver. The flaw could occur when the
 station attempts a connection negotiation during the handling of the
 remote devices country settings. This could have allowed the remote
 device to cause a denial of service (system crash) or possibly execute
 arbitrary code (bnc#1157158).

CVE-2019-18660: The Linux kernel on powerpc allowed Information Exposure
 because the Spectre-RSB mitigation is not in place for all applicable
 CPUs. This is related to arch/powerpc/kernel/entry_64.S and
 arch/powerpc/kernel/security.c (bnc#1157038).

CVE-2019-18683: An issue was discovered in drivers/media/platform/vivid
 in the Linux kernel. It is ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Module for Public Cloud 15-SP1.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~8.22.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~8.22.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base-debuginfo", rpm:"kernel-azure-base-debuginfo~4.12.14~8.22.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~4.12.14~8.22.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~8.22.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~8.22.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~8.22.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~8.22.1", rls:"SLES15.0SP1"))) {
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
