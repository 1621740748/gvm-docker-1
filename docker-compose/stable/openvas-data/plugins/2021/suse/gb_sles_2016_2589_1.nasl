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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.2589.1");
  script_cve_id("CVE-2016-2391", "CVE-2016-2392", "CVE-2016-4453", "CVE-2016-4454", "CVE-2016-5105", "CVE-2016-5106", "CVE-2016-5107", "CVE-2016-5126", "CVE-2016-5238", "CVE-2016-5337", "CVE-2016-5338", "CVE-2016-5403", "CVE-2016-6490", "CVE-2016-6833", "CVE-2016-6836", "CVE-2016-6888", "CVE-2016-7116", "CVE-2016-7155", "CVE-2016-7156");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-15 18:50:00 +0000 (Thu, 15 Oct 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:2589-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:2589-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20162589-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu' package(s) announced via the SUSE-SU-2016:2589-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"qemu was updated to fix 19 security issues.
These security issues were fixed:
- CVE-2016-2392: The is_rndis function in the USB Net device emulator
 (hw/usb/dev-network.c) in QEMU did not properly validate USB
 configuration descriptor objects, which allowed local guest OS
 administrators to cause a denial of service (NULL pointer dereference
 and QEMU process crash) via vectors involving a remote NDIS control
 message packet (bsc#967012)
- CVE-2016-2391: The ohci_bus_start function in the USB OHCI emulation
 support (hw/usb/hcd-ohci.c) in QEMU allowed local guest OS
 administrators to cause a denial of service (NULL pointer dereference
 and QEMU process crash) via vectors related to multiple eof_timers
 (bsc#967013)
- CVE-2016-5106: The megasas_dcmd_set_properties function in
 hw/scsi/megasas.c in QEMU, when built with MegaRAID SAS 8708EM2 Host Bus
 Adapter emulation support, allowed local guest administrators to cause a
 denial of service (out-of-bounds write access) via vectors involving a
 MegaRAID Firmware Interface (MFI) command (bsc#982018)
- CVE-2016-5105: The megasas_dcmd_cfg_read function in hw/scsi/megasas.c
 in QEMU, when built with MegaRAID SAS 8708EM2 Host Bus Adapter emulation
 support, used an uninitialized variable, which allowed local guest
 administrators to read host memory via vectors involving a MegaRAID
 Firmware Interface (MFI) command (bsc#982017)
- CVE-2016-5107: The megasas_lookup_frame function in QEMU, when built
 with MegaRAID SAS 8708EM2 Host Bus Adapter emulation support, allowed
 local guest OS administrators to cause a denial of service
 (out-of-bounds read and crash) via unspecified vectors (bsc#982019)
- CVE-2016-5126: Heap-based buffer overflow in the iscsi_aio_ioctl
 function in block/iscsi.c in QEMU allowed local guest OS users to cause
 a denial of service (QEMU process crash) or possibly execute arbitrary
 code via a crafted iSCSI asynchronous I/O ioctl call (bsc#982285)
- CVE-2016-4454: The vmsvga_fifo_read_raw function in
 hw/display/vmware_vga.c in QEMU allowed local guest OS administrators to
 obtain sensitive host memory information or cause a denial of service
 (QEMU process crash) by changing FIFO registers and issuing a VGA
 command, which triggers an out-of-bounds read (bsc#982222)
- CVE-2016-4453: The vmsvga_fifo_run function in hw/display/vmware_vga.c
 in QEMU allowed local guest OS administrators to cause a denial of
 service (infinite loop and QEMU process crash) via a VGA command
 (bsc#982223)
- CVE-2016-5338: The (1) esp_reg_read and (2) esp_reg_write functions in
 hw/scsi/esp.c in QEMU allowed local guest OS administrators to cause a
 denial of service (QEMU process crash) or execute arbitrary code on the
 QEMU host via vectors related to the information transfer buffer
 (bsc#983982)
- CVE-2016-5337: The megasas_ctrl_get_info function in hw/scsi/megasas.c
 in QEMU allowed local guest OS administrators to obtain ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'qemu' package(s) on SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Desktop 12-SP1.");

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

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"qemu", rpm:"qemu~2.3.1~21.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-curl", rpm:"qemu-block-curl~2.3.1~21.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-curl-debuginfo", rpm:"qemu-block-curl-debuginfo~2.3.1~21.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-debugsource", rpm:"qemu-debugsource~2.3.1~21.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~2.3.1~21.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-guest-agent-debuginfo", rpm:"qemu-guest-agent-debuginfo~2.3.1~21.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-lang", rpm:"qemu-lang~2.3.1~21.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-tools", rpm:"qemu-tools~2.3.1~21.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-tools-debuginfo", rpm:"qemu-tools-debuginfo~2.3.1~21.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~2.3.1~21.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ppc", rpm:"qemu-ppc~2.3.1~21.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ppc-debuginfo", rpm:"qemu-ppc-debuginfo~2.3.1~21.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ipxe", rpm:"qemu-ipxe~1.0.0~21.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-seabios", rpm:"qemu-seabios~1.8.1~21.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-sgabios", rpm:"qemu-sgabios~8~21.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-vgabios", rpm:"qemu-vgabios~1.8.1~21.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-rbd", rpm:"qemu-block-rbd~2.3.1~21.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-rbd-debuginfo", rpm:"qemu-block-rbd-debuginfo~2.3.1~21.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-x86", rpm:"qemu-x86~2.3.1~21.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-s390", rpm:"qemu-s390~2.3.1~21.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-s390-debuginfo", rpm:"qemu-s390-debuginfo~2.3.1~21.1", rls:"SLES12.0SP1"))) {
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
