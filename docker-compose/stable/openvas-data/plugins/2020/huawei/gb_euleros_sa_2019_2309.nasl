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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.2309");
  script_version("2021-08-03T11:00:50+0000");
  script_cve_id("CVE-2019-14814", "CVE-2019-14815", "CVE-2019-14816", "CVE-2019-14835", "CVE-2019-15030", "CVE-2019-15031", "CVE-2019-15090", "CVE-2019-15098", "CVE-2019-15099", "CVE-2019-15212", "CVE-2019-15213", "CVE-2019-15215", "CVE-2019-15216", "CVE-2019-15217", "CVE-2019-15918", "CVE-2019-15922", "CVE-2019-15923", "CVE-2019-15924", "CVE-2019-15926");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_tag(name:"last_modification", value:"2021-08-03 11:00:50 +0000 (Tue, 03 Aug 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-14 04:15:00 +0000 (Sat, 14 Sep 2019)");
  script_tag(name:"creation_date", value:"2020-01-23 12:46:29 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2019-2309)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64-3\.0\.3\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-2309");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2309");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'kernel' package(s) announced via the EulerOS-SA-2019-2309 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered in the Linux kernel before 5.2.3. There is a use-after-free caused by a malicious USB device in the drivers/media/usb/dvb-usb/dvb-usb-init.c driver.(CVE-2019-15213)

An issue was discovered in the Linux kernel before 5.2.6. There is a use-after-free caused by a malicious USB device in the drivers/media/usb/cpia2/cpia2_usb.c driver.(CVE-2019-15215)

An issue was discovered in the Linux kernel before 5.2.3. There is a NULL pointer dereference caused by a malicious USB device in the drivers/media/usb/zr364xx/zr364xx.c driver.(CVE-2019-15217)

An issue was discovered in the Linux kernel before 5.1.8. There is a double-free caused by a malicious USB device in the drivers/usb/misc/rio500.c driver.(CVE-2019-15212)

An issue was discovered in the Linux kernel before 5.0.14. There is a NULL pointer dereference caused by a malicious USB device in the drivers/usb/misc/yurex.c driver.(CVE-2019-15216)

An issue was discovered in drivers/scsi/qedi/qedi_dbg.c in the Linux kernel before 5.1.12. In the qedi_dbg_* family of functions, there is an out-of-bounds read.(CVE-2019-15090)

An issue was discovered in the Linux kernel before 5.0.9. There is a NULL pointer dereference for a cd data structure if alloc_disk fails in drivers/block/paride/pf.c.(CVE-2019-15923)

An issue was discovered in the Linux kernel before 5.0.10. SMB2_negotiate in fs/cifs/smb2pdu.c has an out-of-bounds read because data structures are incompletely updated after a change from smb30 to smb21.(CVE-2019-15918)

An issue was discovered in the Linux kernel before 5.0.9. There is a NULL pointer dereference for a pf data structure if alloc_disk fails in drivers/block/paride/pf.c.(CVE-2019-15922)

An issue was discovered in the Linux kernel before 5.2.3. Out of bounds access exists in the functions ath6kl_wmi_pstream_timeout_event_rx and ath6kl_wmi_cac_event_rx in the file drivers/net/wireless/ath/ath6kl/wmi.c.(CVE-2019-15926)

An issue was discovered in the Linux kernel before 5.0.11. fm10k_init_module in drivers/net/ethernet/intel/fm10k/fm10k_main.c has a NULL pointer dereference because there is no -ENOMEM upon an alloc_workqueue failure.(CVE-2019-15924)

A buffer overflow flaw was found, in versions from 2.6.34 to 5.2.x, in the way Linux kernel's vhost functionality that translates virtqueue buffers to IOVs, logged the buffer descriptors during migration. A privileged guest user able to pass descriptors with invalid length to the host when migration is underway, could use this flaw to increase their privileges on the host.(CVE-2019-14835)

In the Linux kernel through 5.2.14 on the powerpc ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.3.0.");

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

if(release == "EULEROSVIRTARM64-3.0.3.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.19.36~vhulk1907.1.0.h463.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.3.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.19.36~vhulk1907.1.0.h463.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.3.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~4.19.36~vhulk1907.1.0.h463.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.3.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.19.36~vhulk1907.1.0.h463.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.3.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.19.36~vhulk1907.1.0.h463.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.3.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~4.19.36~vhulk1907.1.0.h463.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.3.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~4.19.36~vhulk1907.1.0.h463.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.3.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~4.19.36~vhulk1907.1.0.h463.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.3.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~4.19.36~vhulk1907.1.0.h463.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.3.0"))) {
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
