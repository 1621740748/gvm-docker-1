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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.2011");
  script_version("2021-07-01T07:38:37+0000");
  script_cve_id("CVE-2020-13754", "CVE-2020-13791", "CVE-2020-17380", "CVE-2020-25085", "CVE-2020-25625", "CVE-2020-27617", "CVE-2020-28916", "CVE-2021-3409", "CVE-2021-3416");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2021-07-01 07:38:37 +0000 (Thu, 01 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-01 07:38:37 +0000 (Thu, 01 Jul 2021)");
  script_name("Huawei EulerOS: Security Advisory for qemu-kvm (EulerOS-SA-2021-2011)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64-3\.0\.6\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-2011");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2011");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'qemu-kvm' package(s) announced via the EulerOS-SA-2021-2011 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A potential stack overflow via infinite loop issue was found in various NIC emulators of QEMU in versions up to and including 5.2.0. The issue occurs in loopback mode of a NIC wherein reentrant DMA checks get bypassed. A guest user/process may use this flaw to consume CPU cycles or crash the QEMU process on the host resulting in DoS scenario.(CVE-2021-34161)

hw/pci/pci.c in QEMU 4.2.0 allows guest OS users to trigger an out-of-bounds access by providing an address near the end of the PCI configuration space.CVE-2020-13791

hw/pci/msix.c in QEMU 4.2.0 allows guest OS users to trigger an out-of-bounds access via a crafted address in an msi-x mmio operation.CVE-2020-13754

A heap-based buffer overflow was found in QEMU through 5.0.0 in the SDHCI device emulation support. It could occur while doing a multi block SDMA transfer via the sdhci_sdma_transfer_multi_blocks() routine in hw/sd/sdhci.c. A guest user or process could use this flaw to crash the QEMU process on the host, resulting in a denial of service condition, or potentially execute arbitrary code with privileges of the QEMU process on the host. (CVE-2020-17380)

QEMU 5.0.0 has a heap-based Buffer Overflow in flatview_read_continue in exec.c because hw/sd/sdhci.c mishandles a write operation in the SDHC_BLKSIZE case. (CVE-2020-25085)

The patch for CVE-2020-17380/CVE-2020-25085 was found to be ineffective, thus making QEMU vulnerable to the out-of-bounds read/write access issues previously found in the SDHCI controller emulation code. This flaw allows a malicious privileged guest to crash the QEMU process on the host, resulting in a denial of service or potential code execution. QEMU up to (including) 5.2.0 is affected by this. (CVE-2021-3409)");

  script_tag(name:"affected", value:"'qemu-kvm' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.6.0.");

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

if(release == "EULEROSVIRTARM64-3.0.6.0") {

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~2.8.1~30.482", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~2.8.1~30.482", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-common", rpm:"qemu-kvm-common~2.8.1~30.482", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~2.8.1~30.482", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
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