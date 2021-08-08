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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.1745.1");
  script_cve_id("CVE-2013-4527", "CVE-2013-4529", "CVE-2013-4530", "CVE-2013-4533", "CVE-2013-4534", "CVE-2013-4537", "CVE-2013-4538", "CVE-2013-4539", "CVE-2014-0222", "CVE-2014-3640", "CVE-2014-3689", "CVE-2014-7815", "CVE-2014-9718", "CVE-2015-5278", "CVE-2015-6855", "CVE-2015-7512", "CVE-2015-8345", "CVE-2015-8504", "CVE-2015-8550", "CVE-2015-8554", "CVE-2015-8555", "CVE-2015-8558", "CVE-2015-8743", "CVE-2015-8745", "CVE-2016-1568", "CVE-2016-1570", "CVE-2016-1571", "CVE-2016-1714", "CVE-2016-1981", "CVE-2016-2270", "CVE-2016-2271", "CVE-2016-2391", "CVE-2016-2392", "CVE-2016-2538", "CVE-2016-2841");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:05 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-09 15:14:00 +0000 (Wed, 09 Sep 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:1745-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:1745-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20161745-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2016:1745-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"xen was updated to fix 36 security issues.
These security issues were fixed:
- CVE-2013-4527: Buffer overflow in hw/timer/hpet.c might have allowed
 remote attackers to execute arbitrary code via vectors related to the
 number of timers (bnc#864673).
- CVE-2013-4529: Buffer overflow in hw/pci/pcie_aer.c allowed remote
 attackers to cause a denial of service and possibly execute arbitrary
 code via a large log_num value in a savevm image (bnc#864678).
- CVE-2013-4530: Buffer overflow in hw/ssi/pl022.c allowed remote
 attackers to cause a denial of service or possibly execute arbitrary
 code via crafted tx_fifo_head and rx_fifo_head values in a savevm image
 (bnc#864682).
- CVE-2013-4533: Buffer overflow in the pxa2xx_ssp_load function in
 hw/arm/pxa2xx.c allowed remote attackers to cause a denial of service or
 possibly execute arbitrary code via a crafted s->rx_level value in a
 savevm image (bsc#864655).
- CVE-2013-4534: Buffer overflow in hw/intc/openpic.c allowed remote
 attackers to cause a denial of service or possibly execute arbitrary
 code via vectors related to IRQDest elements (bsc#864811).
- CVE-2013-4537: The ssi_sd_transfer function in hw/sd/ssi-sd.c allowed
 remote attackers to execute arbitrary code via a crafted arglen value in
 a savevm image (bsc#864391).
- CVE-2013-4538: Multiple buffer overflows in the ssd0323_load function in
 hw/display/ssd0323.c allowed remote attackers to cause a denial of
 service (memory corruption) or possibly execute arbitrary code via
 crafted (1) cmd_len, (2) row, or (3) col values, (4) row_start and
 row_end values, or (5) col_star and col_end values in a savevm image
 (bsc#864769).
- CVE-2013-4539: Multiple buffer overflows in the tsc210x_load function in
 hw/input/tsc210x.c might have allowed remote attackers to execute
 arbitrary code via a crafted (1) precision, (2) nextprecision, (3)
 function, or (4) nextfunction value in a savevm image (bsc#864805).
- CVE-2014-0222: Integer overflow in the qcow_open function in
 block/qcow.c allowed remote attackers to cause a denial of service
 (crash) via a large L2 table in a QCOW version 1 image (bsc#877642).
- CVE-2014-3640: The sosendto function in slirp/udp.c allowed local users
 to cause a denial of service (NULL pointer dereference) by sending a udp
 packet with a value of 0 in the source port and address, which triggers
 access of an uninitialized socket (bsc#897654).
- CVE-2014-3689: The vmware-vga driver (hw/display/vmware_vga.c) allowed
 local guest users to write to qemu memory locations and gain privileges
 via unspecified parameters related to rectangle handling (bsc#901508).
- CVE-2014-7815: The set_pixel_format function in ui/vnc.c allowed remote
 attackers to cause a denial of service (crash) via a small
 bytes_per_pixel value (bsc#902737).
- CVE-2014-9718: The (1) BMDMA and (2) AHCI HBA interfaces in the IDE
 functionality had multiple interpretations of a ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'xen' package(s) on SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Debuginfo 11-SP3.");

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

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.2.5_20_3.0.101_0.47.79~24.9", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.2.5_20~24.9", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.2.5_20~24.9", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.2.5_20~24.9", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.2.5_20~24.9", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-pdf", rpm:"xen-doc-pdf~4.2.5_20~24.9", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.2.5_20~24.9", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.2.5_20~24.9", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-pae", rpm:"xen-kmp-pae~4.2.5_20_3.0.101_0.47.79~24.9", rls:"SLES11.0SP3"))) {
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
