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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2014.0373.1");
  script_cve_id("CVE-2013-2212", "CVE-2013-6400", "CVE-2013-6885", "CVE-2014-1642", "CVE-2014-1666", "CVE-2014-1891", "CVE-2014-1892", "CVE-2014-1893", "CVE-2014-1894", "CVE-2014-1895", "CVE-2014-1896", "CVE-2014-1950");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:21 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-03 02:29:00 +0000 (Wed, 03 Jan 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2014:0373-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2014:0373-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2014/suse-su-20140373-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Xen' package(s) announced via the SUSE-SU-2014:0373-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise Server 11 Service Pack 3 Xen hypervisor and toolset has been updated to 4.2.4 to fix various bugs and security issues:

The following security issues have been addressed:

 *

 XSA-60: CVE-2013-2212: The vmx_set_uc_mode function in Xen 3.3 through 4.3, when disabling chaches, allows local HVM guests with access to memory mapped I/O regions to cause a denial of service (CPU consumption and possibly hypervisor or guest kernel panic) via a crafted GFN range.
(bnc#831120)

 *

 XSA-80: CVE-2013-6400: Xen 4.2.x and 4.3.x, when using Intel VT-d and a PCI device has been assigned, does not clear the flag that suppresses IOMMU TLB flushes when unspecified errors occur, which causes the TLB entries to not be flushed and allows local guest administrators to cause a denial of service (host crash) or gain privileges via unspecified vectors. (bnc#853048)

 *

 XSA-82: CVE-2013-6885: The microcode on AMD 16h 00h through 0Fh processors does not properly handle the interaction between locked instructions and write-combined memory types, which allows local users to cause a denial of service (system hang) via a crafted application, aka the errata 793 issue. (bnc#853049)

 *

 XSA-83: CVE-2014-1642: The IRQ setup in Xen 4.2.x and 4.3.x, when using device passthrough and configured to support a large number of CPUs, frees certain memory that may still be intended for use, which allows local guest administrators to cause a denial of service (memory corruption and hypervisor crash) and possibly execute arbitrary code via vectors related to an out-of-memory error that triggers a (1) use-after-free or (2) double free. (bnc#860092)

 *

 XSA-84: CVE-2014-1891: The FLASK_{GET,SET}BOOL,
FLASK_USER and FLASK_CONTEXT_TO_SID suboperations of the flask hypercall are vulnerable to an integer overflow on the input size. The hypercalls attempt to allocate a buffer which is 1 larger than this size and is therefore vulnerable to integer overflow and an attempt to allocate then access a zero byte buffer. (bnc#860163)

 *

 XSA-84: CVE-2014-1892 CVE-2014-1893: Xen 3.3 through 4.1, while not affected by the above overflow, have a different overflow issue on FLASK_{GET,SET}BOOL and expose unreasonably large memory allocation to aribitrary guests.
(bnc#860163)

 *

 XSA-84: CVE-2014-1894: Xen 3.2 (and presumably earlier) exhibit both problems with the overflow issue being present for more than just the suboperations listed above. (bnc#860163)

 *

 XSA-85: CVE-2014-1895: The FLASK_AVC_CACHESTAT hypercall, which provides access to per-cpu statistics on the Flask security policy, incorrectly validates the CPU for which statistics are being requested. (bnc#860165)

 *

 XSA-86: CVE-2014-1896: libvchan (a library for inter-domain communication) does not correctly handle unusual or malicious contents in the xenstore ring. A malicious guest can exploit this to cause a libvchan-using facility ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Xen' package(s) on SUSE Linux Enterprise Software Development Kit 11 SP3, SUSE Linux Enterprise Server 11 SP3, SUSE Linux Enterprise Desktop 11 SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.2.4_02_3.0.101_0.15~0.7.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.2.4_02~0.7.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.2.4_02~0.7.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.2.4_02~0.7.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.2.4_02~0.7.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-pdf", rpm:"xen-doc-pdf~4.2.4_02~0.7.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.2.4_02~0.7.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.2.4_02~0.7.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-pae", rpm:"xen-kmp-pae~4.2.4_02_3.0.101_0.15~0.7.1", rls:"SLES11.0SP3"))) {
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
